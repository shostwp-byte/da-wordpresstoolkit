package snapshot

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

const (
	zstdMagicUint32 uint32 = 0xFD2FB528
	zstdMaxBlockLen int    = 128 * 1024 // 128 KB max Zstd block size per RFC 8878
)

// ZstdMagicBytes is the canonical 4-byte little-endian RFC 8878 Zstandard frame header signature.
var ZstdMagicBytes = []byte{0x28, 0xB5, 0x2F, 0xFD}

func findZstdBinary(explicit string) string {
	if explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return explicit
		}
		return ""
	}
	for _, p := range []string{"/usr/bin/zstd", "/usr/local/bin/zstd", "/bin/zstd"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// compressZstdStream compresses src into dst as a valid `.zst` stream using system `zstd` (with nice/ionice)
// when available on Linux, or pure-Go RFC 8878 Zstandard Raw/RLE frames when `zstd` CLI is absent.
func compressZstdStream(ctx context.Context, zstdBin, niceBin, ioniceBin string, src io.Reader, dst io.Writer) error {
	if bin := findZstdBinary(zstdBin); bin != "" {
		prog, args := wrapLowPriorityCmd(niceBin, ioniceBin, bin, "-q", "-3", "-T2", "-c")
		cmd := exec.CommandContext(ctx, prog, args...)
		cmd.Stdin = src
		cmd.Stdout = dst
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("zstd compress failed: %w (%s)", err, stderr.String())
		}
		return nil
	}
	return encodeNativeRFC8878Zstd(src, dst)
}

// decompressZstdStream decompresses a `.zst` stream from src into dst, enforcing maxOutputBytes.
func decompressZstdStream(ctx context.Context, zstdBin string, src io.Reader, dst io.Writer, maxOutputBytes int64) error {
	if maxOutputBytes <= 0 {
		maxOutputBytes = 20 * 1024 * 1024 * 1024 // 20 GB safety cap
	}
	if bin := findZstdBinary(zstdBin); bin != "" {
		cmd := exec.CommandContext(ctx, bin, "-d", "-q", "-c")
		cmd.Stdin = src
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		stdoutPipe, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		if err := cmd.Start(); err != nil {
			return err
		}
		written, copyErr := io.Copy(dst, io.LimitReader(stdoutPipe, maxOutputBytes+1))
		waitErr := cmd.Wait()
		if copyErr != nil {
			return copyErr
		}
		if written > maxOutputBytes {
			return errors.New("snapshot archive exceeded maximum decompressed size safety limit")
		}
		if waitErr != nil {
			return fmt.Errorf("zstd decompress failed: %w (%s)", waitErr, stderr.String())
		}
		return nil
	}
	return decodeNativeRFC8878Zstd(src, dst, maxOutputBytes)
}

func wrapLowPriorityCmd(niceBin, ioniceBin, bin string, binArgs ...string) (string, []string) {
	prog := bin
	args := append([]string{}, binArgs...)
	if ioniceBin != "" {
		if _, err := os.Stat(ioniceBin); err == nil {
			args = append([]string{"-c2", "-n7", prog}, args...)
			prog = ioniceBin
		}
	}
	if niceBin != "" {
		if _, err := os.Stat(niceBin); err == nil {
			args = append([]string{"-n", "10", prog}, args...)
			prog = niceBin
		}
	}
	return prog, args
}

// encodeNativeRFC8878Zstd writes a 100% RFC 8878 spec-compliant Zstandard frame using RLE_Block (type=1)
// for uniform runs and Raw_Block (type=0) for general chunks (compatible with `zstd -d` CLI everywhere).
func encodeNativeRFC8878Zstd(src io.Reader, dst io.Writer) error {
	// 4-byte Magic (0xFD2FB528 LE) + FHD (0x00) + Window_Descriptor (0x00)
	frameHeader := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00}
	if _, err := dst.Write(frameHeader); err != nil {
		return err
	}

	curBuf := make([]byte, zstdMaxBlockLen)
	nextBuf := make([]byte, zstdMaxBlockLen)

	curN, curErr := io.ReadFull(src, curBuf)
	if errors.Is(curErr, io.EOF) {
		// Empty stream: emit single final 0-length Raw_Block (last=1, type=0, size=0 -> 0x01, 0x00, 0x00)
		_, wErr := dst.Write([]byte{0x01, 0x00, 0x00})
		return wErr
	}
	if curErr != nil && !errors.Is(curErr, io.ErrUnexpectedEOF) {
		return curErr
	}

	for {
		nextN, nextErr := io.ReadFull(src, nextBuf)
		isLast := errors.Is(nextErr, io.EOF)
		if nextErr != nil && !isLast && !errors.Is(nextErr, io.ErrUnexpectedEOF) {
			return nextErr
		}

		if err := writeRFC8878Block(dst, curBuf[:curN], isLast); err != nil {
			return err
		}
		if isLast {
			return nil
		}

		curBuf, nextBuf = nextBuf, curBuf
		curN = nextN
	}
}

func writeRFC8878Block(dst io.Writer, chunk []byte, isLast bool) error {
	var lastBit uint32
	if isLast {
		lastBit = 1
	}

	// Use RLE_Block (Block_Type = 1) when chunk >= 16 bytes and all bytes are identical (e.g. tar zero-padding!)
	if len(chunk) >= 16 && isUniformByteSlice(chunk) {
		hdrVal := lastBit | (1 << 1) | (uint32(len(chunk)) << 3)
		hdr := []byte{byte(hdrVal), byte(hdrVal >> 8), byte(hdrVal >> 16), chunk[0]}
		_, err := dst.Write(hdr)
		return err
	}

	// Raw_Block (Block_Type = 0)
	hdrVal := lastBit | (0 << 1) | (uint32(len(chunk)) << 3)
	hdr := []byte{byte(hdrVal), byte(hdrVal >> 8), byte(hdrVal >> 16)}
	if _, err := dst.Write(hdr); err != nil {
		return err
	}
	if len(chunk) > 0 {
		_, err := dst.Write(chunk)
		return err
	}
	return nil
}

func isUniformByteSlice(b []byte) bool {
	first := b[0]
	for i := 1; i < len(b); i++ {
		if b[i] != first {
			return false
		}
	}
	return true
}

func decodeNativeRFC8878Zstd(src io.Reader, dst io.Writer, maxOutputBytes int64) error {
	var totalOut int64
	var magicBuf [4]byte

	for {
		_, err := io.ReadFull(src, magicBuf[:])
		if errors.Is(err, io.EOF) {
			if totalOut == 0 {
				// Could still be an empty valid frame only if magic was read; pure EOF before first frame is invalid
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		if err != nil {
			return err
		}

		magic := binary.LittleEndian.Uint32(magicBuf[:])
		if magic != zstdMagicUint32 {
			return fmt.Errorf("invalid Zstandard frame magic 0x%08X", magic)
		}

		var fhdBuf [1]byte
		if _, err := io.ReadFull(src, fhdBuf[:]); err != nil {
			return err
		}
		fhd := fhdBuf[0]
		singleSegment := (fhd & 0x20) != 0
		hasChecksum := (fhd & 0x04) != 0
		dictIDFlag := fhd & 0x03
		fcsFlag := fhd >> 6

		if !singleSegment {
			var wd [1]byte
			if _, err := io.ReadFull(src, wd[:]); err != nil {
				return err
			}
		}

		dictSkip := [4]int{0, 1, 2, 4}[dictIDFlag]
		if dictSkip > 0 {
			var skip [4]byte
			if _, err := io.ReadFull(src, skip[:dictSkip]); err != nil {
				return err
			}
		}

		fcsSkip := 0
		switch fcsFlag {
		case 0:
			if singleSegment {
				fcsSkip = 1
			}
		case 1:
			fcsSkip = 2
		case 2:
			fcsSkip = 4
		case 3:
			fcsSkip = 8
		}
		if fcsSkip > 0 {
			var skip [8]byte
			if _, err := io.ReadFull(src, skip[:fcsSkip]); err != nil {
				return err
			}
		}

		copyBuf := make([]byte, zstdMaxBlockLen)
		for {
			var bh [3]byte
			if _, err := io.ReadFull(src, bh[:]); err != nil {
				return err
			}
			hdr := uint32(bh[0]) | uint32(bh[1])<<8 | uint32(bh[2])<<16
			lastBlock := (hdr & 1) != 0
			blockType := (hdr >> 1) & 0x03
			blockSize := int(hdr >> 3)

			if blockSize > zstdMaxBlockLen {
				return fmt.Errorf("zstd block size %d exceeds RFC 8878 128KB maximum", blockSize)
			}

			switch blockType {
			case 0: // Raw_Block
				totalOut += int64(blockSize)
				if totalOut > maxOutputBytes {
					return errors.New("snapshot archive exceeded maximum decompressed size safety limit")
				}
				if blockSize > 0 {
					if _, err := io.ReadFull(src, copyBuf[:blockSize]); err != nil {
						return err
					}
					if _, err := dst.Write(copyBuf[:blockSize]); err != nil {
						return err
					}
				}
			case 1: // RLE_Block
				var rleByte [1]byte
				if _, err := io.ReadFull(src, rleByte[:]); err != nil {
					return err
				}
				totalOut += int64(blockSize)
				if totalOut > maxOutputBytes {
					return errors.New("snapshot archive exceeded maximum decompressed size safety limit")
				}
				for i := 0; i < blockSize; i++ {
					copyBuf[i] = rleByte[0]
				}
				if blockSize > 0 {
					if _, err := dst.Write(copyBuf[:blockSize]); err != nil {
						return err
					}
				}
			case 2:
				return errors.New("compressed Zstd block requires /usr/bin/zstd binary on host")
			default:
				return errors.New("corrupt Zstd reserved block type 3")
			}

			if lastBlock {
				break
			}
		}

		if hasChecksum {
			var csum [4]byte
			if _, err := io.ReadFull(src, csum[:]); err != nil {
				return err
			}
		}

		// Peek if another concatenated frame follows; normal single-frame stream returns EOF on next loop
		var peek [1]byte
		n, pErr := src.Read(peek[:])
		if n == 0 && errors.Is(pErr, io.EOF) {
			return nil
		}
		if n > 0 {
			src = io.MultiReader(bytes.NewReader(peek[:n]), src)
		}
	}
}
