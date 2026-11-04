package quicktools

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
)

const DefaultDebugLogTailBytes = 32 * 1024 // 32 KB reverse tail window

// DebugLogTail represents the last N bytes of wp-content/debug.log read without loading the entire file into RAM.
type DebugLogTail struct {
	Exists         bool     `json:"exists"`
	TotalSizeBytes int64    `json:"total_size_bytes"`
	ReadBytes      int      `json:"read_bytes"`
	Truncated      bool     `json:"truncated"`
	Lines          []string `json:"lines"`
}

// ReadDebugLogTail seeks to the final maxBytes (default 32 KB) of `wp-content/debug.log` safely inside fsguard.
func ReadDebugLogTail(guard *fsguard.Guard, verifiedDocRoot string, maxBytes int64) (DebugLogTail, error) {
	if maxBytes <= 0 || maxBytes > 256*1024 {
		maxBytes = DefaultDebugLogTailBytes
	}

	logPath, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, "wp-content", "debug.log")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DebugLogTail{Exists: false, Lines: []string{}}, nil
		}
		return DebugLogTail{}, err
	}

	st, err := os.Lstat(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DebugLogTail{Exists: false, Lines: []string{}}, nil
		}
		return DebugLogTail{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return DebugLogTail{}, fmt.Errorf("security violation: debug.log is not a regular file")
	}

	f, err := os.Open(logPath)
	if err != nil {
		return DebugLogTail{}, err
	}
	defer f.Close()

	// Re-stat open descriptor to defeat TOCTOU swap between Lstat and Open
	openStat, err := f.Stat()
	if err != nil {
		return DebugLogTail{}, err
	}
	if !openStat.Mode().IsRegular() {
		return DebugLogTail{}, errors.New("refusing to read non-regular debug.log descriptor")
	}

	totalSize := openStat.Size()
	if totalSize == 0 {
		return DebugLogTail{
			Exists:         true,
			TotalSizeBytes: 0,
			Lines:          []string{},
		}, nil
	}

	offset := int64(0)
	truncated := false
	if totalSize > maxBytes {
		offset = totalSize - maxBytes
		truncated = true
	}

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return DebugLogTail{}, err
		}
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		return DebugLogTail{}, err
	}
	readCount := len(raw)

	// When seeking mid-file, discard any partial first line up to and including the first newline
	if truncated {
		if nl := bytes.IndexByte(raw, '\n'); nl >= 0 && nl+1 < len(raw) {
			raw = raw[nl+1:]
		}
	}

	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	var lines []string
	if text != "" {
		lines = strings.Split(text, "\n")
	} else {
		lines = []string{}
	}

	return DebugLogTail{
		Exists:         true,
		TotalSizeBytes: totalSize,
		ReadBytes:      readCount,
		Truncated:      truncated,
		Lines:          lines,
	}, nil
}

// ClearDebugLog safely truncates `wp-content/debug.log` without following symlinks.
func ClearDebugLog(guard *fsguard.Guard, acct dausers.Account, verifiedDocRoot string) error {
	wpContent, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, "wp-content")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	logPath := filepath.Join(wpContent, "debug.log")
	st, err := os.Lstat(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return errors.New("security violation: refusing to truncate non-regular or symlinked debug.log")
	}
	tmpPath := filepath.Join(wpContent, ".da-wptk-debuglog.tmp")
	if err := os.WriteFile(tmpPath, []byte{}, 0o600); err != nil {
		return err
	}
	_ = chownNoFollow(tmpPath, acct.UID, acct.GID)
	if err := os.Rename(tmpPath, logPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
