package extensions

import (
	"archive/zip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
)

const (
	MaxZipEntries          = 10000
	MaxZipSingleFileBytes  = 64 * 1024 * 1024  // 64 MB
	MaxZipTotalUncompBytes = 150 * 1024 * 1024 // 150 MB
	MaxBase64UploadBytes   = 32 * 1024 * 1024  // 32 MB decoded archive via direct upload
)

// ValidateExtensionZip inspects a .zip plugin/theme package before handing it to WP-CLI,
// blocking Zip-Slip path traversal, embedded symlinks, and Zip-Bomb decompression attacks.
func ValidateExtensionZip(zipPath string) (string, error) {
	st, err := os.Lstat(zipPath)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("extension package must be a regular .zip file")
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("invalid .zip archive: %w", err)
	}
	defer zr.Close()

	if len(zr.File) == 0 {
		return "", errors.New("empty .zip archive")
	}
	if len(zr.File) > MaxZipEntries {
		return "", fmt.Errorf(".zip archive exceeds maximum entry count (%d)", MaxZipEntries)
	}

	var topSlug string
	var totalUncompressed uint64
	hasCodeOrStyle := false

	for _, f := range zr.File {
		if f.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("security violation: symbolic link entry %q inside .zip is blocked", f.Name)
		}

		norm := strings.ReplaceAll(f.Name, `\`, "/")
		if strings.HasPrefix(norm, "/") || strings.Contains(norm, ":") {
			return "", fmt.Errorf("security violation: absolute path %q inside .zip is blocked", f.Name)
		}

		parts := strings.Split(strings.TrimSuffix(norm, "/"), "/")
		for _, p := range parts {
			if p == ".." || p == "." || p == "" {
				return "", fmt.Errorf("security violation: path traversal segment in %q is blocked", f.Name)
			}
		}

		rootDir := parts[0]
		if err := config.ValidateIdentifier(rootDir); err != nil {
			return "", fmt.Errorf("invalid top-level folder %q inside .zip: must be a valid WordPress slug", rootDir)
		}
		if topSlug == "" {
			topSlug = rootDir
		} else if !strings.EqualFold(topSlug, rootDir) {
			return "", fmt.Errorf(".zip archive must contain a single top-level plugin/theme folder (found both %q and %q)", topSlug, rootDir)
		}

		if f.UncompressedSize64 > MaxZipSingleFileBytes {
			return "", fmt.Errorf("entry %q exceeds single-file limit (64 MB)", f.Name)
		}
		totalUncompressed += f.UncompressedSize64
		if totalUncompressed > MaxZipTotalUncompBytes {
			return "", errors.New(".zip archive exceeds maximum uncompressed size limit (150 MB)")
		}

		lowerName := strings.ToLower(norm)
		if strings.HasSuffix(lowerName, ".php") || strings.HasSuffix(lowerName, "/style.css") {
			hasCodeOrStyle = true
		}
	}

	if !hasCodeOrStyle {
		return "", errors.New(".zip archive does not appear to contain a valid WordPress plugin or theme")
	}
	return topSlug, nil
}

// StageCustomerZip copies or decodes a verified .zip archive into a temporary file inside customerTempDir
// owned by uid:gid (0600) so privilege-dropped WP-CLI can install it cleanly, returning a cleanup callback.
func StageCustomerZip(
	customerTempDir string,
	sourceZipPath string,
	base64Zip string,
	uid, gid uint32,
) (stagedPath string, topSlug string, cleanup func(), err error) {
	parentDir := filepath.Dir(filepath.Clean(customerTempDir))
	if st, lErr := os.Lstat(parentDir); lErr != nil {
		if errors.Is(lErr, os.ErrNotExist) {
			if mkErr := os.MkdirAll(parentDir, 0o755); mkErr != nil {
				return "", "", nil, mkErr
			}
			_ = os.Chmod(parentDir, 0o755)
			_ = chownFile(parentDir, uid, gid)
		} else {
			return "", "", nil, lErr
		}
	} else if st.Mode()&os.ModeSymlink != 0 {
		return "", "", nil, errors.New("security violation: symbolic link parent directory blocked")
	}

	if st, lErr := os.Lstat(customerTempDir); lErr == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", "", nil, errors.New("security violation: symbolic link staging directory blocked")
	}
	if err := os.MkdirAll(customerTempDir, 0o755); err != nil {
		return "", "", nil, err
	}
	_ = os.Chmod(customerTempDir, 0o755)
	_ = chownFile(customerTempDir, uid, gid)

	tmpFile, err := os.CreateTemp(customerTempDir, "wptk-pkg-*.zip")
	if err != nil {
		return "", "", nil, err
	}
	stagedPath = tmpFile.Name()
	cleanup = func() {
		_ = os.Remove(stagedPath)
	}

	if strings.TrimSpace(base64Zip) != "" {
		rawB64 := strings.TrimSpace(base64Zip)
		if idx := strings.Index(rawB64, ","); idx > 0 && strings.Contains(rawB64[:idx], "base64") {
			rawB64 = rawB64[idx+1:]
		}
		dec := base64.NewDecoder(base64.StdEncoding, strings.NewReader(rawB64))
		written, cErr := io.Copy(tmpFile, io.LimitReader(dec, MaxBase64UploadBytes+1))
		_ = tmpFile.Close()
		if cErr != nil {
			cleanup()
			return "", "", nil, fmt.Errorf("invalid base64 .zip payload: %w", cErr)
		}
		if written > MaxBase64UploadBytes {
			cleanup()
			return "", "", nil, errors.New("uploaded .zip exceeds 32 MB limit")
		}
	} else {
		in, oErr := os.Open(sourceZipPath)
		if oErr != nil {
			_ = tmpFile.Close()
			cleanup()
			return "", "", nil, oErr
		}
		_, cErr := io.Copy(tmpFile, io.LimitReader(in, MaxZipTotalUncompBytes))
		_ = in.Close()
		_ = tmpFile.Close()
		if cErr != nil {
			cleanup()
			return "", "", nil, cErr
		}
	}

	_ = os.Chmod(stagedPath, 0o600)
	_ = chownFile(stagedPath, uid, gid)

	slug, vErr := ValidateExtensionZip(stagedPath)
	if vErr != nil {
		cleanup()
		return "", "", nil, vErr
	}
	return filepath.Clean(stagedPath), slug, cleanup, nil
}
