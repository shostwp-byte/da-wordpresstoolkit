//go:build !linux

package integrity

import "os"

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}

func applyKernelCoreLock(path string, isDir bool, _ uint32) error {
	if isDir {
		return nil
	}
	// Sets FILE_ATTRIBUTE_READONLY on Windows / 0444 on Unix so OS write syscalls fail with os.ErrPermission
	return os.Chmod(path, 0o444)
}

func releaseKernelCoreLock(path string, isDir bool, _, _ uint32) error {
	if isDir {
		return os.Chmod(path, 0o755)
	}
	return os.Chmod(path, 0o644)
}
