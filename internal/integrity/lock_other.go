//go:build !linux

package integrity

import "os"

func chownNoFollow(_ string, _, _ uint32) error {
	return nil
}

func isOwnedAndWritableBy(path string, isDir bool, _ uint32) bool {
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if isDir {
		return st.Mode().Perm()&0o200 != 0
	}
	return st.Mode().Perm()&0o200 != 0
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
