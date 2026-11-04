//go:build linux

package integrity

import "os"

func chownNoFollow(path string, uid, gid uint32) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(path, int(uid), int(gid))
}

func applyKernelCoreLock(path string, isDir bool, gid uint32) error {
	if os.Geteuid() == 0 {
		if err := os.Lchown(path, 0, int(gid)); err != nil {
			return err
		}
		if isDir {
			return os.Chmod(path, 0o755)
		}
		return os.Chmod(path, 0o644)
	}
	// Non-root test runner fallback on Linux CI: enforce read-only kernel mode bits
	if isDir {
		return os.Chmod(path, 0o555)
	}
	return os.Chmod(path, 0o444)
}

func releaseKernelCoreLock(path string, isDir bool, uid, gid uint32) error {
	if isDir {
		_ = os.Chmod(path, 0o755)
	} else {
		_ = os.Chmod(path, 0o644)
	}
	if os.Geteuid() == 0 {
		return os.Lchown(path, int(uid), int(gid))
	}
	return nil
}
