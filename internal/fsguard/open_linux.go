//go:build linux

package fsguard

import (
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open_nofollow", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}
