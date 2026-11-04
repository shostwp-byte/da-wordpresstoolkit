//go:build !linux

package fsguard

import (
	"fmt"
	"os"
)

func openNoFollow(path string) (*os.File, error) {
	st1, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st1.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlink rejected: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st2, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !os.SameFile(st1, st2) {
		_ = f.Close()
		return nil, fmt.Errorf("TOCTOU file replacement detected on %s", path)
	}
	return f, nil
}
