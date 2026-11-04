//go:build linux

package webserver

import "os"

func chownNoFollow(path string, uid, gid uint32) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Lchown(path, int(uid), int(gid))
}
