//go:build linux

package snapshot

import "syscall"

func chownNoFollow(path string, uid, gid uint32) error {
	return syscall.Lchown(path, int(uid), int(gid))
}
