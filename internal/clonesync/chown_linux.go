//go:build linux

package clonesync

import "syscall"

func chownNoFollow(path string, uid, gid uint32) error {
	return syscall.Lchown(path, int(uid), int(gid))
}
