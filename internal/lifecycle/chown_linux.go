//go:build linux

package lifecycle

import "os"

func chownIfRoot(path string, uid, gid uint32) {
	if os.Geteuid() == 0 {
		_ = os.Lchown(path, int(uid), int(gid))
	}
}
