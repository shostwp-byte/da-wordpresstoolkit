//go:build linux

package wpcli

import (
	"os"
	"os/exec"
	"syscall"
)

func applyPrivilegeDrop(cmd *exec.Cmd, uid, gid uint32) {
	if os.Geteuid() != 0 {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    gid,
			Groups: []uint32{gid},
		},
	}
}
