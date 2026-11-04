//go:build !linux

package wpcli

import "os/exec"

func applyPrivilegeDrop(_ *exec.Cmd, _, _ uint32) {
	// Privilege dropping via syscall.Credential is active on Linux hosts.
}
