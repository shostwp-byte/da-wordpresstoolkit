//go:build linux

package ipc

import (
	"fmt"
	"net"
	"syscall"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
)

func readPeerCred(conn net.Conn) (auth.PeerCred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return auth.PeerCred{}, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return auth.PeerCred{}, err
	}

	var cred *syscall.Ucred
	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return auth.PeerCred{}, err
	}
	if sockErr != nil {
		return auth.PeerCred{}, sockErr
	}
	return auth.PeerCred{
		PID: cred.Pid,
		UID: cred.Uid,
		GID: cred.Gid,
	}, nil
}
