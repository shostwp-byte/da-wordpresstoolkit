//go:build !linux

package ipc

import (
	"errors"
	"net"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
)

func readPeerCred(_ net.Conn) (auth.PeerCred, error) {
	return auth.PeerCred{}, errors.New("SO_PEERCRED is only supported on Linux Unix Domain Sockets")
}
