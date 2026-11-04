package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
)

const (
	maxRequestBytes           = 64 * 1024
	DefaultMaxAdminConns      = 32
	DefaultMaxUserConns       = 64
	DefaultUserRateLimitBurst = 30
	DefaultUserRateWindow     = 5 * time.Second
)

// RequestHandler processes decoded IPC requests for Admin and User sockets.
type RequestHandler interface {
	HandleAdminRequest(ctx context.Context, cred auth.PeerCred, req Request) Response
	HandleUserRequest(ctx context.Context, cred auth.PeerCred, req Request) Response
}

// PeerAuthorizer pre-validates kernel peer credentials (UID + PID lineage) BEFORE reading JSON.
type PeerAuthorizer interface {
	AuthorizeSocketPeer(cred auth.PeerCred, isAdminSocket bool) error
}

// PeerCredFunc extracts the kernel-authenticated OS PID/UID/GID of a connected Unix socket client.
type PeerCredFunc func(conn net.Conn) (auth.PeerCred, error)

type uidRateWindow struct {
	windowStart time.Time
	count       int
}

// Server listens on Dual Unix Domain Sockets (Admin + User), enforcing pre-decode SO_PEERCRED +
// process lineage verification, bounded concurrency semaphores, and per-UID rate limits.
type Server struct {
	AdminSocketPath    string
	UserSocketPath     string
	Handler            RequestHandler
	GetPeerCred        PeerCredFunc
	MaxAdminConns      int
	MaxUserConns       int
	UserRateLimitBurst int
	UserRateWindow     time.Duration
	NowFunc            func() time.Time

	rateMu      sync.Mutex
	userRates   map[uint32]uidRateWindow
	lastCleanup time.Time

	wg sync.WaitGroup
}

func NewServer(adminSock, userSock string, handler RequestHandler) *Server {
	if adminSock == "" {
		adminSock = DefaultAdminSocketPath
	}
	if userSock == "" {
		userSock = DefaultUserSocketPath
	}
	return &Server{
		AdminSocketPath:    adminSock,
		UserSocketPath:     userSock,
		Handler:            handler,
		GetPeerCred:        readPeerCred,
		MaxAdminConns:      DefaultMaxAdminConns,
		MaxUserConns:       DefaultMaxUserConns,
		UserRateLimitBurst: DefaultUserRateLimitBurst,
		UserRateWindow:     DefaultUserRateWindow,
		NowFunc:            time.Now,
		userRates:          make(map[uint32]uidRateWindow),
	}
}

// Start binds both Unix sockets and serves incoming connections until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	adminLn, err := listenUnixSocket(s.AdminSocketPath, 0o666)
	if err != nil {
		return fmt.Errorf("listen admin socket %s: %w", s.AdminSocketPath, err)
	}

	userLn, err := listenUnixSocket(s.UserSocketPath, 0o666)
	if err != nil {
		_ = adminLn.Close()
		_ = os.Remove(s.AdminSocketPath)
		return fmt.Errorf("listen user socket %s: %w", s.UserSocketPath, err)
	}

	go func() {
		<-ctx.Done()
		_ = adminLn.Close()
		_ = userLn.Close()
		_ = os.Remove(s.AdminSocketPath)
		_ = os.Remove(s.UserSocketPath)
	}()

	adminCap := s.MaxAdminConns
	if adminCap <= 0 {
		adminCap = DefaultMaxAdminConns
	}
	userCap := s.MaxUserConns
	if userCap <= 0 {
		userCap = DefaultMaxUserConns
	}

	adminSem := make(chan struct{}, adminCap)
	userSem := make(chan struct{}, userCap)

	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, adminLn, true, adminSem)
	}()
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx, userLn, false, userSem)
	}()

	return nil
}

// Wait blocks until all socket accept loops and active client handlers complete.
func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, isAdminSocket bool, sem chan struct{}) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("ipc accept error (admin=%v): %v", isAdminSocket, err)
			continue
		}

		select {
		case sem <- struct{}{}:
			s.wg.Add(1)
			go func(c net.Conn) {
				defer func() {
					<-sem
					s.wg.Done()
				}()
				s.ServeConn(ctx, c, isAdminSocket)
			}(conn)
		default:
			_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
			writeResponse(conn, Response{OK: false, Code: 429, Error: "server busy: too many concurrent IPC connections"})
			_ = conn.Close()
		}
	}
}

// ServeConn verifies kernel SO_PEERCRED + process lineage BEFORE reading JSON, then dispatches one request.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn, isAdminSocket bool) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))

	cred, err := s.GetPeerCred(conn)
	if err != nil {
		writeResponse(conn, Response{OK: false, Code: 403, Error: "unable to verify peer kernel credentials: " + err.Error()})
		return
	}

	if authorizer, ok := s.Handler.(PeerAuthorizer); ok {
		if authErr := authorizer.AuthorizeSocketPeer(cred, isAdminSocket); authErr != nil {
			writeResponse(conn, Response{OK: false, Code: 403, Error: authErr.Error()})
			return
		}
	}

	if !isAdminSocket && cred.UID != 0 && !s.allowUserRequest(cred.UID) {
		writeResponse(conn, Response{OK: false, Code: 429, Error: "rate limit exceeded: please wait a few seconds before retrying"})
		return
	}

	var req Request
	dec := json.NewDecoder(io.LimitReader(conn, maxRequestBytes))
	if err := dec.Decode(&req); err != nil {
		writeResponse(conn, Response{OK: false, Code: 400, Error: "invalid JSON request: " + err.Error()})
		return
	}

	// Root CLI operations over Admin Socket (e.g. synchronous `install` or server-wide `scan`)
	// may legitimately run up to 3 minutes while downloading packages.
	if isAdminSocket && cred.UID == 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(180 * time.Second))
	}

	var resp Response
	if isAdminSocket {
		resp = s.Handler.HandleAdminRequest(ctx, cred, req)
	} else {
		resp = s.Handler.HandleUserRequest(ctx, cred, req)
	}
	writeResponse(conn, resp)
}

func (s *Server) allowUserRequest(uid uint32) bool {
	burst := s.UserRateLimitBurst
	if burst <= 0 {
		return true
	}
	win := s.UserRateWindow
	if win <= 0 {
		win = DefaultUserRateWindow
	}
	now := time.Now()
	if s.NowFunc != nil {
		now = s.NowFunc()
	}

	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	if s.userRates == nil {
		s.userRates = make(map[uint32]uidRateWindow)
	}
	if now.Sub(s.lastCleanup) > 30*time.Second {
		for k, entry := range s.userRates {
			if now.Sub(entry.windowStart) > win*2 {
				delete(s.userRates, k)
			}
		}
		s.lastCleanup = now
	}

	cur, exists := s.userRates[uid]
	if !exists || now.Sub(cur.windowStart) >= win {
		s.userRates[uid] = uidRateWindow{windowStart: now, count: 1}
		return true
	}
	if cur.count >= burst {
		return false
	}
	cur.count++
	s.userRates[uid] = cur
	return true
}

func writeResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		data = []byte(`{"ok":false,"code":500,"error":"internal JSON marshal error"}`)
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

func listenUnixSocket(sockPath string, mode os.FileMode) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, mode); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, err
	}
	return ln, nil
}
