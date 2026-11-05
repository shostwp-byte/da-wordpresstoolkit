package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
)

type mockHandler struct {
	rejectErr error
	called    atomic.Bool
}

func (m *mockHandler) AuthorizeSocketPeer(cred auth.PeerCred, _ bool) error {
	if m.rejectErr != nil {
		return m.rejectErr
	}
	if cred.UID == 9999 {
		return errors.New("403 Unauthorized Peer Lineage")
	}
	return nil
}

func (m *mockHandler) HandleAdminRequest(_ context.Context, cred auth.PeerCred, req Request) Response {
	m.called.Store(true)
	return Response{OK: true, Data: map[string]any{"action": req.Action, "uid": cred.UID}}
}

func (m *mockHandler) HandleUserRequest(_ context.Context, cred auth.PeerCred, req Request) Response {
	m.called.Store(true)
	return Response{OK: true, Data: map[string]any{"action": req.Action, "uid": cred.UID}}
}

func TestServeConnRejectsUnauthorizedPeerBeforeDecodingJSON(t *testing.T) {
	mh := &mockHandler{}
	srv := NewServer("", "", mh)
	srv.GetPeerCred = func(_ net.Conn) (auth.PeerCred, error) {
		return auth.PeerCred{PID: 3001, UID: 9999, GID: 9999}, nil
	}

	c1, c2 := net.Pipe()
	defer c1.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.ServeConn(context.Background(), c2, false)
	}()

	// Even if attacker sends malformed garbage JSON, pre-decode auth must reject with 403 first!
	go func() {
		_, _ = c1.Write([]byte("{malformed_webshell_payload\n"))
	}()

	rd := bufio.NewReader(c1)
	line, err := rd.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read reply error: %v", err)
	}
	<-done

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	if resp.OK || resp.Code != 403 || !strings.Contains(resp.Error, "403") {
		t.Fatalf("expected 403 pre-decode rejection, got: %+v", resp)
	}
	if mh.called.Load() {
		t.Fatal("handler MUST NOT be invoked when AuthorizeSocketPeer fails")
	}
}

func TestPerUIDSlidingWindowRateLimiter(t *testing.T) {
	mh := &mockHandler{}
	srv := NewServer("", "", mh)
	srv.UserRateLimitBurst = 2
	srv.UserRateWindow = 10 * time.Second
	srv.GetPeerCred = func(_ net.Conn) (auth.PeerCred, error) {
		return auth.PeerCred{PID: 2001, UID: 1005, GID: 1005}, nil
	}

	sendOne := func() Response {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go srv.ServeConn(context.Background(), c2, false)
		go func() {
			_, _ = c1.Write([]byte(`{"action":"ping"}` + "\n"))
		}()
		line, err := bufio.NewReader(c1).ReadBytes('\n')
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		var r Response
		_ = json.Unmarshal(line, &r)
		return r
	}

	if r := sendOne(); !r.OK {
		t.Fatalf("req 1 should pass: %+v", r)
	}
	if r := sendOne(); !r.OK {
		t.Fatalf("req 2 should pass: %+v", r)
	}
	if r := sendOne(); r.OK || r.Code != 429 {
		t.Fatalf("req 3 should hit 429 rate limit, got: %+v", r)
	}
}

func TestRequestUnmarshalAcceptsPHPEmptyArrayParams(t *testing.T) {
	mh := &mockHandler{}
	srv := NewServer("", "", mh)
	srv.GetPeerCred = func(_ net.Conn) (auth.PeerCred, error) {
		return auth.PeerCred{PID: 500, UID: 0, GID: 0}, nil
	}

	sendPayload := func(raw string) Response {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go srv.ServeConn(context.Background(), c2, true)
		go func() {
			_, _ = c1.Write([]byte(raw + "\n"))
		}()
		line, err := bufio.NewReader(c1).ReadBytes('\n')
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		var r Response
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		return r
	}

	if r := sendPayload(`{"action":"get_overview","params":[]}`); !r.OK {
		t.Fatalf("expected PHP empty array params [] to succeed, got: %+v", r)
	}
	if r := sendPayload(`{"action":"get_overview","params":{}}`); !r.OK {
		t.Fatalf("expected empty object params {} to succeed, got: %+v", r)
	}
	if r := sendPayload(`{"action":"get_overview","params":[1,2]}`); r.OK || r.Code != 400 {
		t.Fatalf("expected non-empty array params [1,2] to fail with 400, got: %+v", r)
	}
}
