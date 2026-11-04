package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

func writeFakeProc(t *testing.T, procRoot string, pid int32, ppid int32, comm, exePath, cgroup string, uid uint32) {
	t.Helper()
	dir := filepath.Join(procRoot, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	statLine := fmt.Sprintf("%d (%s) S %d 1 1 0 -1 4194304 100 0 0 0 1 1 0 0 20 0 1 0 12345 1000000 100\n", pid, comm, ppid)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(statLine), 0o644); err != nil {
		t.Fatal(err)
	}
	if exePath != "" {
		if err := os.WriteFile(filepath.Join(dir, "exe_path"), []byte(exePath+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if cgroup != "" {
		if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	status := fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n", comm, uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setupTestGuardEnv(t *testing.T) (*Guard, *store.Store, string, string) {
	t.Helper()
	tmp := t.TempDir()
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")
	stateDir := filepath.Join(tmp, "state")
	csrfPath := filepath.Join(tmp, "secret", "csrf.key")

	passwdContent := "" +
		"root:x:0:0:root:/root:/bin/bash\n" +
		"diradmin:x:991:991:DA:/usr/local/directadmin:/bin/false\n" +
		"admin:x:1000:1000:Admin:/home/admin:/bin/bash\n" +
		"reno26:x:1005:1005::/home/reno26:/bin/bash\n" +
		"otheruser:x:1006:1006::/home/otheruser:/bin/bash\n"
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(daRoot, "admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "admin.list"), []byte("admin\n"), 0o600)
	if err := os.MkdirAll(sessDir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, u := range []string{"reno26", "otheruser"} {
		udir := filepath.Join(daRoot, "users", u)
		_ = os.MkdirAll(udir, 0o755)
		_ = os.WriteFile(filepath.Join(udir, "user.conf"), []byte("package=pro\nsuspended=no\n"), 0o600)
	}

	reg := dausers.NewRegistry(daRoot, passwd)
	if err := reg.Reload(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	// PID 500 = DirectAdmin daemon (root)
	writeFakeProc(t, procRoot, 500, 1, "directadmin", "/usr/local/directadmin/directadmin", "0::/system.slice/directadmin.service", 0)
	// PID 2001 = Legitimate DirectAdmin CGI php process spawned by PID 500 for UID 1005 (reno26)
	writeFakeProc(t, procRoot, 2001, 500, "php", "/usr/local/php83/bin/php", "0::/system.slice/directadmin.service", 1005)
	// PID 3001 = Compromised Web-Shell inside PHP-FPM worker running under SAME UID 1005 (reno26)!
	writeFakeProc(t, procRoot, 800, 1, "php-fpm83", "/usr/local/php83/sbin/php-fpm", "0::/system.slice/php-fpm83.service", 0)
	writeFakeProc(t, procRoot, 3001, 800, "php-fpm83", "/usr/local/php83/sbin/php-fpm", "0::/user.slice/user-1005.slice/da-php.scope", 1005)
	// PID 4001 = SSH session / background shell running under SAME UID 1005 (reno26) with no DA ancestor
	writeFakeProc(t, procRoot, 4001, 1, "php", "/usr/local/php83/bin/php", "0::/user.slice/user-1005.slice/session-4.scope", 1005)

	g := NewGuard(reg, st, procRoot, sessDir, csrfPath)
	return g, st, procRoot, sessDir
}

// TestTC01_WebShellSameUIDBlockedAtSocketGate verifies Acceptance Test Case TC-01:
// A compromised PHP web process running under the exact same customer UID (1005) is blocked
// before JSON decoding and logged as a security audit event.
func TestTC01_WebShellSameUIDBlockedAtSocketGate(t *testing.T) {
	g, st, _, sessDir := setupTestGuardEnv(t)

	// Create valid DirectAdmin session for reno26
	validSessID := "a1b2c3d4e5f6g7h8i9j0"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+validSessID), []byte("username=reno26\n"), 0o600)

	// 1. Web-shell in PHP-FPM / da-php.scope (UID 1005, PID 3001) -> MUST BE REJECTED
	err := g.AuthorizeSocketPeer(PeerCred{PID: 3001, UID: 1005, GID: 1005}, false)
	if !errors.Is(err, ErrUnauthorizedLineage) {
		t.Fatalf("TC-01 FAILED: expected ErrUnauthorizedLineage for PHP-FPM web-shell PID 3001, got: %v", err)
	}

	// 2. Orphaned background shell / cron process (UID 1005, PID 4001) -> MUST BE REJECTED
	err = g.AuthorizeSocketPeer(PeerCred{PID: 4001, UID: 1005, GID: 1005}, false)
	if !errors.Is(err, ErrUnauthorizedLineage) {
		t.Fatalf("TC-01 FAILED: expected ErrUnauthorizedLineage for non-DA process PID 4001, got: %v", err)
	}

	// 3. Customer UID 1005 trying to connect to Admin Socket -> MUST BE REJECTED
	err = g.AuthorizeSocketPeer(PeerCred{PID: 2001, UID: 1005, GID: 1005}, true)
	if !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer when customer connects to Admin Socket, got: %v", err)
	}

	// Verify security audit events were recorded
	events := st.RecentSecurityEvents(10)
	if len(events) < 3 {
		t.Fatalf("expected >= 3 recorded security audit events, got %d", len(events))
	}
}

func TestLegitimateDirectAdminSessionAndCSRFEnforcement(t *testing.T) {
	g, _, _, sessDir := setupTestGuardEnv(t)

	validSessID := "sess9988776655443322"
	if err := os.WriteFile(filepath.Join(sessDir, "da_sess_"+validSessID), []byte("username=reno26\nip=1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	legitCred := PeerCred{PID: 2001, UID: 1005, GID: 1005}
	if err := g.AuthorizeSocketPeer(legitCred, false); err != nil {
		t.Fatalf("expected legitimate DA CGI process to pass Layer 1+2, got: %v", err)
	}

	// Read-only bootstrap succeeds without CSRF token and allows issuing CSRF token
	caller, err := g.AuthenticateUserRequest(legitCred, "reno26", validSessID, "", false)
	if err != nil {
		t.Fatalf("expected read-only bootstrap auth to succeed, got: %v", err)
	}

	// Cross-tenant attempt (reno26 trying to query otheruser) -> REJECTED
	if _, err := g.AuthenticateUserRequest(legitCred, "otheruser", validSessID, "", false); !errors.Is(err, ErrUnauthorizedSession) {
		t.Fatalf("expected cross-tenant request to fail with ErrUnauthorizedSession, got: %v", err)
	}

	// Mutating request WITHOUT CSRF token -> REJECTED
	if _, err := g.AuthenticateUserRequest(legitCred, "reno26", validSessID, "", true); !errors.Is(err, ErrInvalidCSRFToken) {
		t.Fatalf("expected mutating request without CSRF token to fail, got: %v", err)
	}

	// Issue valid root-signed CSRF token and verify mutating request SUCCEEDS
	token, err := g.IssueCSRFToken(legitCred.UID, caller.Username, caller.SessionIDHash)
	if err != nil {
		t.Fatalf("IssueCSRFToken failed: %v", err)
	}
	if _, err := g.AuthenticateUserRequest(legitCred, "reno26", validSessID, token, true); err != nil {
		t.Fatalf("expected mutating request with valid CSRF token to succeed, got: %v", err)
	}
}

func TestAdminImpersonationLoginAsUserSession(t *testing.T) {
	g, _, _, sessDir := setupTestGuardEnv(t)

	// DirectAdmin "Login as reno26" from admin stores username=admin|reno26 while running user CGI as UID 1005
	impersonatedSess := "impersonate_1122334455"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+impersonatedSess), []byte("username=admin%7Creno26\n"), 0o600)

	legitCred := PeerCred{PID: 2001, UID: 1005, GID: 1005}
	caller, err := g.AuthenticateUserRequest(legitCred, "reno26", impersonatedSess, "", false)
	if err != nil || caller.Username != "reno26" {
		t.Fatalf("expected admin|reno26 Login-As session to authenticate as reno26, got err=%v caller=%+v", err, caller)
	}
}
