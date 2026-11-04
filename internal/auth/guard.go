package auth

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

const (
	DefaultProcRoot      = "/proc"
	DefaultDASessionsDir = "/usr/local/directadmin/data/sessions"
	DefaultCSRFKeyPath   = "/var/lib/da-wptoolkit/secret/csrf.key"
	DefaultSessionMaxAge = 24 * time.Hour
	csrfWindowSeconds    = 43200 // 12 hours
	maxLineageDepth      = 16
)

var (
	ErrUnauthorizedPeer    = errors.New("403 Unauthorized Peer: caller UID is not permitted on this socket")
	ErrUnauthorizedLineage = errors.New("403 Unauthorized Peer Lineage: caller did not originate from DirectAdmin panel")
	ErrUnauthorizedSession = errors.New("403 Unauthorized Session: invalid or expired DirectAdmin login session")
	ErrInvalidCSRFToken    = errors.New("403 Forbidden: missing or invalid CSRF security token")
)

// PeerCred holds kernel-verified SO_PEERCRED process credentials of the Unix socket client.
type PeerCred struct {
	PID int32  `json:"pid"`
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

// VerifiedCaller represents a fully authenticated DirectAdmin User or Administrator session.
type VerifiedCaller struct {
	Peer          PeerCred
	Username      string
	Account       dausers.Account
	IsAdmin       bool
	IsRootCLI     bool
	SessionIDHash string
}

// Guard enforces 3-layer Zero-Trust authentication (SO_PEERCRED + Process Lineage + DirectAdmin Session & CSRF).
type Guard struct {
	Users         *dausers.Registry
	Store         *store.Store
	ProcRoot      string
	DASessionsDir string
	CSRFKeyPath   string
	SessionMaxAge time.Duration
	NowFunc       func() time.Time

	keyMu   sync.Mutex
	csrfKey []byte
}

func NewGuard(users *dausers.Registry, st *store.Store, procRoot, daSessionsDir, csrfKeyPath string) *Guard {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	if daSessionsDir == "" {
		daSessionsDir = DefaultDASessionsDir
	}
	if csrfKeyPath == "" {
		csrfKeyPath = DefaultCSRFKeyPath
	}
	return &Guard{
		Users:         users,
		Store:         st,
		ProcRoot:      procRoot,
		DASessionsDir: daSessionsDir,
		CSRFKeyPath:   csrfKeyPath,
		SessionMaxAge: DefaultSessionMaxAge,
		NowFunc:       time.Now,
	}
}

func (g *Guard) now() time.Time {
	if g.NowFunc != nil {
		return g.NowFunc()
	}
	return time.Now()
}

// AuthorizeSocketPeer runs Layer 1 (UID validation) and Layer 2 (Process Lineage anti-webshell check)
// immediately upon socket accept BEFORE reading or decoding any JSON payload (TC-01).
func (g *Guard) AuthorizeSocketPeer(cred PeerCred, isAdminSocket bool) error {
	if isAdminSocket {
		if cred.UID == 0 {
			return nil // Root CLI / DirectAdmin root hook
		}
		if _, ok := g.Users.IsAuthorizedAdminUID(cred.UID); !ok {
			g.auditReject("ipc_auth", "", cred, "non-admin UID attempted connection to admin socket")
			return fmt.Errorf("%w (uid=%d)", ErrUnauthorizedPeer, cred.UID)
		}
		if err := g.VerifyDirectAdminLineage(cred.PID); err != nil {
			g.auditReject("ipc_auth", "", cred, err.Error())
			return err
		}
		return nil
	}

	// User socket: allow root (for diagnostics), authorized admins, or valid DirectAdmin hosting accounts
	if cred.UID == 0 {
		return nil
	}
	var ownerName string
	if acct, ok := g.Users.LookupByUID(cred.UID); ok {
		ownerName = acct.Username
	} else if adminName, ok := g.Users.IsAuthorizedAdminUID(cred.UID); ok {
		ownerName = adminName
	} else {
		g.auditReject("ipc_auth", "", cred, "unmanaged UID attempted connection to user socket")
		return fmt.Errorf("%w (uid=%d)", ErrUnauthorizedPeer, cred.UID)
	}

	if err := g.VerifyDirectAdminLineage(cred.PID); err != nil {
		g.auditReject("ipc_auth", ownerName, cred, err.Error())
		return err
	}
	return nil
}

// VerifyDirectAdminLineage inspects /proc/<pid>/cgroup and walks /proc/<pid>/stat PPid chain
// to guarantee the caller was spawned by DirectAdmin CGI and NOT by php-fpm, lsphp, cron, or sshd.
func (g *Guard) VerifyDirectAdminLineage(pid int32) error {
	if pid <= 1 {
		return fmt.Errorf("%w: invalid peer PID %d", ErrUnauthorizedLineage, pid)
	}

	// Fast reject if caller cgroup belongs to web worker pools or SSH sessions
	cgBytes, err := os.ReadFile(filepath.Join(g.ProcRoot, strconv.Itoa(int(pid)), "cgroup"))
	if err == nil {
		cgLower := strings.ToLower(string(cgBytes))
		for _, forbidden := range []string{
			"da-php.scope",
			"php-fpm",
			"lshttpd",
			"lsws",
			"apache2.service",
			"httpd.service",
			"nginx.service",
			"sshd.service",
		} {
			if strings.Contains(cgLower, forbidden) {
				return fmt.Errorf("%w: web/remote worker cgroup %q blocked", ErrUnauthorizedLineage, forbidden)
			}
		}
	}

	curPID := pid
	visited := make(map[int32]struct{}, maxLineageDepth)

	for hop := 0; hop < maxLineageDepth && curPID > 1; hop++ {
		if _, seen := visited[curPID]; seen {
			break
		}
		visited[curPID] = struct{}{}

		comm, ppid, statErr := g.readProcCommAndPPID(curPID)
		if statErr != nil {
			if hop == 0 {
				return fmt.Errorf("%w: cannot inspect /proc/%d/stat", ErrUnauthorizedLineage, curPID)
			}
			break
		}

		exePath := g.readProcExe(curPID)
		commLower := strings.ToLower(comm)
		exeLower := strings.ToLower(filepath.ToSlash(exePath))

		// Reject if any ancestor in the chain is a web application worker, cron, or SSH daemon
		for _, bad := range []string{"php-fpm", "lsphp", "lshttpd", "httpd", "apache2", "nginx", "sshd", "crond", "cron"} {
			if commLower == bad || strings.HasSuffix(exeLower, "/"+bad) {
				return fmt.Errorf("%w: ancestor PID %d (%s) is forbidden", ErrUnauthorizedLineage, curPID, bad)
			}
		}

		// Match DirectAdmin master/worker binary
		if strings.HasSuffix(exeLower, "/usr/local/directadmin/directadmin") ||
			(commLower == "directadmin" && g.isPrivilegedProcOwner(curPID)) {
			return nil
		}

		curPID = ppid
	}

	return fmt.Errorf("%w: PID %d has no DirectAdmin ancestor", ErrUnauthorizedLineage, pid)
}

// AuthenticateUserRequest performs Layer 3 verification (DirectAdmin da_sess_* + CSRF HMAC token on mutating actions).
func (g *Guard) AuthenticateUserRequest(cred PeerCred, claimedUsername, sessionID, csrfToken string, mutating bool) (VerifiedCaller, error) {
	if cred.UID == 0 {
		// Root CLI diagnostic access: resolve target user directly
		acct, ok := g.Users.LookupByUsername(claimedUsername)
		if !ok && claimedUsername != "" {
			return VerifiedCaller{}, fmt.Errorf("unknown DirectAdmin user %q", claimedUsername)
		}
		return VerifiedCaller{
			Peer:      cred,
			Username:  claimedUsername,
			Account:   acct,
			IsAdmin:   true,
			IsRootCLI: true,
		}, nil
	}

	sessUser, sessCreator, err := g.verifyDASessionFile(sessionID)
	if err != nil {
		g.auditReject("ipc_auth", claimedUsername, cred, err.Error())
		return VerifiedCaller{}, err
	}

	var resolvedAcct dausers.Account
	var isAdmin bool

	if acct, ok := g.Users.LookupByUID(cred.UID); ok {
		// Caller process runs under customer's Unix UID: session MUST belong to this exact customer
		if sessUser != acct.Username {
			msg := fmt.Sprintf("session user %q does not match caller UID %d (%s)", sessUser, cred.UID, acct.Username)
			g.auditReject("ipc_auth", acct.Username, cred, msg)
			return VerifiedCaller{}, fmt.Errorf("%w: %s", ErrUnauthorizedSession, msg)
		}
		if claimedUsername != "" && claimedUsername != acct.Username {
			msg := fmt.Sprintf("caller %s attempted cross-tenant access to %s", acct.Username, claimedUsername)
			g.auditReject("ipc_auth", acct.Username, cred, msg)
			return VerifiedCaller{}, fmt.Errorf("%w: cross-tenant access denied", ErrUnauthorizedSession)
		}
		if mutating && acct.Suspended {
			return VerifiedCaller{}, errors.New("account is currently suspended; mutating operations are disabled")
		}
		resolvedAcct = acct
	} else if adminName, ok := g.Users.IsAuthorizedAdminUID(cred.UID); ok {
		isAdmin = true
		target := sessUser
		if claimedUsername != "" {
			target = claimedUsername
		}
		if sessUser != adminName && sessCreator != adminName && sessUser != target {
			return VerifiedCaller{}, fmt.Errorf("%w: admin session mismatch", ErrUnauthorizedSession)
		}
		if targetAcct, exists := g.Users.LookupByUsername(target); exists {
			resolvedAcct = targetAcct
		} else {
			resolvedAcct = dausers.Account{Username: target, UID: cred.UID}
		}
	} else {
		return VerifiedCaller{}, ErrUnauthorizedPeer
	}

	sessHash := shortSessionHash(sessionID)
	caller := VerifiedCaller{
		Peer:          cred,
		Username:      resolvedAcct.Username,
		Account:       resolvedAcct,
		IsAdmin:       isAdmin,
		SessionIDHash: sessHash,
	}

	if mutating {
		if err := g.VerifyCSRFToken(cred.UID, caller.Username, sessHash, csrfToken); err != nil {
			g.auditReject("ipc_auth", caller.Username, cred, "invalid CSRF token on mutating request")
			return VerifiedCaller{}, err
		}
	}

	return caller, nil
}

// AuthenticateAdminRequest validates Admin Socket requests (Root CLI or DirectAdmin Admin CGI session + CSRF).
func (g *Guard) AuthenticateAdminRequest(cred PeerCred, sessionID, csrfToken string, mutating bool) (VerifiedCaller, error) {
	if cred.UID == 0 {
		return VerifiedCaller{
			Peer:      cred,
			Username:  "root",
			IsAdmin:   true,
			IsRootCLI: true,
		}, nil
	}

	adminName, ok := g.Users.IsAuthorizedAdminUID(cred.UID)
	if !ok {
		g.auditReject("ipc_auth", "", cred, "unauthorized UID on admin socket")
		return VerifiedCaller{}, ErrUnauthorizedPeer
	}

	sessUser, _, err := g.verifyDASessionFile(sessionID)
	if err != nil {
		g.auditReject("ipc_auth", adminName, cred, err.Error())
		return VerifiedCaller{}, err
	}
	if !g.Users.IsAdminName(sessUser) {
		msg := fmt.Sprintf("session user %q is not in DirectAdmin admin.list", sessUser)
		g.auditReject("ipc_auth", adminName, cred, msg)
		return VerifiedCaller{}, fmt.Errorf("%w: %s", ErrUnauthorizedSession, msg)
	}

	sessHash := shortSessionHash(sessionID)
	if mutating {
		if err := g.VerifyCSRFToken(cred.UID, sessUser, sessHash, csrfToken); err != nil {
			g.auditReject("ipc_auth", sessUser, cred, "invalid CSRF token on admin mutating request")
			return VerifiedCaller{}, err
		}
	}

	return VerifiedCaller{
		Peer:          cred,
		Username:      sessUser,
		IsAdmin:       true,
		SessionIDHash: sessHash,
	}, nil
}

// IssueCSRFToken generates a root-secret HMAC-SHA256 token bound to (peerUID, username, sessionHash, 12h window).
func (g *Guard) IssueCSRFToken(peerUID uint32, username, sessionHash string) (string, error) {
	key, err := g.loadOrInitCSRFKey()
	if err != nil {
		return "", err
	}
	win := g.now().Unix() / csrfWindowSeconds
	return computeCSRFHMAC(key, peerUID, username, sessionHash, win), nil
}

// VerifyCSRFToken checks a provided token against the current and immediately preceding 12-hour HMAC windows.
func (g *Guard) VerifyCSRFToken(peerUID uint32, username, sessionHash, provided string) error {
	clean := strings.TrimSpace(provided)
	if len(clean) != 64 {
		return ErrInvalidCSRFToken
	}
	providedBytes, err := hex.DecodeString(clean)
	if err != nil {
		return ErrInvalidCSRFToken
	}
	key, err := g.loadOrInitCSRFKey()
	if err != nil {
		return err
	}
	win := g.now().Unix() / csrfWindowSeconds
	for _, w := range []int64{win, win - 1} {
		expectedHex := computeCSRFHMAC(key, peerUID, username, sessionHash, w)
		expectedBytes, _ := hex.DecodeString(expectedHex)
		if hmac.Equal(expectedBytes, providedBytes) {
			return nil
		}
	}
	return ErrInvalidCSRFToken
}

func computeCSRFHMAC(key []byte, peerUID uint32, username, sessionHash string, window int64) string {
	mac := hmac.New(sha256.New, key)
	fmt.Fprintf(mac, "%d|%s|%s|%d", peerUID, username, sessionHash, window)
	return hex.EncodeToString(mac.Sum(nil))
}

func (g *Guard) loadOrInitCSRFKey() ([]byte, error) {
	g.keyMu.Lock()
	defer g.keyMu.Unlock()

	if len(g.csrfKey) >= 32 {
		return g.csrfKey, nil
	}

	if info, err := os.Lstat(g.CSRFKeyPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("refusing to read symlinked CSRF key %s", g.CSRFKeyPath)
		}
		raw, readErr := os.ReadFile(g.CSRFKeyPath)
		if readErr == nil {
			decoded, decErr := hex.DecodeString(strings.TrimSpace(string(raw)))
			if decErr == nil && len(decoded) >= 32 {
				g.csrfKey = decoded
				return g.csrfKey, nil
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(g.CSRFKeyPath), 0o700); err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	hexLine := hex.EncodeToString(secret) + "\n"
	if err := os.WriteFile(g.CSRFKeyPath, []byte(hexLine), 0o600); err != nil {
		return nil, err
	}
	g.csrfKey = secret
	return g.csrfKey, nil
}

func (g *Guard) verifyDASessionFile(sessionID string) (effectiveUser string, creatorUser string, err error) {
	if err := config.ValidateSessionID(sessionID); err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrUnauthorizedSession, err)
	}

	candidates := []string{
		filepath.Join(g.DASessionsDir, "da_sess_"+sessionID),
		filepath.Join(g.DASessionsDir, "sess_"+sessionID),
	}

	var sessPath string
	var info os.FileInfo
	for _, c := range candidates {
		st, statErr := os.Lstat(c)
		if statErr == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return "", "", fmt.Errorf("%w: symlinked session file rejected", ErrUnauthorizedSession)
			}
			if st.Mode().IsRegular() {
				sessPath = c
				info = st
				break
			}
		}
	}
	if sessPath == "" {
		return "", "", fmt.Errorf("%w: active session file not found", ErrUnauthorizedSession)
	}

	maxAge := g.SessionMaxAge
	if maxAge <= 0 {
		maxAge = DefaultSessionMaxAge
	}
	if g.now().Sub(info.ModTime()) > maxAge {
		return "", "", fmt.Errorf("%w: DirectAdmin session expired", ErrUnauthorizedSession)
	}

	f, err := os.Open(sessPath)
	if err != nil {
		return "", "", fmt.Errorf("%w: unable to read session file", ErrUnauthorizedSession)
	}
	defer f.Close()

	kv := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// DirectAdmin session files may store newline-delimited key=val or URL-encoded query pairs
		if strings.Contains(line, "&") && strings.Contains(line, "=") {
			if parsed, pErr := url.ParseQuery(line); pErr == nil {
				for k, vals := range parsed {
					if len(vals) > 0 {
						kv[k] = vals[0]
					}
				}
				continue
			}
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if unesc, uErr := url.QueryUnescape(v); uErr == nil {
			v = unesc
		}
		kv[k] = v
	}

	rawUser := strings.TrimSpace(kv["username"])
	if rawUser == "" {
		return "", "", fmt.Errorf("%w: session missing username", ErrUnauthorizedSession)
	}

	// Support DirectAdmin "Login as User" format: "admin|reno26"
	if pipeIdx := strings.LastIndexByte(rawUser, '|'); pipeIdx > 0 && pipeIdx < len(rawUser)-1 {
		creatorUser = rawUser[:pipeIdx]
		effectiveUser = rawUser[pipeIdx+1:]
	} else {
		effectiveUser = rawUser
		creatorUser = strings.TrimSpace(kv["creator"])
	}

	if err := config.ValidateIdentifier(effectiveUser); err != nil {
		return "", "", fmt.Errorf("%w: invalid username in session", ErrUnauthorizedSession)
	}
	return effectiveUser, creatorUser, nil
}

func (g *Guard) readProcCommAndPPID(pid int32) (string, int32, error) {
	statPath := filepath.Join(g.ProcRoot, strconv.Itoa(int(pid)), "stat")
	raw, err := os.ReadFile(statPath)
	if err != nil {
		return "", 0, err
	}
	s := strings.TrimSpace(string(raw))
	openIdx := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if openIdx < 0 || closeIdx <= openIdx || closeIdx+2 >= len(s) {
		return "", 0, errors.New("malformed /proc/pid/stat")
	}
	comm := s[openIdx+1 : closeIdx]
	rest := strings.Fields(s[closeIdx+2:])
	// rest[0] = state ('S', 'R', ...), rest[1] = ppid
	if len(rest) < 2 {
		return "", 0, errors.New("truncated /proc/pid/stat fields")
	}
	ppid64, err := strconv.ParseInt(rest[1], 10, 32)
	if err != nil {
		return "", 0, err
	}
	return comm, int32(ppid64), nil
}

func (g *Guard) readProcExe(pid int32) string {
	p := filepath.Join(g.ProcRoot, strconv.Itoa(int(pid)), "exe")
	if target, err := os.Readlink(p); err == nil && target != "" {
		return strings.TrimSuffix(target, " (deleted)")
	}
	// Fallback for synthetic unit-test /proc trees where exe_path file may be used on non-Linux hosts
	if raw, err := os.ReadFile(filepath.Join(g.ProcRoot, strconv.Itoa(int(pid)), "exe_path")); err == nil {
		return strings.TrimSpace(string(raw))
	}
	return ""
}

func (g *Guard) isPrivilegedProcOwner(pid int32) bool {
	statusPath := filepath.Join(g.ProcRoot, strconv.Itoa(int(pid)), "status")
	f, err := os.Open(statusPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line[4:])
			if len(fields) > 0 {
				if uid64, pErr := strconv.ParseUint(fields[0], 10, 32); pErr == nil {
					return g.Users.IsRootOrDiradminUID(uint32(uid64))
				}
			}
		}
	}
	return false
}

func (g *Guard) auditReject(category, owner string, cred PeerCred, msg string) {
	if g.Store == nil {
		return
	}
	g.Store.RecordSecurityEvent(store.SecurityAuditEvent{
		Severity: "warning",
		Category: category,
		Owner:    owner,
		PeerUID:  cred.UID,
		PeerPID:  cred.PID,
		Message:  msg,
	})
}

func shortSessionHash(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:8])
}

// IsMutatingAction classifies IPC actions so read-only queries can bootstrap UI while mutating actions strictly enforce CSRF.
func IsMutatingAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "ping",
		"get_bootstrap",
		"get_overview",
		"list_domains",
		"list_instances",
		"get_instance",
		"list_plugins",
		"list_themes",
		"list_all_plugins",
		"list_all_themes",
		"search_wporg",
		"get_vulns",
		"get_vulndb_status",
		"get_security_status",
		"get_tools_status",
		"read_debug_log",
		"get_safe_wpconfig",
		"list_snapshots",
		"get_snapshot_download",
		"list_quarantine",
		"get_quarantine_diff",
		"list_whitelist",
		"get_core_cache_status",
		"list_sets",
		"list_jobs",
		"get_job",
		"get_security_events",
		"list_packages",
		"get_updater_config",
		"check_github_update":
		return false
	default:
		return true
	}
}
