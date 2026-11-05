package dausers

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
)

const (
	DefaultMinUID   = uint32(500)
	DefaultMaxUID   = uint32(65533) // Explicitly excludes nobody/nfsnobody (65534)
	DefaultCacheTTL = 2 * time.Second
)

// Account represents a validated DirectAdmin hosting user mapped to an OS UID/GID.
type Account struct {
	Username  string `json:"username"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	HomeDir   string `json:"home_dir"`
	Package   string `json:"package"`
	Creator   string `json:"creator"`
	Email     string `json:"email"`
	Suspended bool   `json:"suspended"`
}

type passwdEntry struct {
	Username string
	UID      uint32
	GID      uint32
	HomeDir  string
}

// Registry synchronizes DirectAdmin user metadata with /etc/passwd and admin.list.
type Registry struct {
	DADataRoot string // Default: /usr/local/directadmin/data
	PasswdPath string // Default: /etc/passwd
	MinUID     uint32
	MaxUID     uint32
	CacheTTL   time.Duration

	mu          sync.RWMutex
	lastRefresh time.Time
	byUsername  map[string]Account
	byUID       map[uint32]Account
	adminUIDs   map[uint32]string
	adminNames  map[string]uint32
	diradminUID uint32
}

func NewRegistry(daDataRoot, passwdPath string) *Registry {
	if daDataRoot == "" {
		daDataRoot = "/usr/local/directadmin/data"
	}
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	minUID := envUint32("DA_WPTK_MIN_UID", DefaultMinUID)
	maxUID := envUint32("DA_WPTK_MAX_UID", DefaultMaxUID)
	return &Registry{
		DADataRoot: daDataRoot,
		PasswdPath: passwdPath,
		MinUID:     minUID,
		MaxUID:     maxUID,
		CacheTTL:   DefaultCacheTTL,
		byUsername: make(map[string]Account),
		byUID:      make(map[uint32]Account),
		adminUIDs:  make(map[uint32]string),
		adminNames: make(map[string]uint32),
	}
}

func (r *Registry) ensureFresh() {
	r.mu.RLock()
	fresh := !r.lastRefresh.IsZero() && time.Since(r.lastRefresh) < r.CacheTTL
	r.mu.RUnlock()
	if fresh {
		return
	}
	_ = r.Reload()
}

// Reload forces an immediate re-index of /etc/passwd, admin.list, and DirectAdmin users/.
func (r *Registry) Reload() error {
	pwByName, pwByUID, err := parsePasswd(r.PasswdPath)
	if err != nil {
		return err
	}

	adminNamesList := readLines(filepath.Join(r.DADataRoot, "admin", "admin.list"))
	adminSet := make(map[string]struct{}, len(adminNamesList)+1)
	for _, a := range adminNamesList {
		if config.ValidateIdentifier(a) == nil {
			adminSet[a] = struct{}{}
		}
	}

	adminUIDs := make(map[uint32]string)
	adminNames := make(map[string]uint32)
	for name := range adminSet {
		if pw, ok := pwByName[name]; ok {
			adminUIDs[pw.UID] = name
			adminNames[name] = pw.UID
		}
	}

	var diradminUID uint32
	if pw, ok := pwByName["diradmin"]; ok {
		diradminUID = pw.UID
	}

	usersDir := filepath.Join(r.DADataRoot, "users")
	entries, _ := os.ReadDir(usersDir)

	byUsername := make(map[string]Account)
	byUID := make(map[uint32]Account)

	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		uname := ent.Name()
		if config.ValidateIdentifier(uname) != nil {
			continue
		}
		if uname == "root" || uname == "diradmin" || uname == "nobody" || uname == "nfsnobody" {
			continue
		}
		pw, ok := pwByName[uname]
		if !ok {
			continue
		}
		if pw.UID < r.MinUID || pw.UID > r.MaxUID {
			continue
		}
		// Exclude pure system administrator accounts if they have no domains, unless admin also hosts domains;
		// Wait: on DirectAdmin, 'admin' CAN also host personal domains under /home/admin/domains/,
		// EXCEPT if 'admin' is strictly listed as admin we still track whether they are an admin separately.
		userConfPath := filepath.Join(usersDir, uname, "user.conf")
		kv := readSimpleConf(userConfPath)
		if len(kv) == 0 {
			continue
		}

		acct := Account{
			Username:  uname,
			UID:       pw.UID,
			GID:       pw.GID,
			HomeDir:   pw.HomeDir,
			Package:   kv["package"],
			Creator:   kv["creator"],
			Email:     kv["email"],
			Suspended: strings.EqualFold(kv["suspended"], "yes"),
		}
		byUsername[uname] = acct
		byUID[pw.UID] = acct
	}
	_ = pwByUID

	r.mu.Lock()
	r.byUsername = byUsername
	r.byUID = byUID
	r.adminUIDs = adminUIDs
	r.adminNames = adminNames
	r.diradminUID = diradminUID
	r.lastRefresh = time.Now()
	r.mu.Unlock()
	return nil
}

func (r *Registry) LookupByUID(uid uint32) (Account, bool) {
	r.ensureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	acct, ok := r.byUID[uid]
	return acct, ok
}

func (r *Registry) LookupByUsername(username string) (Account, bool) {
	r.ensureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	acct, ok := r.byUsername[username]
	return acct, ok
}

func (r *Registry) ListAccounts() []Account {
	r.ensureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Account, 0, len(r.byUsername))
	for _, acct := range r.byUsername {
		out = append(out, acct)
	}
	return out
}

// IsAuthorizedAdminUID returns (adminName, true) if uid is root (0), diradmin, or listed in admin.list.
func (r *Registry) IsAuthorizedAdminUID(uid uint32) (string, bool) {
	if uid == 0 {
		return "root", true
	}
	r.ensureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.diradminUID > 0 && uid == r.diradminUID {
		return "diradmin", true
	}
	if name, ok := r.adminUIDs[uid]; ok {
		return name, true
	}
	return "", false
}

// IsAdminName checks whether a DirectAdmin username is listed in admin.list.
func (r *Registry) IsAdminName(username string) bool {
	if username == "root" || username == "diradmin" {
		return true
	}
	r.ensureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.adminNames[username]
	return ok
}

// IsRootOrDiradminUID restricts system-level operations (self-updater) strictly to root or diradmin.
func (r *Registry) IsRootOrDiradminUID(uid uint32) bool {
	if uid == 0 {
		return true
	}
	r.ensureFresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.diradminUID > 0 && uid == r.diradminUID
}

func parsePasswd(path string) (map[string]passwdEntry, map[uint32]passwdEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	byName := make(map[string]passwdEntry)
	byUID := make(map[uint32]passwdEntry)

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}
		uid64, err1 := strconv.ParseUint(parts[2], 10, 32)
		gid64, err2 := strconv.ParseUint(parts[3], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		homeRaw := parts[5]
		if len(parts) > 7 {
			homeRaw = filepath.FromSlash(strings.Join(parts[5:len(parts)-1], ":"))
		}
		ent := passwdEntry{
			Username: parts[0],
			UID:      uint32(uid64),
			GID:      uint32(gid64),
			HomeDir:  homeRaw,
		}
		byName[ent.Username] = ent
		byUID[ent.UID] = ent
	}
	return byName, byUID, sc.Err()
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s != "" && !strings.HasPrefix(s, "#") {
			lines = append(lines, s)
		}
	}
	return lines
}

func readSimpleConf(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		out[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}
	return out
}

func envUint32(key string, fallback uint32) uint32 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return fallback
	}
	return uint32(v)
}
