package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	ShieldModeMonitor      = "monitor"
	ShieldModeAutoHeal     = "auto_heal"
	ShieldModeFortressLock = "fortress_lock"

	DefaultChannelStable   = "stable"
	DefaultChannelBeta     = "beta"
	DefaultBackupRetention = 5
)

// PackagePolicy defines per-package feature quotas and security defaults for end users.
type PackagePolicy struct {
	Enabled                bool   `json:"enabled"`
	MaxInstances           int    `json:"max_instances"` // 0 = unlimited
	AllowClone             bool   `json:"allow_clone"`
	AllowStagingSync       bool   `json:"allow_staging_sync"`
	AllowCoreFortressLock  bool   `json:"allow_core_fortress_lock"`
	MaxSnapshotsPerSite    int    `json:"max_snapshots_per_site"`
	DefaultCoreShieldMode  string `json:"default_core_shield_mode"`
	AutoHardeningOnInstall bool   `json:"auto_hardening_on_install"`
}

// DefaultPackagePolicy returns safe, customer-friendly production defaults.
func DefaultPackagePolicy() PackagePolicy {
	return PackagePolicy{
		Enabled:                true,
		MaxInstances:           0,
		AllowClone:             true,
		AllowStagingSync:       true,
		AllowCoreFortressLock:  true,
		MaxSnapshotsPerSite:    5,
		DefaultCoreShieldMode:  ShieldModeAutoHeal,
		AutoHardeningOnInstall: true,
	}
}

// Validate normalizes and validates PackagePolicy fields.
func (p *PackagePolicy) Validate() error {
	if p.MaxInstances < 0 || p.MaxInstances > 10000 {
		return fmt.Errorf("max_instances out of range (0..10000): %d", p.MaxInstances)
	}
	if p.MaxSnapshotsPerSite < 0 || p.MaxSnapshotsPerSite > 100 {
		return fmt.Errorf("max_snapshots_per_site out of range (0..100): %d", p.MaxSnapshotsPerSite)
	}
	switch p.DefaultCoreShieldMode {
	case ShieldModeMonitor, ShieldModeAutoHeal, ShieldModeFortressLock:
	case "":
		p.DefaultCoreShieldMode = ShieldModeAutoHeal
	default:
		return fmt.Errorf("invalid default_core_shield_mode %q", p.DefaultCoreShieldMode)
	}
	return nil
}

// UpdaterConfig stores root-only GitHub Self-Updater parameters (/etc/da-wptoolkit/updater.conf).
type UpdaterConfig struct {
	GitHubRepo      string `json:"github_repo"`
	GitHubToken     string `json:"-"`
	UpdateChannel   string `json:"update_channel"`
	BackupRetention int    `json:"backup_retention"`
}

// ValidateIdentifier ensures a username, package name, or config key cannot traverse paths or inject shell/INI tokens.
func ValidateIdentifier(s string) error {
	if len(s) == 0 || len(s) > 64 {
		return fmt.Errorf("identifier length must be 1..64 bytes")
	}
	if s == "." || s == ".." {
		return errors.New("dot path segments are forbidden")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		isExtra := c == '_' || c == '-' || c == '.'
		if i == 0 && !isAlpha && !isDigit {
			return fmt.Errorf("identifier %q must start with an alphanumeric character", s)
		}
		if !isAlpha && !isDigit && !isExtra {
			return fmt.Errorf("identifier %q contains invalid character %q", s, c)
		}
	}
	return nil
}

// ValidateSessionID strictly validates a DirectAdmin session identifier before touching /usr/local/directadmin/data/sessions/.
func ValidateSessionID(s string) error {
	if len(s) < 8 || len(s) > 128 {
		return errors.New("invalid DirectAdmin session ID length")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !isDigit && c != '_' && c != '-' {
			return errors.New("DirectAdmin session ID contains forbidden characters")
		}
	}
	return nil
}

// ValidateInstanceID validates a toolkit WordPress instance identifier.
func ValidateInstanceID(s string) error {
	if len(s) < 4 || len(s) > 64 {
		return errors.New("invalid instance ID length")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !isDigit && c != '_' && c != '-' {
			return errors.New("instance ID contains forbidden characters")
		}
	}
	return nil
}

// ValidateDomainName validates an ASCII/punycode FQDN managed by DirectAdmin.
func ValidateDomainName(domain string) error {
	d := strings.ToLower(strings.TrimSpace(domain))
	if len(d) < 3 || len(d) > 253 || !strings.Contains(d, ".") {
		return fmt.Errorf("invalid domain name %q", domain)
	}
	labels := strings.Split(d, ".")
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 {
			return fmt.Errorf("invalid domain label in %q", domain)
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return fmt.Errorf("domain label cannot start or end with hyphen in %q", domain)
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return fmt.Errorf("domain %q contains invalid character %q", domain, c)
			}
		}
	}
	return nil
}

// PolicyStore reads and writes default and per-package policies atomically.
type PolicyStore struct {
	DataDir        string
	UpdaterCfgPath string
}

func NewPolicyStore(dataDir, updaterCfgPath string) *PolicyStore {
	return &PolicyStore{
		DataDir:        dataDir,
		UpdaterCfgPath: updaterCfgPath,
	}
}

func (s *PolicyStore) LoadDefaultPolicy() (PackagePolicy, error) {
	base := DefaultPackagePolicy()
	p := filepath.Join(s.DataDir, "default_policy.conf")
	kv, err := readKeyValueFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return base, nil
		}
		return base, err
	}
	applyPolicyKV(&base, kv)
	return base, base.Validate()
}

func (s *PolicyStore) SaveDefaultPolicy(pol PackagePolicy) error {
	if err := pol.Validate(); err != nil {
		return err
	}
	p := filepath.Join(s.DataDir, "default_policy.conf")
	return atomicWriteFile(p, []byte(formatPolicyKV(pol)), 0o640)
}

func (s *PolicyStore) ResolvePackagePolicy(pkgName string) (PackagePolicy, error) {
	pol, err := s.LoadDefaultPolicy()
	if err != nil {
		return pol, err
	}
	if strings.TrimSpace(pkgName) == "" {
		return pol, nil
	}
	if err := ValidateIdentifier(pkgName); err != nil {
		return pol, err
	}
	pkgPath := filepath.Join(s.DataDir, "packages", pkgName+".conf")
	kv, err := readKeyValueFile(pkgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return pol, nil
		}
		return pol, err
	}
	applyPolicyKV(&pol, kv)
	return pol, pol.Validate()
}

func (s *PolicyStore) SavePackagePolicy(pkgName string, pol PackagePolicy) error {
	if err := ValidateIdentifier(pkgName); err != nil {
		return err
	}
	if err := pol.Validate(); err != nil {
		return err
	}
	pkgPath := filepath.Join(s.DataDir, "packages", pkgName+".conf")
	return atomicWriteFile(pkgPath, []byte(formatPolicyKV(pol)), 0o640)
}

func (s *PolicyStore) DeletePackagePolicy(pkgName string) error {
	if err := ValidateIdentifier(pkgName); err != nil {
		return err
	}
	pkgPath := filepath.Join(s.DataDir, "packages", pkgName+".conf")
	if info, err := os.Lstat(pkgPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove symlinked package policy %s", pkgPath)
	}
	if err := os.Remove(pkgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *PolicyStore) ListPackageOverrides() []string {
	dir := filepath.Join(s.DataDir, "packages")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(ent.Name(), ".conf")
		if ValidateIdentifier(name) == nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (s *PolicyStore) updaterPath() string {
	if strings.TrimSpace(s.UpdaterCfgPath) != "" {
		return s.UpdaterCfgPath
	}
	return filepath.Join(s.DataDir, "updater.conf")
}

func (s *PolicyStore) LoadUpdaterConfig(defaultRepo string) (UpdaterConfig, error) {
	cfg := UpdaterConfig{
		GitHubRepo:      strings.TrimSpace(defaultRepo),
		UpdateChannel:   DefaultChannelStable,
		BackupRetention: DefaultBackupRetention,
	}
	kv, err := readKeyValueFile(s.updaterPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if ch := strings.ToLower(strings.TrimSpace(kv["UPDATE_CHANNEL"])); ch == DefaultChannelStable || ch == DefaultChannelBeta {
		cfg.UpdateChannel = ch
	}
	if n, nErr := strconv.Atoi(strings.TrimSpace(kv["BACKUP_RETENTION"])); nErr == nil && n >= 1 && n <= 50 {
		cfg.BackupRetention = n
	}
	if tok, ok := kv["GITHUB_TOKEN"]; ok {
		cfg.GitHubToken = strings.TrimSpace(tok)
	}
	return cfg, nil
}

func (s *PolicyStore) SaveUpdaterConfig(defaultRepo string, channel string, retention int, newToken string, updateToken bool, clearToken bool) (UpdaterConfig, error) {
	existing, _ := s.LoadUpdaterConfig(defaultRepo)
	ch := strings.ToLower(strings.TrimSpace(channel))
	if ch == "" {
		ch = existing.UpdateChannel
	}
	if ch != DefaultChannelStable && ch != DefaultChannelBeta {
		return existing, fmt.Errorf("invalid update_channel %q (must be stable or beta)", channel)
	}
	if retention <= 0 {
		retention = existing.BackupRetention
	}
	if retention < 1 || retention > 50 {
		return existing, fmt.Errorf("backup_retention out of range (1..50): %d", retention)
	}
	token := existing.GitHubToken
	if clearToken {
		token = ""
	} else if updateToken {
		t := strings.TrimSpace(newToken)
		if strings.ContainsAny(t, "\r\n\x00") || len(t) > 256 {
			return existing, errors.New("invalid GitHub token format")
		}
		token = t
	}
	updated := UpdaterConfig{
		GitHubRepo:      strings.TrimSpace(defaultRepo),
		GitHubToken:     token,
		UpdateChannel:   ch,
		BackupRetention: retention,
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GITHUB_REPO=%s\n", updated.GitHubRepo)
	fmt.Fprintf(&b, "UPDATE_CHANNEL=%s\n", updated.UpdateChannel)
	fmt.Fprintf(&b, "BACKUP_RETENTION=%d\n", updated.BackupRetention)
	if updated.GitHubToken != "" {
		fmt.Fprintf(&b, "GITHUB_TOKEN=%s\n", updated.GitHubToken)
	}
	if err := atomicWriteFile(s.updaterPath(), []byte(b.String()), 0o600); err != nil {
		return existing, err
	}
	return updated, nil
}

func applyPolicyKV(pol *PackagePolicy, kv map[string]string) {
	if v, ok := kv["ENABLED"]; ok {
		pol.Enabled = parseBool(v, pol.Enabled)
	}
	if v, ok := kv["MAX_INSTANCES"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			pol.MaxInstances = n
		}
	}
	if v, ok := kv["ALLOW_CLONE"]; ok {
		pol.AllowClone = parseBool(v, pol.AllowClone)
	}
	if v, ok := kv["ALLOW_STAGING_SYNC"]; ok {
		pol.AllowStagingSync = parseBool(v, pol.AllowStagingSync)
	}
	if v, ok := kv["ALLOW_CORE_FORTRESS_LOCK"]; ok {
		pol.AllowCoreFortressLock = parseBool(v, pol.AllowCoreFortressLock)
	}
	if v, ok := kv["MAX_SNAPSHOTS_PER_SITE"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			pol.MaxSnapshotsPerSite = n
		}
	}
	if v, ok := kv["DEFAULT_CORE_SHIELD_MODE"]; ok && v != "" {
		pol.DefaultCoreShieldMode = v
	}
	if v, ok := kv["AUTO_HARDENING_ON_INSTALL"]; ok {
		pol.AutoHardeningOnInstall = parseBool(v, pol.AutoHardeningOnInstall)
	}
}

func formatPolicyKV(pol PackagePolicy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ENABLED=%s\n", formatBool(pol.Enabled))
	fmt.Fprintf(&b, "MAX_INSTANCES=%d\n", pol.MaxInstances)
	fmt.Fprintf(&b, "ALLOW_CLONE=%s\n", formatBool(pol.AllowClone))
	fmt.Fprintf(&b, "ALLOW_STAGING_SYNC=%s\n", formatBool(pol.AllowStagingSync))
	fmt.Fprintf(&b, "ALLOW_CORE_FORTRESS_LOCK=%s\n", formatBool(pol.AllowCoreFortressLock))
	fmt.Fprintf(&b, "MAX_SNAPSHOTS_PER_SITE=%d\n", pol.MaxSnapshotsPerSite)
	fmt.Fprintf(&b, "DEFAULT_CORE_SHIELD_MODE=%s\n", pol.DefaultCoreShieldMode)
	fmt.Fprintf(&b, "AUTO_HARDENING_ON_INSTALL=%s\n", formatBool(pol.AutoHardeningOnInstall))
	return b.String()
}

func parseBool(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func formatBool(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func readKeyValueFile(path string) (map[string]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to read symlinked config file %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		out[k] = v
	}
	return out, sc.Err()
}

func atomicWriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s", path)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
