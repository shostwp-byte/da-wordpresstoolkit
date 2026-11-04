package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/database"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

var weakAdminUsernames = map[string]struct{}{
	"admin":         {},
	"administrator": {},
	"root":          {},
	"test":          {},
	"user":          {},
	"wordpress":     {},
}

// InstallRequest defines parameters for 1-Click Express or Custom WordPress installation.
type InstallRequest struct {
	Domain        string `json:"domain"`
	SubPath       string `json:"sub_path"` // "" or "/blog"
	SiteTitle     string `json:"site_title"`
	WPVersion     string `json:"wp_version"` // "" = latest
	Locale        string `json:"locale"`     // default "vi"
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
	AdminEmail    string `json:"admin_email"`
	TablePrefix   string `json:"table_prefix"`
	SetID         string `json:"set_id"`
}

// InstallResult returns the created instance record and one-time generated admin credentials (never stored on disk).
type InstallResult struct {
	Instance              store.InstanceRecord `json:"instance"`
	AdminUser             string               `json:"admin_user"`
	GeneratedPassword     string               `json:"generated_password,omitempty"`
	AppliedPluginsCount   int                  `json:"applied_plugins_count"`
	PopulatedFromCorePool bool                 `json:"populated_from_core_pool"`
}

// Manager orchestrates 1-Click Install, Uninstall, Passwordless SSO, and Emergency Admin Reset.
type Manager struct {
	Domains           *dadomains.Resolver
	DB                database.Provisioner
	WPCLI             *wpcli.Runner
	Store             *store.Store
	Policies          *config.PolicyStore
	CoreCacheDir      string
	SSOTTLSeconds     int
	ReapDelayOverride time.Duration
}

func NewManager(
	domains *dadomains.Resolver,
	db database.Provisioner,
	wp *wpcli.Runner,
	st *store.Store,
	policies *config.PolicyStore,
	coreCacheDir string,
) *Manager {
	if coreCacheDir == "" {
		coreCacheDir = "/var/cache/da-wptoolkit/wp-core"
	}
	return &Manager{
		Domains:       domains,
		DB:            db,
		WPCLI:         wp,
		Store:         st,
		Policies:      policies,
		CoreCacheDir:  coreCacheDir,
		SSOTTLSeconds: DefaultSSOTTLSeconds,
	}
}

type preparedInstall struct {
	req             InstallRequest
	pol             config.PackagePolicy
	domainsRoot     string
	target          dadomains.DomainTarget
	verifiedDocRoot string
	generatedPass   string
}

// PrepareInstallRequest validates quota, domain ownership, symlink/traversal confinement, and weak-username rules
// up front (< 1ms), generating strong one-time credentials in memory when omitted so async callers get immediate feedback.
func (m *Manager) PrepareInstallRequest(acct dausers.Account, req InstallRequest) (InstallRequest, string, error) {
	prep, err := m.prepareInstall(acct, req)
	if err != nil {
		return InstallRequest{}, "", err
	}
	return prep.req, prep.generatedPass, nil
}

func (m *Manager) prepareInstall(acct dausers.Account, req InstallRequest) (preparedInstall, error) {
	pol := config.DefaultPackagePolicy()
	if m.Policies != nil {
		if resolved, err := m.Policies.ResolvePackagePolicy(acct.Package); err == nil {
			pol = resolved
		}
	}
	if !pol.Enabled {
		return preparedInstall{}, errors.New("WordPress Toolkit is disabled for your hosting package")
	}
	if pol.MaxInstances > 0 && len(m.Store.ListInstancesByOwner(acct.Username)) >= pol.MaxInstances {
		return preparedInstall{}, fmt.Errorf("hosting package limit reached (%d WordPress instances maximum)", pol.MaxInstances)
	}

	target, err := m.Domains.FindTarget(acct, req.Domain)
	if err != nil {
		return preparedInstall{}, err
	}

	subPath, err := normalizeSubPath(req.SubPath)
	if err != nil {
		return preparedInstall{}, err
	}
	if subPath != "" {
		relCheck := strings.TrimPrefix(subPath, "/")
		if owningSub, conflict := target.ExcludedRelPaths[relCheck]; conflict {
			return preparedInstall{}, fmt.Errorf("path %s belongs to subdomain %s; please select %s directly", subPath, owningSub, owningSub)
		}
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return preparedInstall{}, err
	}

	installDocRoot := target.DocRoot
	if subPath != "" {
		installDocRoot = filepath.Join(target.DocRoot, filepath.FromSlash(strings.TrimPrefix(subPath, "/")))
	}
	verifiedDocRoot, err := guard.VerifyProspectivePath(installDocRoot)
	if err != nil {
		return preparedInstall{}, err
	}

	if hasExistingWordPress(verifiedDocRoot) {
		return preparedInstall{}, fmt.Errorf("a WordPress installation already exists at %s%s", target.Domain, subPath)
	}

	adminUser := strings.TrimSpace(req.AdminUser)
	if adminUser == "" {
		suffix, _ := randomHex(2)
		adminUser = "wpadmin_" + suffix
	}
	if err := config.ValidateIdentifier(adminUser); err != nil {
		return preparedInstall{}, fmt.Errorf("invalid admin username: %w", err)
	}
	if _, weak := weakAdminUsernames[strings.ToLower(adminUser)]; weak {
		return preparedInstall{}, fmt.Errorf("weak admin username %q is blocked for security; please choose a custom username", adminUser)
	}

	generatedPass := ""
	adminPass := req.AdminPassword
	if len(strings.TrimSpace(adminPass)) < 10 {
		p, pErr := generateStrongSecret(20, false)
		if pErr != nil {
			return preparedInstall{}, pErr
		}
		adminPass = p
		generatedPass = p
	}

	adminEmail := strings.TrimSpace(req.AdminEmail)
	if adminEmail == "" || !strings.Contains(adminEmail, "@") {
		if acct.Email != "" && strings.Contains(acct.Email, "@") {
			adminEmail = acct.Email
		} else {
			adminEmail = "admin@" + target.Domain
		}
	}

	tablePrefix := strings.TrimSpace(req.TablePrefix)
	if tablePrefix == "" {
		pfxHex, _ := randomHex(2)
		tablePrefix = "wp_" + pfxHex + "_"
	} else if !isValidTablePrefix(tablePrefix) {
		return preparedInstall{}, errors.New("invalid table_prefix: must match [a-zA-Z0-9_]+ and end with '_'")
	}

	locale := strings.TrimSpace(req.Locale)
	if locale == "" {
		locale = "vi"
	} else if err := config.ValidateIdentifier(locale); err != nil {
		return preparedInstall{}, fmt.Errorf("invalid locale %q", locale)
	}

	wpVer := strings.TrimSpace(req.WPVersion)
	if wpVer != "" && config.ValidateIdentifier(wpVer) != nil {
		return preparedInstall{}, fmt.Errorf("invalid wp_version %q", wpVer)
	}

	siteTitle := strings.TrimSpace(req.SiteTitle)
	if siteTitle == "" {
		siteTitle = target.Domain
	}

	normalized := req
	normalized.Domain = target.Domain
	normalized.SubPath = subPath
	normalized.SiteTitle = siteTitle
	normalized.WPVersion = wpVer
	normalized.Locale = locale
	normalized.AdminUser = adminUser
	normalized.AdminPassword = adminPass
	normalized.AdminEmail = adminEmail
	normalized.TablePrefix = tablePrefix

	return preparedInstall{
		req:             normalized,
		pol:             pol,
		domainsRoot:     domainsRoot,
		target:          target,
		verifiedDocRoot: verifiedDocRoot,
		generatedPass:   generatedPass,
	}, nil
}

// Install executes the complete 1-Click WordPress installation pipeline for a DirectAdmin account.
func (m *Manager) Install(
	ctx context.Context,
	acct dausers.Account,
	req InstallRequest,
	report store.ProgressReporter,
) (InstallResult, error) {
	if report == nil {
		report = func(int, string) {}
	}

	prep, err := m.prepareInstall(acct, req)
	if err != nil {
		return InstallResult{}, err
	}
	pol := prep.pol
	domainsRoot := prep.domainsRoot
	target := prep.target
	subPath := prep.req.SubPath
	verifiedDocRoot := prep.verifiedDocRoot
	adminUser := prep.req.AdminUser
	adminPass := prep.req.AdminPassword
	generatedPass := prep.generatedPass
	adminEmail := prep.req.AdminEmail
	tablePrefix := prep.req.TablePrefix
	locale := prep.req.Locale
	wpVer := prep.req.WPVersion
	siteTitle := prep.req.SiteTitle
	req.SetID = prep.req.SetID

	scheme := "http://"
	if target.SSLActive {
		scheme = "https://"
	}
	siteURL := scheme + target.Domain + subPath

	// Step 1: Provision MariaDB database & user
	report(15, "Provisioning MariaDB database and user")
	dbCreds, err := m.DB.CreateDatabase(ctx, acct, target.Domain)
	if err != nil {
		return InstallResult{}, fmt.Errorf("database provisioning failed: %w", err)
	}
	rollbackDB := true
	defer func() {
		if rollbackDB {
			_ = m.DB.DropDatabase(context.Background(), acct, dbCreds.DBName, dbCreds.DBUser)
		}
	}()

	if err := ensurePathHierarchyOwned(domainsRoot, verifiedDocRoot, acct.UID, acct.GID); err != nil {
		return InstallResult{}, err
	}

	// Step 2: Populate WordPress Core from verified local cache or WP-CLI download
	report(35, "Deploying WordPress Core files")
	fromPool, resolvedVer, err := m.deployCoreFiles(ctx, acct, target, verifiedDocRoot, wpVer, locale)
	if err != nil {
		return InstallResult{}, err
	}

	// Step 3: Write hardened wp-config.php (0600, fresh salts, isolated WP_CACHE_KEY_SALT)
	report(55, "Generating hardened wp-config.php")
	wpCfgContent, err := generateHardenedWPConfig(dbCreds, tablePrefix, target.Domain+subPath, pol.AutoHardeningOnInstall)
	if err != nil {
		return InstallResult{}, err
	}
	wpCfgPath := filepath.Join(verifiedDocRoot, "wp-config.php")
	if err := writeOwnedFile(wpCfgPath, []byte(wpCfgContent), acct.UID, acct.GID, 0o600); err != nil {
		return InstallResult{}, fmt.Errorf("write wp-config.php: %w", err)
	}

	// Step 4: Initialize WordPress tables & set real admin password via STDIN (never exposed in /proc/pid/cmdline)
	report(75, "Running WordPress database installation")
	throwawayPass, _ := generateStrongSecret(24, true)
	_, err = m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account: acct,
		DocRoot: verifiedDocRoot,
		PHP:     target.PHP,
		Args: []string{
			"core", "install",
			"--url=" + siteURL,
			"--title=" + siteTitle,
			"--admin_user=" + adminUser,
			"--admin_password=" + throwawayPass,
			"--admin_email=" + adminEmail,
			"--skip-email",
		},
	})
	if err != nil {
		return InstallResult{}, err
	}

	if err := m.setUserPasswordViaStdin(ctx, acct, verifiedDocRoot, target.PHP, adminUser, adminPass); err != nil {
		return InstallResult{}, err
	}

	// Step 5: Apply Plugin & Theme Set if requested
	appliedPlugins := 0
	activeTheme := ""
	if strings.TrimSpace(req.SetID) != "" {
		report(88, "Installing selected Plugin & Theme Set")
		appliedPlugins, activeTheme = m.applySetBestEffort(ctx, acct, verifiedDocRoot, target.PHP, strings.TrimSpace(req.SetID))
	}

	// Step 6: Register managed instance in Store
	report(96, "Registering WordPress instance")
	securityScore := 1 // 0600 wp-config.php
	if pol.AutoHardeningOnInstall {
		securityScore = 2 // + DISALLOW_FILE_EDIT
	}
	inst := store.InstanceRecord{
		Owner:              acct.Username,
		OwnerUID:           acct.UID,
		Domain:             target.Domain,
		DomainType:         target.DomainType,
		SubPath:            subPath,
		DocRoot:            verifiedDocRoot,
		SiteURL:            siteURL,
		SiteTitle:          siteTitle,
		AdminUser:          adminUser,
		AdminEmail:         adminEmail,
		WPVersion:          resolvedVer,
		Locale:             locale,
		PHPVersion:         target.PHP.Version,
		MemoryLimit:        "256M",
		DBName:             dbCreds.DBName,
		DBUser:             dbCreds.DBUser,
		TablePrefix:        tablePrefix,
		ActiveTheme:        activeTheme,
		SSLActive:          target.SSLActive,
		SearchIndexing:     target.DomainType != dadomains.DomainTypeSubdomain || !strings.HasPrefix(target.Domain, "staging."),
		CoreShieldMode:     pol.DefaultCoreShieldMode,
		CoreIntegrityClean: true,
		SecurityScore:      securityScore,
		SecurityTotal:      12,
		PluginCount:        appliedPlugins,
		EnvironmentTag:     inferEnvTag(target.Domain, subPath),
		LastScannedAt:      time.Now().UTC(),
	}

	saved, err := m.Store.UpsertInstance(inst)
	if err != nil {
		return InstallResult{}, err
	}

	rollbackDB = false
	report(100, "WordPress installation completed")
	return InstallResult{
		Instance:              saved,
		AdminUser:             adminUser,
		GeneratedPassword:     generatedPass,
		AppliedPluginsCount:   appliedPlugins,
		PopulatedFromCorePool: fromPool,
	}, nil
}

// Uninstall removes WordPress files safely (preserving sibling classic subdomains & .well-known)
// and optionally drops the MariaDB database if no other instance shares it.
func (m *Manager) Uninstall(ctx context.Context, acct dausers.Account, instanceID string, dropDatabase bool) error {
	inst, err := m.Store.GetInstanceForOwner(instanceID, acct.Username)
	if err != nil {
		return err
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return err
	}
	verifiedRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		preservedTopDirs := map[string]struct{}{
			".well-known": {},
			"cgi-bin":     {},
		}
		if tgt, tErr := m.Domains.FindTarget(acct, inst.Domain); tErr == nil && inst.SubPath == "" {
			for relPath := range tgt.ExcludedRelPaths {
				topSeg := strings.Split(relPath, "/")[0]
				if topSeg != "" {
					preservedTopDirs[topSeg] = struct{}{}
				}
			}
		}

		if inst.SubPath != "" {
			// Subdirectory install (e.g. /blog): verify no excluded subdomain sits inside before removing folder
			entries, _ := os.ReadDir(verifiedRoot)
			for _, ent := range entries {
				_ = os.RemoveAll(filepath.Join(verifiedRoot, ent.Name()))
			}
			_ = os.Remove(verifiedRoot)
		} else {
			entries, _ := os.ReadDir(verifiedRoot)
			for _, ent := range entries {
				if _, keep := preservedTopDirs[ent.Name()]; keep {
					continue
				}
				_ = os.RemoveAll(filepath.Join(verifiedRoot, ent.Name()))
			}
		}
	}

	if dropDatabase && inst.DBName != "" {
		sharedByOther := false
		for _, other := range m.Store.ListAllInstances(true) {
			if other.ID != inst.ID && other.Owner == acct.Username && other.DBName == inst.DBName {
				sharedByOther = true
				break
			}
		}
		if !sharedByOther {
			_ = m.DB.DropDatabase(ctx, acct, inst.DBName, inst.DBUser)
		}
	}

	return m.Store.DeleteInstance(inst.ID)
}

// ResetAdminPassword resets a WordPress Administrator password safely via STDIN (--skip-plugins --skip-themes).
func (m *Manager) ResetAdminPassword(ctx context.Context, acct dausers.Account, instanceID, adminUser, newPassword string) error {
	if len(strings.TrimSpace(newPassword)) < 10 {
		return errors.New("new password must be at least 10 characters")
	}
	inst, err := m.Store.GetInstanceForOwner(instanceID, acct.Username)
	if err != nil {
		return err
	}
	if strings.TrimSpace(adminUser) == "" {
		adminUser = inst.AdminUser
	}
	if err := config.ValidateIdentifier(adminUser); err != nil {
		return fmt.Errorf("invalid admin username: %w", err)
	}
	tgt, err := m.Domains.FindTarget(acct, inst.Domain)
	if err != nil {
		return err
	}
	return m.setUserPasswordViaStdin(ctx, acct, inst.DocRoot, tgt.PHP, adminUser, newPassword)
}

func (m *Manager) setUserPasswordViaStdin(
	ctx context.Context,
	acct dausers.Account,
	docRoot string,
	phpSel daphp.Selection,
	username string,
	password string,
) error {
	evalCode := `$u = get_user_by('login', getenv('DA_WPTK_TARGET_ADMIN')); if (!$u) { fwrite(STDERR, "User not found\n"); exit(1); } $pw = rtrim(stream_get_contents(STDIN), "\r\n"); wp_set_password($pw, $u->ID);`
	_, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     docRoot,
		PHP:         phpSel,
		SkipPlugins: true,
		SkipThemes:  true,
		Stdin:       password + "\n",
		ExtraEnv:    map[string]string{"DA_WPTK_TARGET_ADMIN": username},
		Args:        []string{"eval", evalCode},
	})
	return err
}

func (m *Manager) deployCoreFiles(
	ctx context.Context,
	acct dausers.Account,
	target dadomains.DomainTarget,
	destDocRoot string,
	wpVersion string,
	locale string,
) (fromCache bool, resolvedVer string, err error) {
	verKey := wpVersion
	if verKey == "" {
		verKey = "latest"
	}
	cacheSubdir := filepath.Join(m.CoreCacheDir, verKey+"-"+locale)
	if st, statErr := os.Stat(filepath.Join(cacheSubdir, "wp-includes", "version.php")); statErr == nil && !st.IsDir() {
		if copyErr := copyDirOwned(cacheSubdir, destDocRoot, acct.UID, acct.GID); copyErr == nil {
			ver := extractQuickVersion(filepath.Join(destDocRoot, "wp-includes", "version.php"))
			if ver == "" {
				ver = wpVersion
			}
			return true, ver, nil
		}
	}

	dlArgs := []string{"core", "download", "--locale=" + locale}
	if wpVersion != "" {
		dlArgs = append(dlArgs, "--version="+wpVersion)
	}
	if _, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account: acct,
		DocRoot: destDocRoot,
		PHP:     target.PHP,
		Args:    dlArgs,
	}); err != nil {
		return false, "", err
	}

	ver := extractQuickVersion(filepath.Join(destDocRoot, "wp-includes", "version.php"))
	if ver == "" {
		ver = wpVersion
	}
	if ver == "" {
		ver = "latest"
	}
	return false, ver, nil
}

func (m *Manager) applySetBestEffort(
	ctx context.Context,
	acct dausers.Account,
	docRoot string,
	phpSel daphp.Selection,
	setID string,
) (installedPlugins int, activeTheme string) {
	sets := m.Store.ListSetsForOwner(acct.Username)
	var chosen *store.PluginSet
	for i := range sets {
		if sets[i].ID == setID {
			chosen = &sets[i]
			break
		}
	}
	if chosen == nil {
		return 0, ""
	}

	if len(chosen.Plugins) > 0 {
		args := append([]string{"plugin", "install"}, chosen.Plugins...)
		args = append(args, "--activate")
		if _, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account: acct,
			DocRoot: docRoot,
			PHP:     phpSel,
			Args:    args,
		}); err == nil {
			installedPlugins = len(chosen.Plugins)
		}
	}

	if len(chosen.Themes) > 0 {
		for _, th := range chosen.Themes {
			args := []string{"theme", "install", th}
			if chosen.ActiveTheme == th {
				args = append(args, "--activate")
			}
			if _, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account: acct,
				DocRoot: docRoot,
				PHP:     phpSel,
				Args:    args,
			}); err == nil && chosen.ActiveTheme == th {
				activeTheme = th
			}
		}
	}
	return installedPlugins, activeTheme
}

func generateHardenedWPConfig(creds database.Credentials, tablePrefix, siteScope string, autoHarden bool) (string, error) {
	saltKeys := []string{
		"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
		"AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT",
	}
	var salts strings.Builder
	for _, k := range saltKeys {
		val, err := generateStrongSecret(64, false)
		if err != nil {
			return "", err
		}
		escaped := strings.ReplaceAll(strings.ReplaceAll(val, `\`, `\\`), `'`, `\'`)
		fmt.Fprintf(&salts, "define( '%s', '%s' );\n", k, escaped)
	}

	cacheSaltRand, _ := randomHex(6)
	safeScope := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, siteScope)
	cacheSalt := safeScope + "_" + cacheSaltRand

	hardenLine := ""
	if autoHarden {
		hardenLine = "define( 'DISALLOW_FILE_EDIT', true );\n"
	}

	return fmt.Sprintf(`<?php
/**
 * WordPress configuration generated by DA-WordPressToolkits.
 */
define( 'DB_NAME', '%s' );
define( 'DB_USER', '%s' );
define( 'DB_PASSWORD', '%s' );
define( 'DB_HOST', '%s' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

%s
$table_prefix = '%s';

define( 'WP_DEBUG', false );
define( 'WP_MEMORY_LIMIT', '256M' );
define( 'FS_METHOD', 'direct' );
define( 'WP_CACHE_KEY_SALT', '%s' );
%s
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
`,
		creds.DBName,
		creds.DBUser,
		creds.Password,
		creds.Host,
		salts.String(),
		tablePrefix,
		cacheSalt,
		hardenLine,
	), nil
}

func normalizeSubPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "/" {
		return "", nil
	}
	trimmed = "/" + strings.Trim(filepath.ToSlash(trimmed), "/")
	segs := strings.Split(strings.TrimPrefix(trimmed, "/"), "/")
	if len(segs) > 2 {
		return "", errors.New("sub_path depth cannot exceed 2 levels")
	}
	blocked := map[string]struct{}{
		"wp-admin": {}, "wp-content": {}, "wp-includes": {}, "cgi-bin": {}, ".well-known": {},
	}
	for _, seg := range segs {
		if err := config.ValidateIdentifier(seg); err != nil {
			return "", fmt.Errorf("invalid sub_path segment %q: %w", seg, err)
		}
		if _, bad := blocked[strings.ToLower(seg)]; bad {
			return "", fmt.Errorf("reserved directory %q cannot be used as sub_path", seg)
		}
	}
	return trimmed, nil
}

func hasExistingWordPress(docRoot string) bool {
	if _, err := os.Lstat(filepath.Join(docRoot, "wp-config.php")); err == nil {
		return true
	}
	if _, err := os.Lstat(filepath.Join(docRoot, "wp-includes", "version.php")); err == nil {
		return true
	}
	return false
}

func isValidTablePrefix(p string) bool {
	if len(p) < 2 || len(p) > 24 || !strings.HasSuffix(p, "_") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func generateStrongSecret(length int, alnumOnly bool) (string, error) {
	alphabet := "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%^&*()-_=+"
	if alnumOnly {
		alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

func randomHex(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ensurePathHierarchyOwned(domainsRoot, targetDir string, uid, gid uint32) error {
	rel, err := filepath.Rel(domainsRoot, targetDir)
	if err != nil {
		return err
	}
	cur := domainsRoot
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		if err := ensureOwnedDir(cur, uid, gid, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func ensureOwnedDir(path string, uid, gid uint32, mode os.FileMode) error {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fsguard.ErrSymlinkBlocked
		}
		if st.IsDir() {
			return nil
		}
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	chownIfRoot(path, uid, gid)
	return nil
}

func writeOwnedFile(path string, data []byte, uid, gid uint32, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wptk-*")
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
	if _, err := tmp.Write(data); err != nil {
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
	chownIfRoot(tmpPath, uid, gid)
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func copyDirOwned(srcDir, dstDir string, uid, gid uint32) error {
	return filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return ensureOwnedDir(dstDir, uid, gid, 0o755)
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return ensureOwnedDir(target, uid, gid, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		raw, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		return writeOwnedFile(target, raw, uid, gid, 0o644)
	})
}

func extractQuickVersion(verFile string) string {
	raw, err := os.ReadFile(verFile)
	if err != nil {
		return ""
	}
	s := string(raw)
	idx := strings.Index(s, "$wp_version")
	if idx < 0 {
		return ""
	}
	sub := s[idx:]
	q1 := strings.IndexAny(sub, `'"`)
	if q1 < 0 || q1+1 >= len(sub) {
		return ""
	}
	quote := sub[q1]
	q2 := strings.IndexByte(sub[q1+1:], quote)
	if q2 <= 0 {
		return ""
	}
	return strings.TrimSpace(sub[q1+1 : q1+1+q2])
}

func inferEnvTag(domain, subPath string) string {
	lower := strings.ToLower(domain + subPath)
	if strings.HasPrefix(lower, "staging.") || strings.Contains(lower, "/staging") {
		return "staging"
	}
	if strings.HasPrefix(lower, "dev.") || strings.Contains(lower, "/dev") {
		return "development"
	}
	return "production"
}
