package quicktools

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/discovery"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/hardening"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

var reMemoryLimit = regexp.MustCompile(`^[1-9][0-9]{1,4}[MG]$`)

// DebugConfig represents WP_DEBUG, WP_DEBUG_LOG, and WP_DEBUG_DISPLAY states in wp-config.php.
type DebugConfig struct {
	WPDebug        bool `json:"wp_debug"`
	WPDebugLog     bool `json:"wp_debug_log"`
	WPDebugDisplay bool `json:"wp_debug_display"`
}

// PasswordProtectionRequest updates HTTP Basic Auth on an instance.
type PasswordProtectionRequest struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Realm    string `json:"realm,omitempty"`
}

// SafeWPConfigView exposes non-secret database metadata and safe editable wp-config.php constants.
type SafeWPConfigView struct {
	DBName             string `json:"db_name"`
	DBUser             string `json:"db_user"`
	DBHost             string `json:"db_host"`
	TablePrefix        string `json:"table_prefix"`
	CacheKeySalt       string `json:"cache_key_salt,omitempty"`
	WPMemoryLimit      string `json:"wp_memory_limit"`
	WPMaxMemoryLimit   string `json:"wp_max_memory_limit"`
	WPPostRevisions    int    `json:"wp_post_revisions"`
	AutosaveInterval   int    `json:"autosave_interval"`
	EmptyTrashDays     int    `json:"empty_trash_days"`
	ConcatenateScripts bool   `json:"concatenate_scripts"`
}

// SafeWPConfigUpdate mutates whitelisted operational constants in wp-config.php without permitting arbitrary PHP.
type SafeWPConfigUpdate struct {
	WPMemoryLimit      *string `json:"wp_memory_limit,omitempty"`
	WPMaxMemoryLimit   *string `json:"wp_max_memory_limit,omitempty"`
	WPPostRevisions    *int    `json:"wp_post_revisions,omitempty"`
	AutosaveInterval   *int    `json:"autosave_interval,omitempty"`
	EmptyTrashDays     *int    `json:"empty_trash_days,omitempty"`
	ConcatenateScripts *bool   `json:"concatenate_scripts,omitempty"`
}

// AdminAccountRequest updates an existing WP administrator or creates an emergency administrator account.
type AdminAccountRequest struct {
	Operation   string `json:"operation"` // update | create_emergency
	Username    string `json:"username"`
	Email       string `json:"email,omitempty"`
	NewPassword string `json:"new_password,omitempty"`
}

// SearchReplaceRequest configures serialized-safe database URL/string search-and-replace with optional Dry-Run.
type SearchReplaceRequest struct {
	Search  string `json:"search"`
	Replace string `json:"replace"`
	DryRun  bool   `json:"dry_run"`
}

// TableReplacement summarizes replacements in a single database table/column from `wp search-replace`.
type TableReplacement struct {
	Table        string `json:"table"`
	Column       string `json:"column"`
	Replacements int    `json:"replacements"`
	Type         string `json:"type"`
}

// SearchReplaceResult summarizes a Dry-Run or Live serialized-safe Search & Replace pass.
type SearchReplaceResult struct {
	DryRun            bool               `json:"dry_run"`
	Search            string             `json:"search"`
	Replace           string             `json:"replace"`
	TablesAffected    int                `json:"tables_affected"`
	TotalReplacements int                `json:"total_replacements"`
	Details           []TableReplacement `json:"details"`
}

// ToolsStatus aggregates all Plesk-style Quick Toggles, Deep-Links, and Config states for an instance card.
type ToolsStatus struct {
	Instance           store.InstanceRecord               `json:"instance"`
	ManageFilesURL     string                             `json:"manage_files_url"`
	PHPMyAdminURL      string                             `json:"phpmyadmin_url"`
	Maintenance        MaintenanceConfig                  `json:"maintenance"`
	Debug              DebugConfig                        `json:"debug"`
	PasswordProtection webserver.PasswordProtectionStatus `json:"password_protection"`
	SafeWPConfig       SafeWPConfigView                   `json:"safe_wp_config"`
	CronCommand        string                             `json:"cron_command,omitempty"`
}

// Manager implements the Plesk Quick Tools suite (7 Toggle Cards, Log Tail Viewer, DA Cron Takeover, Search-Replace, Cache & Safe Config).
type Manager struct {
	Domains               *dadomains.Resolver
	WPCLI                 *wpcli.Runner
	WebServer             *webserver.Adapter
	Cron                  *DACronManager
	Store                 *store.Store
	WithShieldSuppression func(acct dausers.Account, inst store.InstanceRecord, fn func() error) error
}

func NewManager(
	domains *dadomains.Resolver,
	wp *wpcli.Runner,
	ws *webserver.Adapter,
	cron *DACronManager,
	st *store.Store,
) *Manager {
	if cron == nil {
		cron = NewDACronManager("")
	}
	return &Manager{
		Domains:   domains,
		WPCLI:     wp,
		WebServer: ws,
		Cron:      cron,
		Store:     st,
	}
}

func (m *Manager) runSuppressed(acct dausers.Account, inst store.InstanceRecord, fn func() error) error {
	if m.WithShieldSuppression != nil {
		return m.WithShieldSuppression(acct, inst, fn)
	}
	return fn()
}

func (m *Manager) resolveInstanceAndGuard(acct dausers.Account, instanceID string) (store.InstanceRecord, *fsguard.Guard, string, daphp.Selection, error) {
	inst, err := m.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return store.InstanceRecord{}, nil, "", daphp.Selection{}, err
	}
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return store.InstanceRecord{}, nil, "", daphp.Selection{}, err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return store.InstanceRecord{}, nil, "", daphp.Selection{}, err
	}
	var phpSel daphp.Selection
	if m.Domains != nil {
		if tgt, tErr := m.Domains.FindTarget(acct, inst.Domain); tErr == nil {
			phpSel = tgt.PHP
		}
	}
	return inst, guard, verifiedDocRoot, phpSel, nil
}

// BuildFileManagerDeepLink builds a DirectAdmin Evolution Skin File Manager URL pointing straight to DocRoot.
func BuildFileManagerDeepLink(acct dausers.Account, docRoot string) string {
	home := filepath.Clean(acct.HomeDir)
	cleanDoc := filepath.Clean(docRoot)
	rel, err := filepath.Rel(home, cleanDoc)
	relSlash := "/"
	if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		relSlash = "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
	}
	return "/evo/user/file-manager?path=" + url.QueryEscape(relSlash)
}

// GetStatus inspects live filesystem and wp-config.php states for all Quick Tools on an instance.
func (m *Manager) GetStatus(acct dausers.Account, instanceID string) (ToolsStatus, error) {
	inst, guard, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return ToolsStatus{}, err
	}

	maint := readMaintenanceConfig(guard, verifiedDocRoot)
	dbg, safeCfg := readDebugAndSafeWPConfig(guard, verifiedDocRoot, inst)

	var pwStatus webserver.PasswordProtectionStatus
	if m.WebServer != nil {
		pwStatus = m.WebServer.GetPasswordProtectionStatus(acct, inst)
	}

	var cronCmd string
	if inst.DisableWPCron {
		cronCmd = BuildWPCronCommand(phpSel.BinaryPath, verifiedDocRoot, inst.ID)
	}

	// Keep Store flags aligned with live disk reality
	dirty := false
	if inst.MaintenanceMode != maint.Enabled {
		inst.MaintenanceMode = maint.Enabled
		dirty = true
	}
	if inst.DebugMode != dbg.WPDebug {
		inst.DebugMode = dbg.WPDebug
		dirty = true
	}
	if inst.PasswordProtected != pwStatus.Enabled {
		inst.PasswordProtected = pwStatus.Enabled
		dirty = true
	}
	if dirty {
		if saved, uErr := m.Store.UpsertInstance(inst); uErr == nil {
			inst = saved
		}
	}

	return ToolsStatus{
		Instance:           inst,
		ManageFilesURL:     BuildFileManagerDeepLink(acct, verifiedDocRoot),
		PHPMyAdminURL:      "/phpMyAdmin/",
		Maintenance:        maint,
		Debug:              dbg,
		PasswordProtection: pwStatus,
		SafeWPConfig:       safeCfg,
		CronCommand:        cronCmd,
	}, nil
}

// SetSearchIndexing toggles WordPress `blog_public` (`1` = allow indexing, `0` = `noindex`).
func (m *Manager) SetSearchIndexing(ctx context.Context, acct dausers.Account, instanceID string, allowIndexing bool) (store.InstanceRecord, error) {
	inst, _, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return store.InstanceRecord{}, err
	}
	if m.WPCLI == nil {
		return store.InstanceRecord{}, errors.New("WP-CLI runner is not configured")
	}
	val := "0"
	if allowIndexing {
		val = "1"
	}
	if _, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDocRoot,
		PHP:         phpSel,
		Args:        []string{"option", "update", "blog_public", val},
		SkipPlugins: true,
		SkipThemes:  true,
	}); err != nil {
		return store.InstanceRecord{}, err
	}
	inst.SearchIndexing = allowIndexing
	return m.Store.UpsertInstance(inst)
}

// SetMaintenanceMode toggles or customizes the HTTP 503 Maintenance screen.
func (m *Manager) SetMaintenanceMode(_ context.Context, acct dausers.Account, instanceID string, req MaintenanceConfig) (MaintenanceConfig, error) {
	inst, guard, verifiedDocRoot, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return MaintenanceConfig{}, err
	}
	var updated MaintenanceConfig
	err = m.runSuppressed(acct, inst, func() error {
		var innerErr error
		updated, innerErr = applyMaintenanceState(guard, acct, verifiedDocRoot, inst.SiteTitle, req)
		return innerErr
	})
	if err != nil {
		return MaintenanceConfig{}, err
	}
	inst.MaintenanceMode = updated.Enabled
	_, _ = m.Store.UpsertInstance(inst)
	return updated, nil
}

// SetDebugConfig atomically updates WP_DEBUG, WP_DEBUG_LOG, and WP_DEBUG_DISPLAY in wp-config.php.
func (m *Manager) SetDebugConfig(_ context.Context, acct dausers.Account, instanceID string, req DebugConfig) (DebugConfig, error) {
	inst, guard, verifiedDocRoot, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return DebugConfig{}, err
	}
	if !req.WPDebug {
		req.WPDebugLog = false
		req.WPDebugDisplay = false
	}

	err = m.runSuppressed(acct, inst, func() error {
		return mutateWPConfigFile(guard, acct, verifiedDocRoot, func(cur string) (string, error) {
			next, _ := hardening.SetDefinedBool(cur, "WP_DEBUG", req.WPDebug)
			next, _ = hardening.SetDefinedBool(next, "WP_DEBUG_LOG", req.WPDebugLog)
			next, _ = hardening.SetDefinedBool(next, "WP_DEBUG_DISPLAY", req.WPDebugDisplay)
			return next, nil
		})
	})
	if err != nil {
		return DebugConfig{}, err
	}
	inst.DebugMode = req.WPDebug
	_, _ = m.Store.UpsertInstance(inst)
	return req, nil
}

// ReadDebugLog reads the last maxBytes (default 32 KB) of `wp-content/debug.log`.
func (m *Manager) ReadDebugLog(acct dausers.Account, instanceID string, maxBytes int64) (DebugLogTail, error) {
	_, guard, verifiedDocRoot, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return DebugLogTail{}, err
	}
	return ReadDebugLogTail(guard, verifiedDocRoot, maxBytes)
}

// ClearDebugLog truncates `wp-content/debug.log` safely.
func (m *Manager) ClearDebugLog(acct dausers.Account, instanceID string) error {
	_, guard, verifiedDocRoot, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return err
	}
	return ClearDebugLog(guard, acct, verifiedDocRoot)
}

// SetPasswordProtection enables, updates, or disables HTTP Basic Authentication across all 4 web servers.
func (m *Manager) SetPasswordProtection(ctx context.Context, acct dausers.Account, instanceID string, req PasswordProtectionRequest) (webserver.PasswordProtectionStatus, error) {
	if m.WebServer == nil {
		return webserver.PasswordProtectionStatus{}, errors.New("web server adapter is not configured")
	}
	inst, _, _, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return webserver.PasswordProtectionStatus{}, err
	}

	var st webserver.PasswordProtectionStatus
	err = m.runSuppressed(acct, inst, func() error {
		var innerErr error
		st, innerErr = m.WebServer.SetPasswordProtection(ctx, acct, inst, req.Enabled, req.Username, req.Password, req.Realm)
		return innerErr
	})
	if err != nil {
		return webserver.PasswordProtectionStatus{}, err
	}

	inst.PasswordProtected = st.Enabled
	_, _ = m.Store.UpsertInstance(inst)
	return st, nil
}

// SetWPCronTakeover toggles DISABLE_WP_CRON in wp-config.php and syncs a real DirectAdmin system cronjob.
func (m *Manager) SetWPCronTakeover(ctx context.Context, acct dausers.Account, instanceID string, disableWPCron bool, intervalMin int) (store.InstanceRecord, string, error) {
	inst, guard, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return store.InstanceRecord{}, "", err
	}
	normInterval := NormalizeCronInterval(intervalMin)

	err = m.runSuppressed(acct, inst, func() error {
		return mutateWPConfigFile(guard, acct, verifiedDocRoot, func(cur string) (string, error) {
			next, _ := hardening.SetDefinedBool(cur, "DISABLE_WP_CRON", disableWPCron)
			return next, nil
		})
	})
	if err != nil {
		return store.InstanceRecord{}, "", err
	}

	var cronCmd string
	if m.Cron != nil {
		cmdStr, cErr := m.Cron.SyncInstanceCron(ctx, acct.Username, inst.ID, disableWPCron, normInterval, phpSel.BinaryPath, verifiedDocRoot)
		if cErr != nil {
			return store.InstanceRecord{}, "", cErr
		}
		cronCmd = cmdStr
	}

	inst.DisableWPCron = disableWPCron
	if disableWPCron {
		inst.CronIntervalMin = normInterval
	} else {
		inst.CronIntervalMin = 0
	}
	saved, err := m.Store.UpsertInstance(inst)
	if err != nil {
		return store.InstanceRecord{}, "", err
	}
	return saved, cronCmd, nil
}

// SetCaching toggles `WP_CACHE` in wp-config.php and activates/flushes LiteSpeed/Redis cache integration when available.
func (m *Manager) SetCaching(ctx context.Context, acct dausers.Account, instanceID string, enabled bool) (store.InstanceRecord, error) {
	inst, guard, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return store.InstanceRecord{}, err
	}

	err = m.runSuppressed(acct, inst, func() error {
		return mutateWPConfigFile(guard, acct, verifiedDocRoot, func(cur string) (string, error) {
			next, _ := hardening.SetDefinedBool(cur, "WP_CACHE", enabled)
			return next, nil
		})
	})
	if err != nil {
		return store.InstanceRecord{}, err
	}

	if m.WPCLI != nil && !enabled {
		_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDocRoot,
			PHP:         phpSel,
			Args:        []string{"cache", "flush"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
	}

	inst.CacheEnabled = enabled
	return m.Store.UpsertInstance(inst)
}

// ClearCache flushes WordPress Object Cache (Redis/Memcached), Rewrite rules, LiteSpeed Cache, and wp-content/cache directories.
func (m *Manager) ClearCache(ctx context.Context, acct dausers.Account, instanceID string) (map[string]any, error) {
	_, guard, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return nil, err
	}

	flushedObjectCache := false
	if m.WPCLI != nil {
		if _, cErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDocRoot,
			PHP:         phpSel,
			Args:        []string{"cache", "flush"},
			SkipPlugins: true,
			SkipThemes:  true,
		}); cErr == nil {
			flushedObjectCache = true
		}
		// If LiteSpeed Cache CLI is installed, purge LSCache tags cleanly as well
		_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account: acct,
			DocRoot: verifiedDocRoot,
			PHP:     phpSel,
			Args:    []string{"litespeed-purge", "all"},
		})
		_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDocRoot,
			PHP:         phpSel,
			Args:        []string{"rewrite", "flush"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
	}

	purgedDirs := purgeSafeCacheDirectories(guard, verifiedDocRoot)
	return map[string]any{
		"object_cache_flushed": flushedObjectCache,
		"purged_directories":   purgedDirs,
	}, nil
}

// UpdateSiteTitle updates WordPress `blogname` option and syncs InstanceRecord.SiteTitle.
func (m *Manager) UpdateSiteTitle(ctx context.Context, acct dausers.Account, instanceID, newTitle string) (store.InstanceRecord, error) {
	cleanTitle := strings.TrimSpace(newTitle)
	if cleanTitle == "" || len(cleanTitle) > 160 {
		return store.InstanceRecord{}, errors.New("site title must be 1..160 characters")
	}
	inst, _, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return store.InstanceRecord{}, err
	}
	if m.WPCLI == nil {
		return store.InstanceRecord{}, errors.New("WP-CLI runner is not configured")
	}
	if _, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDocRoot,
		PHP:         phpSel,
		Args:        []string{"option", "update", "blogname", cleanTitle},
		SkipPlugins: true,
		SkipThemes:  true,
	}); err != nil {
		return store.InstanceRecord{}, err
	}
	inst.SiteTitle = cleanTitle
	return m.Store.UpsertInstance(inst)
}

// ManageAdminAccount updates an existing administrator's email/password or creates an emergency administrator via STDIN (never exposing passwords in argv).
func (m *Manager) ManageAdminAccount(ctx context.Context, acct dausers.Account, instanceID string, req AdminAccountRequest) (store.InstanceRecord, error) {
	inst, _, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return store.InstanceRecord{}, err
	}
	if m.WPCLI == nil {
		return store.InstanceRecord{}, errors.New("WP-CLI runner is not configured")
	}

	userLogin := strings.TrimSpace(req.Username)
	if userLogin == "" {
		userLogin = inst.AdminUser
	}
	if userLogin == "" {
		return store.InstanceRecord{}, errors.New("administrator username is required")
	}
	if req.NewPassword != "" && len(req.NewPassword) < 8 {
		return store.InstanceRecord{}, errors.New("administrator password must be at least 8 characters")
	}

	op := strings.ToLower(strings.TrimSpace(req.Operation))
	if op == "" {
		op = "update"
	}
	if op != "update" && op != "create_emergency" {
		return store.InstanceRecord{}, errors.New("operation must be 'update' or 'create_emergency'")
	}
	if op == "create_emergency" {
		lower := strings.ToLower(userLogin)
		if lower == "admin" || lower == "administrator" || lower == "root" {
			return store.InstanceRecord{}, errors.New("weak administrator username is forbidden")
		}
		if strings.TrimSpace(req.Email) == "" || req.NewPassword == "" {
			return store.InstanceRecord{}, errors.New("both email and new_password are required for create_emergency")
		}
	}

	stdinPayload, _ := json.Marshal(map[string]string{
		"op":    op,
		"login": userLogin,
		"email": strings.TrimSpace(req.Email),
		"pass":  req.NewPassword,
	})
	phpScript := `$in = json_decode(stream_get_contents(STDIN), true);
if (!is_array($in)) { WP_CLI::error('invalid stdin payload'); }
if ($in['op'] === 'create_emergency') {
    $uid = wp_create_user($in['login'], $in['pass'], $in['email']);
    if (is_wp_error($uid)) { WP_CLI::error($uid->get_error_message()); }
    $u = new WP_User($uid);
    $u->set_role('administrator');
    WP_CLI::success('created');
} else {
    $u = get_user_by('login', $in['login']);
    if (!$u) { WP_CLI::error('administrator user not found'); }
    if ($in['email'] !== '') {
        $r = wp_update_user(array('ID' => $u->ID, 'user_email' => $in['email']));
        if (is_wp_error($r)) { WP_CLI::error($r->get_error_message()); }
    }
    if ($in['pass'] !== '') {
        wp_set_password($in['pass'], $u->ID);
    }
    WP_CLI::success('updated');
}`

	if _, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDocRoot,
		PHP:         phpSel,
		Args:        []string{"eval", phpScript},
		Stdin:       string(stdinPayload),
		SkipPlugins: true,
		SkipThemes:  true,
	}); err != nil {
		return store.InstanceRecord{}, err
	}

	inst.AdminUser = userLogin
	if strings.TrimSpace(req.Email) != "" {
		inst.AdminEmail = strings.TrimSpace(req.Email)
	}
	return m.Store.UpsertInstance(inst)
}

// SearchReplace executes serialized-safe `wp search-replace` with Dry-Run preview support.
func (m *Manager) SearchReplace(ctx context.Context, acct dausers.Account, instanceID string, req SearchReplaceRequest) (SearchReplaceResult, error) {
	if req.Search == "" {
		return SearchReplaceResult{}, errors.New("search string cannot be empty")
	}
	if req.Search == req.Replace {
		return SearchReplaceResult{}, errors.New("search and replace strings are identical")
	}
	inst, _, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return SearchReplaceResult{}, err
	}
	if m.WPCLI == nil {
		return SearchReplaceResult{}, errors.New("WP-CLI runner is not configured")
	}

	args := []string{
		"search-replace",
		req.Search,
		req.Replace,
		"--all-tables-with-prefix",
		"--precise",
		"--format=csv",
	}
	if req.DryRun {
		args = append(args, "--dry-run")
	}

	stdout, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDocRoot,
		PHP:         phpSel,
		Args:        args,
		SkipPlugins: true,
		SkipThemes:  true,
	})
	if err != nil {
		return SearchReplaceResult{}, err
	}

	res := parseSearchReplaceCSV(stdout, req)

	if !req.DryRun {
		_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDocRoot,
			PHP:         phpSel,
			Args:        []string{"cache", "flush"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		if req.Search == inst.SiteURL && strings.HasPrefix(req.Replace, "http") {
			inst.SiteURL = req.Replace
			_, _ = m.Store.UpsertInstance(inst)
		}
	}
	return res, nil
}

// RunDBMaintenance executes `wp db optimize` or `wp db repair`.
func (m *Manager) RunDBMaintenance(ctx context.Context, acct dausers.Account, instanceID, operation string) (string, error) {
	op := strings.ToLower(strings.TrimSpace(operation))
	if op != "optimize" && op != "repair" {
		return "", errors.New("database operation must be 'optimize' or 'repair'")
	}
	_, _, verifiedDocRoot, phpSel, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return "", err
	}
	if m.WPCLI == nil {
		return "", errors.New("WP-CLI runner is not configured")
	}
	out, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDocRoot,
		PHP:         phpSel,
		Args:        []string{"db", op},
		SkipPlugins: true,
		SkipThemes:  true,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// GetSafeWPConfig reads database connection metadata (without DB_PASSWORD!) and whitelisted constants from wp-config.php.
func (m *Manager) GetSafeWPConfig(acct dausers.Account, instanceID string) (SafeWPConfigView, error) {
	inst, guard, verifiedDocRoot, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return SafeWPConfigView{}, err
	}
	_, view := readDebugAndSafeWPConfig(guard, verifiedDocRoot, inst)
	return view, nil
}

// UpdateSafeWPConfig safely updates whitelisted operational constants in wp-config.php.
func (m *Manager) UpdateSafeWPConfig(acct dausers.Account, instanceID string, upd SafeWPConfigUpdate) (SafeWPConfigView, error) {
	if upd.WPMemoryLimit != nil {
		v := strings.ToUpper(strings.TrimSpace(*upd.WPMemoryLimit))
		if !reMemoryLimit.MatchString(v) {
			return SafeWPConfigView{}, fmt.Errorf("invalid wp_memory_limit %q (expected e.g. 128M, 256M, 512M)", *upd.WPMemoryLimit)
		}
		*upd.WPMemoryLimit = v
	}
	if upd.WPMaxMemoryLimit != nil {
		v := strings.ToUpper(strings.TrimSpace(*upd.WPMaxMemoryLimit))
		if !reMemoryLimit.MatchString(v) {
			return SafeWPConfigView{}, fmt.Errorf("invalid wp_max_memory_limit %q (expected e.g. 256M, 512M)", *upd.WPMaxMemoryLimit)
		}
		*upd.WPMaxMemoryLimit = v
	}
	if upd.WPPostRevisions != nil && (*upd.WPPostRevisions < 0 || *upd.WPPostRevisions > 200) {
		return SafeWPConfigView{}, errors.New("wp_post_revisions must be between 0 and 200")
	}
	if upd.AutosaveInterval != nil && (*upd.AutosaveInterval < 15 || *upd.AutosaveInterval > 3600) {
		return SafeWPConfigView{}, errors.New("autosave_interval must be between 15 and 3600 seconds")
	}
	if upd.EmptyTrashDays != nil && (*upd.EmptyTrashDays < 0 || *upd.EmptyTrashDays > 365) {
		return SafeWPConfigView{}, errors.New("empty_trash_days must be between 0 and 365")
	}

	inst, guard, verifiedDocRoot, _, err := m.resolveInstanceAndGuard(acct, instanceID)
	if err != nil {
		return SafeWPConfigView{}, err
	}

	err = m.runSuppressed(acct, inst, func() error {
		return mutateWPConfigFile(guard, acct, verifiedDocRoot, func(cur string) (string, error) {
			next := cur
			var sErr error
			if upd.WPMemoryLimit != nil {
				next, sErr = hardening.SetDefinedString(next, "WP_MEMORY_LIMIT", *upd.WPMemoryLimit)
				if sErr != nil {
					return "", sErr
				}
			}
			if upd.WPMaxMemoryLimit != nil {
				next, sErr = hardening.SetDefinedString(next, "WP_MAX_MEMORY_LIMIT", *upd.WPMaxMemoryLimit)
				if sErr != nil {
					return "", sErr
				}
			}
			if upd.WPPostRevisions != nil {
				next, _ = hardening.SetDefinedInt(next, "WP_POST_REVISIONS", *upd.WPPostRevisions)
			}
			if upd.AutosaveInterval != nil {
				next, _ = hardening.SetDefinedInt(next, "AUTOSAVE_INTERVAL", *upd.AutosaveInterval)
			}
			if upd.EmptyTrashDays != nil {
				next, _ = hardening.SetDefinedInt(next, "EMPTY_TRASH_DAYS", *upd.EmptyTrashDays)
			}
			if upd.ConcatenateScripts != nil {
				next, _ = hardening.SetDefinedBool(next, "CONCATENATE_SCRIPTS", *upd.ConcatenateScripts)
			}
			return next, nil
		})
	})
	if err != nil {
		return SafeWPConfigView{}, err
	}

	if upd.WPMemoryLimit != nil {
		inst.MemoryLimit = *upd.WPMemoryLimit
		_, _ = m.Store.UpsertInstance(inst)
	}
	_, view := readDebugAndSafeWPConfig(guard, verifiedDocRoot, inst)
	return view, nil
}

// CleanupInstance removes DirectAdmin cron entries and .htpasswd artifacts when an instance is detached or uninstalled.
func (m *Manager) CleanupInstance(ctx context.Context, acct dausers.Account, inst store.InstanceRecord) {
	if m.Cron != nil {
		_, _ = m.Cron.SyncInstanceCron(ctx, acct.Username, inst.ID, false, 15, "", inst.DocRoot)
	}
	if m.WebServer != nil && inst.PasswordProtected {
		_, _ = m.WebServer.SetPasswordProtection(ctx, acct, inst, false, "", "", "")
	}
}

func readDebugAndSafeWPConfig(guard *fsguard.Guard, verifiedDocRoot string, inst store.InstanceRecord) (DebugConfig, SafeWPConfigView) {
	view := SafeWPConfigView{
		DBName:             inst.DBName,
		DBUser:             inst.DBUser,
		DBHost:             "localhost",
		TablePrefix:        inst.TablePrefix,
		WPMemoryLimit:      defaultIfEmpty(inst.MemoryLimit, "128M"),
		WPMaxMemoryLimit:   "256M",
		WPPostRevisions:    10,
		AutosaveInterval:   60,
		EmptyTrashDays:     30,
		ConcatenateScripts: true,
	}
	var dbg DebugConfig

	raw, err := guard.ReadRegularFileUnderVerifiedRoot(verifiedDocRoot, 128*1024, "wp-config.php")
	if err != nil {
		return dbg, view
	}
	content := string(raw)
	parsed := discovery.ParseWPConfig(raw)
	if parsed.DBName != "" {
		view.DBName = parsed.DBName
	}
	if parsed.DBUser != "" {
		view.DBUser = parsed.DBUser
	}
	if parsed.DBHost != "" {
		view.DBHost = parsed.DBHost
	}
	if parsed.TablePrefix != "" {
		view.TablePrefix = parsed.TablePrefix
	}

	dbg.WPDebug, _ = hardening.GetDefinedBool(content, "WP_DEBUG")
	dbg.WPDebugLog, _ = hardening.GetDefinedBool(content, "WP_DEBUG_LOG")
	dbg.WPDebugDisplay, _ = hardening.GetDefinedBool(content, "WP_DEBUG_DISPLAY")

	if v, ok := hardening.GetDefinedString(content, "WP_CACHE_KEY_SALT"); ok {
		view.CacheKeySalt = v
	}
	if v, ok := hardening.GetDefinedString(content, "WP_MEMORY_LIMIT"); ok && v != "" {
		view.WPMemoryLimit = v
	}
	if v, ok := hardening.GetDefinedString(content, "WP_MAX_MEMORY_LIMIT"); ok && v != "" {
		view.WPMaxMemoryLimit = v
	}
	if n, ok := hardening.GetDefinedInt(content, "WP_POST_REVISIONS"); ok {
		view.WPPostRevisions = n
	} else if b, ok := hardening.GetDefinedBool(content, "WP_POST_REVISIONS"); ok && !b {
		view.WPPostRevisions = 0
	}
	if n, ok := hardening.GetDefinedInt(content, "AUTOSAVE_INTERVAL"); ok {
		view.AutosaveInterval = n
	}
	if n, ok := hardening.GetDefinedInt(content, "EMPTY_TRASH_DAYS"); ok {
		view.EmptyTrashDays = n
	}
	if b, ok := hardening.GetDefinedBool(content, "CONCATENATE_SCRIPTS"); ok {
		view.ConcatenateScripts = b
	}
	return dbg, view
}

func mutateWPConfigFile(guard *fsguard.Guard, acct dausers.Account, verifiedDocRoot string, fn func(string) (string, error)) error {
	raw, err := guard.ReadRegularFileUnderVerifiedRoot(verifiedDocRoot, 128*1024, "wp-config.php")
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(verifiedDocRoot, "wp-config.php")
	perm := os.FileMode(0o600)
	if st, sErr := os.Lstat(cfgPath); sErr == nil {
		perm = st.Mode().Perm()
	}
	updated, err := fn(string(raw))
	if err != nil {
		return err
	}
	return writeCustomerFileAtomic(acct, cfgPath, []byte(updated), perm)
}

func purgeSafeCacheDirectories(guard *fsguard.Guard, verifiedDocRoot string) []string {
	candidates := [][]string{
		{"wp-content", "cache"},
		{"wp-content", "litespeed", "cache"},
		{"wp-content", "litespeed", "cssjs"},
		{"wp-content", "et-cache"},
	}
	var purged []string
	for _, relSegs := range candidates {
		dirPath, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, relSegs...)
		if err != nil {
			continue
		}
		entries, rErr := os.ReadDir(dirPath)
		if rErr != nil {
			continue
		}
		removedAny := false
		for _, ent := range entries {
			name := ent.Name()
			if name == ".htaccess" || name == "index.php" || name == "index.html" {
				continue
			}
			child := filepath.Join(dirPath, name)
			if st, lErr := os.Lstat(child); lErr == nil && st.Mode()&os.ModeSymlink == 0 {
				_ = os.RemoveAll(child)
				removedAny = true
			}
		}
		if removedAny {
			purged = append(purged, strings.Join(relSegs, "/"))
		}
	}
	return purged
}

func parseSearchReplaceCSV(stdout string, req SearchReplaceRequest) SearchReplaceResult {
	res := SearchReplaceResult{
		DryRun:  req.DryRun,
		Search:  req.Search,
		Replace: req.Replace,
		Details: []TableReplacement{},
	}
	r := csv.NewReader(strings.NewReader(strings.TrimSpace(stdout)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return res
	}
	tableSet := make(map[string]struct{})
	for i, row := range rows {
		if len(row) < 3 {
			continue
		}
		if i == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "Table") {
			continue
		}
		cnt, cErr := strconv.Atoi(strings.TrimSpace(row[2]))
		if cErr != nil || cnt <= 0 {
			continue
		}
		tbl := strings.TrimSpace(row[0])
		col := strings.TrimSpace(row[1])
		tp := ""
		if len(row) >= 4 {
			tp = strings.TrimSpace(row[3])
		}
		tableSet[tbl] = struct{}{}
		res.TotalReplacements += cnt
		res.Details = append(res.Details, TableReplacement{
			Table:        tbl,
			Column:       col,
			Replacements: cnt,
			Type:         tp,
		})
	}
	res.TablesAffected = len(tableSet)
	return res
}
