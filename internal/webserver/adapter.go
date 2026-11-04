package webserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

// ServerKind identifies the active DirectAdmin CustomBuild web server architecture.
type ServerKind string

const (
	KindApache        ServerKind = "apache"
	KindLiteSpeed     ServerKind = "litespeed"
	KindOpenLiteSpeed ServerKind = "openlitespeed"
	KindNginx         ServerKind = "nginx"
	KindNginxApache   ServerKind = "nginx_apache"
)

const (
	DefaultNginxSnippetDir   = "/etc/nginx/da-wptoolkit"
	DefaultLSWSCtrlBin       = "/usr/local/lsws/bin/lswsctrl"
	DefaultNginxBin          = "/usr/sbin/nginx"
	DefaultOLSReloadDebounce = 2 * time.Second
)

const (
	RuleBlockUploadsPHP     = "block_uploads_php"
	RuleBlockIncludesPHP    = "block_includes_php"
	RuleBlockSensitiveFiles = "block_sensitive_files"
	RuleDisableXMLRPC       = "disable_xmlrpc"
	RuleBlockAuthorEnum     = "block_user_enumeration"
	RuleSecurityHeaders     = "hide_wp_version_headers"
	RuleForceHTTPS          = "force_https"
)

var allWebRuleIDs = []string{
	RulePasswordProtect,
	RuleBlockUploadsPHP,
	RuleBlockIncludesPHP,
	RuleBlockSensitiveFiles,
	RuleDisableXMLRPC,
	RuleBlockAuthorEnum,
	RuleSecurityHeaders,
	RuleForceHTTPS,
}

// CommandRunner executes a privileged web server control command (`lswsctrl reload`, `nginx -t`, `nginx -s reload`).
type CommandRunner func(ctx context.Context, bin string, args ...string) (string, error)

// Adapter translates WordPress security rules across Apache, LiteSpeed, OpenLiteSpeed, and Nginx Standalone.
type Adapter struct {
	OptionsConfPath   string
	NginxSnippetDir   string
	LSWSCtrlBin       string
	NginxBin          string
	OLSReloadDebounce time.Duration
	ExecCommand       CommandRunner

	mu             sync.Mutex
	olsDirty       bool
	olsTimer       *time.Timer
	olsReloadCount int
	olsCommitted   map[string]map[string]bool // instanceID -> committed rules visible to OLS worker after reload
}

// NewAdapter creates a Multi-WebServer Adapter reading CustomBuild's options.conf.
func NewAdapter(optionsConfPath, nginxSnippetDir string) *Adapter {
	if strings.TrimSpace(optionsConfPath) == "" {
		optionsConfPath = daphp.DefaultOptionsConfPath
	}
	if strings.TrimSpace(nginxSnippetDir) == "" {
		nginxSnippetDir = DefaultNginxSnippetDir
	}
	a := &Adapter{
		OptionsConfPath:   optionsConfPath,
		NginxSnippetDir:   nginxSnippetDir,
		LSWSCtrlBin:       DefaultLSWSCtrlBin,
		NginxBin:          DefaultNginxBin,
		OLSReloadDebounce: DefaultOLSReloadDebounce,
		olsCommitted:      make(map[string]map[string]bool),
	}
	a.ExecCommand = a.defaultExecCommand
	return a
}

func (a *Adapter) defaultExecCommand(ctx context.Context, bin string, args ...string) (string, error) {
	if _, err := os.Stat(bin); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s failed: %w (%s)", bin, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// DetectKind reads `webserver=` from DirectAdmin CustomBuild's options.conf.
func (a *Adapter) DetectKind() ServerKind {
	f, err := os.Open(a.OptionsConfPath)
	if err != nil {
		return KindApache
	}
	defer f.Close()

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
		k := strings.TrimSpace(line[:idx])
		v := strings.ToLower(strings.TrimSpace(line[idx+1:]))
		if k == "webserver" {
			switch v {
			case "openlitespeed":
				return KindOpenLiteSpeed
			case "litespeed":
				return KindLiteSpeed
			case "nginx":
				return KindNginx
			case "nginx_apache":
				return KindNginxApache
			default:
				return KindApache
			}
		}
	}
	return KindApache
}

// IsWebRule reports whether ruleID is enforced at the Web Server layer.
func IsWebRule(ruleID string) bool {
	for _, id := range allWebRuleIDs {
		if id == ruleID {
			return true
		}
	}
	return false
}

// IsRuleApplied checks whether a web-layer security rule is active on disk for the target instance.
func (a *Adapter) IsRuleApplied(acct dausers.Account, inst store.InstanceRecord, ruleID string) bool {
	kind := a.DetectKind()
	if kind == KindNginx {
		raw, err := os.ReadFile(a.nginxSnippetPath(inst.Owner, inst.ID))
		if err != nil {
			return false
		}
		return HasMarkerBlock(string(raw), ruleID)
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return false
	}

	if ruleID == RuleBlockUploadsPHP {
		uploadsHT := filepath.Join(inst.DocRoot, "wp-content", "uploads", ".htaccess")
		content, rErr := readGuardedCustomerFile(guard, uploadsHT)
		if rErr != nil {
			return false
		}
		return HasMarkerBlock(content, ruleID)
	}

	rootHT := filepath.Join(inst.DocRoot, ".htaccess")
	content, err := readGuardedCustomerFile(guard, rootHT)
	if err != nil {
		return false
	}
	return HasMarkerBlock(content, ruleID)
}

// ApplyRule enables a single web-layer rule on the target instance.
func (a *Adapter) ApplyRule(ctx context.Context, acct dausers.Account, inst store.InstanceRecord, ruleID string) error {
	return a.SyncRules(ctx, acct, inst, map[string]bool{ruleID: true})
}

// RevertRule disables a single web-layer rule on the target instance.
func (a *Adapter) RevertRule(ctx context.Context, acct dausers.Account, inst store.InstanceRecord, ruleID string) error {
	return a.SyncRules(ctx, acct, inst, map[string]bool{ruleID: false})
}

// SyncRules atomically updates multiple web-layer security rules on an instance, minimizing reloads.
func (a *Adapter) SyncRules(ctx context.Context, acct dausers.Account, inst store.InstanceRecord, updates map[string]bool) error {
	if len(updates) == 0 {
		return nil
	}
	if err := config.ValidateIdentifier(inst.Owner); err != nil {
		return err
	}
	if err := config.ValidateInstanceID(inst.ID); err != nil {
		return err
	}

	kind := a.DetectKind()
	if kind == KindNginx {
		return a.syncNginxRules(ctx, acct, inst, updates)
	}
	return a.syncHTAccessRules(ctx, kind, acct, inst, updates)
}

func (a *Adapter) syncHTAccessRules(_ context.Context, kind ServerKind, acct dausers.Account, inst store.InstanceRecord, updates map[string]bool) error {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return err
	}
	if _, err := guard.VerifyExistingPath(inst.DocRoot); err != nil {
		return err
	}

	anyChanged := false

	// 1. Handle wp-content/uploads/.htaccess for RuleBlockUploadsPHP
	if wantUploads, ok := updates[RuleBlockUploadsPHP]; ok {
		uploadsHT := filepath.Join(inst.DocRoot, "wp-content", "uploads", ".htaccess")
		curUploads, rErr := readGuardedCustomerFile(guard, uploadsHT)
		if rErr != nil {
			return rErr
		}
		var nextUploads string
		var changed bool
		if wantUploads {
			nextUploads, changed = UpsertMarkerBlock(curUploads, RuleBlockUploadsPHP, htaccessUploadsNoPHPBlock(), true)
		} else {
			nextUploads, changed = RemoveMarkerBlock(curUploads, RuleBlockUploadsPHP)
		}
		if changed {
			if err := writeGuardedCustomerFileAtomic(guard, acct, uploadsHT, nextUploads, 0o644); err != nil {
				return err
			}
			anyChanged = true
		}
	}

	// 2. Handle root DocRoot/.htaccess for all rules (including rewrite defense-in-depth for uploads)
	rootHT := filepath.Join(inst.DocRoot, ".htaccess")
	curRoot, err := readGuardedCustomerFile(guard, rootHT)
	if err != nil {
		return err
	}
	nextRoot := curRoot
	rootChanged := false

	// Deterministic rule order
	orderedKeys := make([]string, 0, len(updates))
	for k := range updates {
		if IsWebRule(k) {
			orderedKeys = append(orderedKeys, k)
		}
	}
	sort.Strings(orderedKeys)

	for _, ruleID := range orderedKeys {
		enable := updates[ruleID]
		var changed bool
		if enable {
			var block string
			if ruleID == RulePasswordProtect {
				block = a.buildHTAccessPasswordBlock(acct, inst)
			} else {
				block = buildRootHTAccessBlock(ruleID, inst.SubPath)
			}
			if block != "" {
				nextRoot, changed = UpsertMarkerBlock(nextRoot, ruleID, block, true)
			}
		} else {
			nextRoot, changed = RemoveMarkerBlock(nextRoot, ruleID)
		}
		if changed {
			rootChanged = true
		}
	}

	if rootChanged {
		if err := writeGuardedCustomerFileAtomic(guard, acct, rootHT, nextRoot, 0o644); err != nil {
			return err
		}
		anyChanged = true
	}

	if anyChanged && kind == KindOpenLiteSpeed {
		a.scheduleOLSReload(acct, inst)
	}
	return nil
}

func (a *Adapter) scheduleOLSReload(acct dausers.Account, inst store.InstanceRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Ensure olsCommitted initializes baseline snapshot before pending reload completes
	if _, exists := a.olsCommitted[inst.ID]; !exists {
		a.olsCommitted[inst.ID] = make(map[string]bool)
	}
	a.olsDirty = true
	delay := a.OLSReloadDebounce
	if delay <= 0 {
		delay = 10 * time.Millisecond
	}
	if a.olsTimer != nil {
		a.olsTimer.Stop()
	}
	snapAcct := acct
	snapInst := inst
	a.olsTimer = time.AfterFunc(delay, func() {
		_ = a.flushOLSReloadNow(context.Background(), &snapAcct, &snapInst)
	})
}

// FlushPendingReloads immediately executes any pending debounced OpenLiteSpeed graceful reload.
func (a *Adapter) FlushPendingReloads(ctx context.Context) error {
	return a.flushOLSReloadNow(ctx, nil, nil)
}

// OLSReloadCount returns the number of executed OpenLiteSpeed graceful reloads (for telemetry & TC-07 tests).
func (a *Adapter) OLSReloadCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.olsReloadCount
}

func (a *Adapter) flushOLSReloadNow(ctx context.Context, acct *dausers.Account, inst *store.InstanceRecord) error {
	a.mu.Lock()
	if !a.olsDirty {
		a.mu.Unlock()
		return nil
	}
	if a.olsTimer != nil {
		a.olsTimer.Stop()
		a.olsTimer = nil
	}
	a.olsDirty = false
	runner := a.ExecCommand
	bin := a.LSWSCtrlBin
	a.mu.Unlock()

	if runner != nil {
		if _, err := runner(ctx, bin, "reload"); err != nil {
			a.mu.Lock()
			a.olsDirty = true
			a.mu.Unlock()
			return err
		}
	}

	a.mu.Lock()
	a.olsReloadCount++
	if acct != nil && inst != nil {
		a.olsCommitted[inst.ID] = a.snapshotDiskRules(*acct, *inst)
	} else {
		// Clear stale cache so evaluator reads fresh post-reload disk state
		a.olsCommitted = make(map[string]map[string]bool)
	}
	a.mu.Unlock()
	return nil
}

func (a *Adapter) snapshotDiskRules(acct dausers.Account, inst store.InstanceRecord) map[string]bool {
	m := make(map[string]bool, len(allWebRuleIDs))
	for _, r := range allWebRuleIDs {
		if a.IsRuleApplied(acct, inst, r) {
			m[r] = true
		}
	}
	return m
}

func (a *Adapter) nginxSnippetPath(owner, instanceID string) string {
	return filepath.Join(a.NginxSnippetDir, owner, instanceID+".conf")
}

func (a *Adapter) syncNginxRules(ctx context.Context, acct dausers.Account, inst store.InstanceRecord, updates map[string]bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	snippetPath := a.nginxSnippetPath(inst.Owner, inst.ID)
	ownerDir := filepath.Dir(snippetPath)
	if err := os.MkdirAll(ownerDir, 0o750); err != nil {
		return fmt.Errorf("create nginx snippet dir: %w", err)
	}

	prevBytes, prevErr := os.ReadFile(snippetPath)
	hadPrev := prevErr == nil
	curContent := ""
	if hadPrev {
		curContent = strings.ReplaceAll(string(prevBytes), "\r\n", "\n")
	}

	activeRules := make(map[string]bool, len(allWebRuleIDs))
	for _, ruleID := range allWebRuleIDs {
		if HasMarkerBlock(curContent, ruleID) {
			activeRules[ruleID] = true
		}
	}
	for ruleID, want := range updates {
		if IsWebRule(ruleID) {
			activeRules[ruleID] = want
		}
	}

	rendered := a.renderNginxSnippet(acct, inst, activeRules)
	if rendered == curContent {
		return nil
	}

	if rendered == "" {
		_ = os.Remove(snippetPath)
	} else {
		tmpPath := snippetPath + ".tmp"
		if err := os.WriteFile(tmpPath, []byte(rendered), 0o640); err != nil {
			return err
		}
		if err := os.Rename(tmpPath, snippetPath); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	}

	// Validate configuration with `nginx -t` BEFORE reloading; auto-rollback on syntax/config failure!
	if a.ExecCommand != nil {
		if _, testErr := a.ExecCommand(ctx, a.NginxBin, "-t"); testErr != nil {
			if hadPrev {
				_ = os.WriteFile(snippetPath, prevBytes, 0o640)
			} else {
				_ = os.Remove(snippetPath)
			}
			return fmt.Errorf("nginx configuration test failed (rolled back safely): %w", testErr)
		}
		if _, reloadErr := a.ExecCommand(ctx, a.NginxBin, "-s", "reload"); reloadErr != nil {
			if hadPrev {
				_ = os.WriteFile(snippetPath, prevBytes, 0o640)
			} else {
				_ = os.Remove(snippetPath)
			}
			return fmt.Errorf("nginx reload failed (rolled back safely): %w", reloadErr)
		}
	}
	return nil
}

// RemoveInstanceConfigs removes Nginx snippets for an uninstalled or destroyed WordPress instance.
func (a *Adapter) RemoveInstanceConfigs(ctx context.Context, owner, instanceID string) error {
	if err := config.ValidateIdentifier(owner); err != nil {
		return err
	}
	if err := config.ValidateInstanceID(instanceID); err != nil {
		return err
	}
	p := a.nginxSnippetPath(owner, instanceID)
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if a.DetectKind() == KindNginx && a.ExecCommand != nil {
		if _, err := a.ExecCommand(ctx, a.NginxBin, "-t"); err == nil {
			_, _ = a.ExecCommand(ctx, a.NginxBin, "-s", "reload")
		}
	}
	return nil
}

// RemoveOwnerConfigs purges all Nginx snippets belonging to a deleted DirectAdmin user (user_destroy_post.sh).
func (a *Adapter) RemoveOwnerConfigs(ctx context.Context, owner string) error {
	if err := config.ValidateIdentifier(owner); err != nil {
		return err
	}
	ownerDir := filepath.Join(a.NginxSnippetDir, owner)
	if _, err := os.Stat(ownerDir); err != nil {
		return nil
	}
	if err := os.RemoveAll(ownerDir); err != nil {
		return err
	}
	if a.DetectKind() == KindNginx && a.ExecCommand != nil {
		if _, err := a.ExecCommand(ctx, a.NginxBin, "-t"); err == nil {
			_, _ = a.ExecCommand(ctx, a.NginxBin, "-s", "reload")
		}
	}
	return nil
}

func htaccessUploadsNoPHPBlock() string {
	return strings.Join([]string{
		`<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pl|py|jsp|asp|sh|cgi)$">`,
		`    <IfModule mod_authz_core.c>`,
		`        Require all denied`,
		`    </IfModule>`,
		`    <IfModule !mod_authz_core.c>`,
		`        Order allow,deny`,
		`        Deny from all`,
		`    </IfModule>`,
		`</FilesMatch>`,
	}, "\n")
}

func buildRootHTAccessBlock(ruleID, subPath string) string {
	basePrefix := strings.Trim(subPath, "/")
	rewritePrefix := ""
	if basePrefix != "" {
		rewritePrefix = regexp.QuoteMeta(basePrefix) + "/"
	}
	_ = rewritePrefix

	switch ruleID {
	case RuleBlockUploadsPHP:
		return strings.Join([]string{
			`<IfModule mod_rewrite.c>`,
			`RewriteEngine On`,
			`RewriteRule ^wp-content/uploads/.*\.(?:php[0-9]?|phtml|phar|pl|py|cgi|sh)$ - [F,L,NC]`,
			`</IfModule>`,
		}, "\n")

	case RuleBlockIncludesPHP:
		return strings.Join([]string{
			`<IfModule mod_rewrite.c>`,
			`RewriteEngine On`,
			`RewriteRule ^wp-admin/includes/ - [F,L]`,
			`RewriteRule !^wp-includes/ - [S=3]`,
			`RewriteRule ^wp-includes/(?:ms-files|js/tinymce/wp-tinymce)\.php$ - [S=2]`,
			`RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]`,
			`RewriteRule ^wp-includes/theme-compat/ - [F,L]`,
			`</IfModule>`,
		}, "\n")

	case RuleBlockSensitiveFiles:
		return strings.Join([]string{
			`<FilesMatch "^(?:wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt|debug\.log|error_log|\.env)$">`,
			`    <IfModule mod_authz_core.c>`,
			`        Require all denied`,
			`    </IfModule>`,
			`    <IfModule !mod_authz_core.c>`,
			`        Order allow,deny`,
			`        Deny from all`,
			`    </IfModule>`,
			`</FilesMatch>`,
			`<FilesMatch "\.(?i:sql|sql\.gz|bak|swp|old)$">`,
			`    <IfModule mod_authz_core.c>`,
			`        Require all denied`,
			`    </IfModule>`,
			`    <IfModule !mod_authz_core.c>`,
			`        Order allow,deny`,
			`        Deny from all`,
			`    </IfModule>`,
			`</FilesMatch>`,
			`<IfModule mod_rewrite.c>`,
			`RewriteEngine On`,
			`RewriteRule ^(?:.*/)?\.git/ - [F,L]`,
			`</IfModule>`,
		}, "\n")

	case RuleDisableXMLRPC:
		return strings.Join([]string{
			`<Files "xmlrpc.php">`,
			`    <IfModule mod_authz_core.c>`,
			`        Require all denied`,
			`    </IfModule>`,
			`    <IfModule !mod_authz_core.c>`,
			`        Order allow,deny`,
			`        Deny from all`,
			`    </IfModule>`,
			`</Files>`,
		}, "\n")

	case RuleBlockAuthorEnum:
		return strings.Join([]string{
			`<IfModule mod_rewrite.c>`,
			`RewriteEngine On`,
			`RewriteCond %{REQUEST_URI} !^/wp-admin [NC]`,
			`RewriteCond %{QUERY_STRING} (?:^|&)author=[0-9]+ [NC]`,
			`RewriteRule .* - [F,L]`,
			`</IfModule>`,
		}, "\n")

	case RuleSecurityHeaders:
		return strings.Join([]string{
			`<IfModule mod_headers.c>`,
			`    Header always set X-Content-Type-Options "nosniff"`,
			`    Header always set X-Frame-Options "SAMEORIGIN"`,
			`    Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
			`</IfModule>`,
		}, "\n")

	case RuleForceHTTPS:
		return strings.Join([]string{
			`<IfModule mod_rewrite.c>`,
			`RewriteEngine On`,
			`RewriteCond %{HTTPS} !=on`,
			`RewriteCond %{HTTP:X-Forwarded-Proto} !https [NC]`,
			`RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]`,
			`</IfModule>`,
		}, "\n")
	}
	return ""
}

func (a *Adapter) renderNginxSnippet(acct dausers.Account, inst store.InstanceRecord, active map[string]bool) string {
	prefix := strings.TrimSuffix(inst.SubPath, "/")
	escapedPrefix := regexp.QuoteMeta(prefix)

	var sections []string
	for _, ruleID := range allWebRuleIDs {
		if !active[ruleID] {
			continue
		}
		var body string
		switch ruleID {
		case RulePasswordProtect:
			body = a.buildNginxPasswordBlock(acct, inst)
		case RuleBlockUploadsPHP:
			body = fmt.Sprintf(
				"location ~* ^%s/wp-content/uploads/.*\\.(?:php[0-9]?|phtml|phar|pl|py|jsp|asp|sh|cgi)$ {\n    deny all;\n}",
				escapedPrefix,
			)
		case RuleBlockIncludesPHP:
			body = fmt.Sprintf(
				"location ~* ^%s/wp-includes/(?!ms-files\\.php$|js/tinymce/wp-tinymce\\.php$).*\\.php$ {\n    deny all;\n}\nlocation ~* ^%s/wp-admin/includes/.*\\.php$ {\n    deny all;\n}",
				escapedPrefix,
				escapedPrefix,
			)
		case RuleBlockSensitiveFiles:
			body = fmt.Sprintf(
				"location ~* ^%s/(?:wp-config\\.php|wp-config-sample\\.php|readme\\.html|license\\.txt|debug\\.log|error_log|\\.env|\\.git/.*)$ {\n    deny all;\n}\nlocation ~* ^%s/.*\\.(?:sql|sql\\.gz|bak|swp|old)$ {\n    deny all;\n}",
				escapedPrefix,
				escapedPrefix,
			)
		case RuleDisableXMLRPC:
			xmlPath := prefix + "/xmlrpc.php"
			body = fmt.Sprintf("location = %s {\n    deny all;\n}", xmlPath)
		case RuleBlockAuthorEnum:
			body = "if ($args ~* \"(?:^|&)author=[0-9]+\") {\n    return 403;\n}"
		case RuleSecurityHeaders:
			body = "add_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
		case RuleForceHTTPS:
			body = "if ($scheme = http) {\n    return 301 https://$host$request_uri;\n}"
		}
		if body != "" {
			sections = append(sections, markerStart(ruleID)+"\n"+body+"\n"+markerEnd(ruleID))
		}
	}
	if len(sections) == 0 {
		return ""
	}
	header := fmt.Sprintf("# Managed by DA-WordPressToolkits for instance %s (%s%s)\n", inst.ID, inst.Domain, inst.SubPath)
	return header + strings.Join(sections, "\n\n") + "\n"
}

var (
	reUploadsExec    = regexp.MustCompile(`(?i)^/wp-content/uploads/.*\.(?:php[0-9]?|phtml|phar|pl|py|jsp|asp|sh|cgi)$`)
	reIncludesExec   = regexp.MustCompile(`(?i)^/wp-includes/.*\.php$`)
	reAdminInclExec  = regexp.MustCompile(`(?i)^/wp-admin/includes/.*\.php$`)
	reSensitiveNames = regexp.MustCompile(`(?i)^/(?:wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt|debug\.log|error_log|\.env|\.git/.*)$`)
	reBackupDumps    = regexp.MustCompile(`(?i)^/.*\.(?:sql|sql\.gz|bak|swp|old)$`)
	reAuthorQuery    = regexp.MustCompile(`(?i)(?:^|&)author=[0-9]+`)
)

// EvaluateHTTPRequest evaluates active web-server rules (including OpenLiteSpeed reload-gating semantics)
// against an HTTP request so end-to-end integration tests (TC-07) can verify real 403/301/header behavior.
func (a *Adapter) EvaluateHTTPRequest(acct dausers.Account, inst store.InstanceRecord, w http.ResponseWriter, r *http.Request) bool {
	kind := a.DetectKind()

	ruleActive := func(ruleID string) bool {
		if kind == KindOpenLiteSpeed {
			a.mu.Lock()
			dirty := a.olsDirty
			committed, tracked := a.olsCommitted[inst.ID]
			a.mu.Unlock()
			if dirty && tracked {
				return committed[ruleID]
			}
		}
		return a.IsRuleApplied(acct, inst, ruleID)
	}

	reqPath := r.URL.Path
	prefix := strings.TrimSuffix(inst.SubPath, "/")
	relPath := reqPath
	if prefix != "" {
		if !strings.HasPrefix(reqPath, prefix+"/") && reqPath != prefix {
			return false
		}
		relPath = strings.TrimPrefix(reqPath, prefix)
		if relPath == "" {
			relPath = "/"
		}
	}

	if ruleActive(RuleSecurityHeaders) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	}

	isHTTPS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	if ruleActive(RuleForceHTTPS) && !isHTTPS {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		return true
	}

	if ruleActive(RulePasswordProtect) {
		u, p, ok := r.BasicAuth()
		if !ok || !a.VerifyHTTPBasicAuth(acct, inst, u, p) {
			st := a.GetPasswordProtectionStatus(acct, inst)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, st.Realm))
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("401 Unauthorized"))
			return true
		}
	}

	if ruleActive(RuleBlockUploadsPHP) && reUploadsExec.MatchString(relPath) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("403 Forbidden"))
		return true
	}

	if ruleActive(RuleBlockIncludesPHP) {
		allowedIncludes := strings.EqualFold(relPath, "/wp-includes/ms-files.php") ||
			strings.EqualFold(relPath, "/wp-includes/js/tinymce/wp-tinymce.php")
		if (!allowedIncludes && reIncludesExec.MatchString(relPath)) || reAdminInclExec.MatchString(relPath) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("403 Forbidden"))
			return true
		}
	}

	if ruleActive(RuleBlockSensitiveFiles) && (reSensitiveNames.MatchString(relPath) || reBackupDumps.MatchString(relPath)) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("403 Forbidden"))
		return true
	}

	if ruleActive(RuleDisableXMLRPC) && strings.EqualFold(relPath, "/xmlrpc.php") {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("403 Forbidden"))
		return true
	}

	if ruleActive(RuleBlockAuthorEnum) && !strings.HasPrefix(strings.ToLower(relPath), "/wp-admin") && reAuthorQuery.MatchString(r.URL.RawQuery) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("403 Forbidden"))
		return true
	}

	return false
}
