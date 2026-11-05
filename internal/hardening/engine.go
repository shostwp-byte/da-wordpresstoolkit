package hardening

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

const (
	RuleBlockUploadsPHP      = "block_uploads_php"
	RuleBlockIncludesPHP     = "block_includes_php"
	RuleLockPermissions      = "lock_permissions"
	RuleDisallowFileEdit     = "disallow_file_edit"
	RuleBlockSensitiveFiles  = "block_sensitive_files"
	RuleDisableXMLRPC        = "disable_xmlrpc"
	RuleRefreshSecuritySalts = "refresh_security_salts"
	RuleBlockUserEnumeration = "block_user_enumeration"
	RuleRenameDefaultAdmin   = "rename_default_admin"
	RuleChangeDBPrefix       = "change_db_prefix"
	RuleHideWPVersionHeaders = "hide_wp_version_headers"
	RuleForceHTTPS           = "force_https"

	PresetCritical    = "critical"
	PresetRecommended = "recommended"
	PresetAll         = "all"

	securityTweaksMUFile = "da-wptk-security-tweaks.php"
)

// RuleSpec describes one of the 12 canonical WordPress security hardening rules.
type RuleSpec struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // critical | recommended
	Title       string `json:"title"`
	Description string `json:"description"`
	Reversible  bool   `json:"reversible"`
}

// RuleStatus reports the live compliance state of a single hardening rule on an instance.
type RuleStatus struct {
	RuleSpec
	Applied bool   `json:"applied"`
	Detail  string `json:"detail,omitempty"`
}

// Report summarizes all 12 hardening rules and score for a WordPress instance.
type Report struct {
	InstanceID string       `json:"instance_id"`
	Domain     string       `json:"domain"`
	SubPath    string       `json:"sub_path,omitempty"`
	WebServer  string       `json:"web_server"`
	Score      int          `json:"score"`
	Total      int          `json:"total"`
	Rules      []RuleStatus `json:"rules"`
}

// ApplyRequest defines a single-rule, multi-rule, or preset hardening operation.
type ApplyRequest struct {
	Preset         string   `json:"preset,omitempty"` // critical | recommended | all
	RuleIDs        []string `json:"rule_ids,omitempty"`
	NewAdminUser   string   `json:"new_admin_user,omitempty"`
	NewTablePrefix string   `json:"new_table_prefix,omitempty"`
}

var catalog = []RuleSpec{
	{
		ID:          RuleBlockUploadsPHP,
		Severity:    "critical",
		Title:       "Chặn thực thi PHP trong wp-content/uploads",
		Description: "Ngăn chặn mã độc giả dạng ảnh/tài liệu thực thi file .php/.phtml/.phar trong thư mục tải lên.",
		Reversible:  true,
	},
	{
		ID:          RuleBlockIncludesPHP,
		Severity:    "critical",
		Title:       "Chặn thực thi PHP trực tiếp trong wp-includes",
		Description: "Khóa truy cập HTTP trực tiếp vào các tệp PHP nội bộ trong wp-includes và wp-admin/includes.",
		Reversible:  true,
	},
	{
		ID:          RuleLockPermissions,
		Severity:    "critical",
		Title:       "Khóa phân quyền wp-config.php (0600) & chuẩn hóa 0755/0644",
		Description: "Bảo vệ tệp cấu hình cơ sở dữ liệu ở mức 0600 và loại bỏ quyền ghi công khai (0777) trên thư mục.",
		Reversible:  true,
	},
	{
		ID:          RuleDisallowFileEdit,
		Severity:    "critical",
		Title:       "Tắt trình chỉnh sửa mã nguồn trong wp-admin (DISALLOW_FILE_EDIT)",
		Description: "Ngăn tài khoản quản trị bị lộ mật khẩu chèn trực tiếp webshell vào giao diện hoặc plugin.",
		Reversible:  true,
	},
	{
		ID:          RuleBlockSensitiveFiles,
		Severity:    "critical",
		Title:       "Chặn truy cập công khai tệp nhạy cảm & bản sao lưu (.sql, .env, debug.log)",
		Description: "Khóa truy cập HTTP tới wp-config-sample.php, readme.html, debug.log, .env, .git và các file .sql.",
		Reversible:  true,
	},
	{
		ID:          RuleDisableXMLRPC,
		Severity:    "critical",
		Title:       "Vô hiệu hóa cổng xmlrpc.php",
		Description: "Chặn tấn công dò mật khẩu khuếch đại (system.multicall) và DDoS Pingback qua xmlrpc.php.",
		Reversible:  true,
	},
	{
		ID:          RuleRefreshSecuritySalts,
		Severity:    "recommended",
		Title:       "Làm mới bộ khóa xác thực Security Keys & Salts",
		Description: "Sinh mới 8 hằng số mã hóa phiên đăng nhập độ dài 64 ký tự ngẫu nhiên trong wp-config.php.",
		Reversible:  false,
	},
	{
		ID:          RuleBlockUserEnumeration,
		Severity:    "recommended",
		Title:       "Chặn dò quét danh sách tài khoản Quản trị (User Enumeration)",
		Description: "Chặn truy vấn ?author=N và ẩn danh sách /wp-json/wp/v2/users đối với khách chưa đăng nhập.",
		Reversible:  true,
	},
	{
		ID:          RuleRenameDefaultAdmin,
		Severity:    "recommended",
		Title:       "Đổi tên đăng nhập quản trị mặc định 'admin'",
		Description: "Đảm bảo không tồn tại tài khoản quản trị mang username mặc định dễ bị brute-force.",
		Reversible:  false,
	},
	{
		ID:          RuleChangeDBPrefix,
		Severity:    "recommended",
		Title:       "Đổi tiền tố bảng cơ sở dữ liệu mặc định 'wp_'",
		Description: "Sử dụng tiền tố bảng ngẫu nhiên (vd: wp_9f3a_) để vô hiệu hóa các khai thác SQL Injection định sẵn.",
		Reversible:  false,
	},
	{
		ID:          RuleHideWPVersionHeaders,
		Severity:    "recommended",
		Title:       "Ẩn phiên bản WordPress & bật HTTP Security Headers",
		Description: "Ẩn thẻ wp_generator và gắn X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN.",
		Reversible:  true,
	},
	{
		ID:          RuleForceHTTPS,
		Severity:    "recommended",
		Title:       "Ép buộc kết nối mã hóa HTTPS (FORCE_SSL_ADMIN & Redirect 301)",
		Description: "Tự động chuyển hướng truy cập HTTP sang HTTPS và mã hóa toàn bộ phiên quản trị.",
		Reversible:  true,
	},
}

var reValidPrefix = regexp.MustCompile(`^[a-z0-9]{2,8}_[a-z0-9]{2,10}_$`)

type persistedHardeningState struct {
	PermissionsLocked map[string]bool `json:"permissions_locked"`
}

// Engine evaluates, applies, and reverts the 12 WordPress security hardening rules across all 4 web servers.
type Engine struct {
	StateDir              string
	WebServer             *webserver.Adapter
	Domains               *dadomains.Resolver
	WPCLI                 *wpcli.Runner
	Store                 *store.Store
	WithShieldSuppression func(acct dausers.Account, inst store.InstanceRecord, fn func() error) error

	mu          sync.Mutex
	permTracked map[string]bool
}

// NewEngine creates a 12-rule Security Hardening Engine.
func NewEngine(
	stateDir string,
	ws *webserver.Adapter,
	domains *dadomains.Resolver,
	wp *wpcli.Runner,
	st *store.Store,
) *Engine {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = store.DefaultStateDir
	}
	e := &Engine{
		StateDir:    stateDir,
		WebServer:   ws,
		Domains:     domains,
		WPCLI:       wp,
		Store:       st,
		permTracked: make(map[string]bool),
	}
	e.loadState()
	return e
}

// Catalog returns the static definition list of all 12 hardening rules.
func Catalog() []RuleSpec {
	out := make([]RuleSpec, len(catalog))
	copy(out, catalog)
	return out
}

func (e *Engine) statePath() string {
	return filepath.Join(e.StateDir, "hardening_state.json")
}

func (e *Engine) loadState() {
	raw, err := os.ReadFile(e.statePath())
	if err != nil {
		return
	}
	var st persistedHardeningState
	if json.Unmarshal(raw, &st) == nil && st.PermissionsLocked != nil {
		e.permTracked = st.PermissionsLocked
	}
}

func (e *Engine) saveStateLocked() {
	_ = os.MkdirAll(e.StateDir, 0o700)
	payload, err := json.MarshalIndent(persistedHardeningState{PermissionsLocked: e.permTracked}, "", "  ")
	if err != nil {
		return
	}
	tmp := e.statePath() + ".tmp"
	if os.WriteFile(tmp, append(payload, '\n'), 0o600) == nil {
		_ = os.Rename(tmp, e.statePath())
	}
}

// Check evaluates all 12 security hardening rules on an instance and updates its SecurityScore in Store.
func (e *Engine) Check(acct dausers.Account, instanceID string) (Report, error) {
	inst, err := e.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return Report{}, err
	}
	return e.evaluateInstance(acct, inst, true)
}

func (e *Engine) evaluateInstance(acct dausers.Account, inst store.InstanceRecord, persistScore bool) (Report, error) {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return Report{}, err
	}

	wpConfigRaw, _ := guard.ReadRegularFileSafe(filepath.Join(inst.DocRoot, "wp-config.php"), 256*1024)
	wpConfigStr := string(wpConfigRaw)

	muRaw, _ := guard.ReadRegularFileSafe(filepath.Join(inst.DocRoot, "wp-content", "mu-plugins", securityTweaksMUFile), 64*1024)
	muStr := string(muRaw)

	wsKind := string(webserver.KindApache)
	if e.WebServer != nil {
		wsKind = string(e.WebServer.DetectKind())
	}

	rep := Report{
		InstanceID: inst.ID,
		Domain:     inst.Domain,
		SubPath:    inst.SubPath,
		WebServer:  wsKind,
		Total:      len(catalog),
		Rules:      make([]RuleStatus, 0, len(catalog)),
	}

	score := 0
	for _, spec := range catalog {
		applied, detail := e.checkSingleRule(spec.ID, acct, inst, wpConfigStr, muStr)
		if applied {
			score++
		}
		rep.Rules = append(rep.Rules, RuleStatus{
			RuleSpec: spec,
			Applied:  applied,
			Detail:   detail,
		})
	}
	rep.Score = score

	if persistScore && (inst.SecurityScore != score || inst.SecurityTotal != len(catalog)) {
		inst.SecurityScore = score
		inst.SecurityTotal = len(catalog)
		_, _ = e.Store.UpsertInstance(inst)
	}
	return rep, nil
}

func (e *Engine) checkSingleRule(
	ruleID string,
	acct dausers.Account,
	inst store.InstanceRecord,
	wpConfigStr string,
	muStr string,
) (bool, string) {
	switch ruleID {
	case RuleBlockUploadsPHP, RuleBlockIncludesPHP, RuleBlockSensitiveFiles, RuleDisableXMLRPC:
		if e.WebServer != nil && e.WebServer.IsRuleApplied(acct, inst, ruleID) {
			return true, "Đang bảo vệ qua " + string(e.WebServer.DetectKind())
		}
		return false, "Chưa bật quy tắc chặn mức Web Server"

	case RuleLockPermissions:
		cfgPath := filepath.Join(inst.DocRoot, "wp-config.php")
		st, err := os.Lstat(cfgPath)
		if err != nil {
			return false, "Không tìm thấy wp-config.php"
		}
		if runtime.GOOS == "linux" {
			perm := st.Mode().Perm()
			if perm == 0o600 || perm == 0o400 {
				return true, fmt.Sprintf("wp-config.php đang khóa ở quyền %04o", perm)
			}
			return false, fmt.Sprintf("wp-config.php đang ở quyền %04o (khuyến nghị 0600)", perm)
		}
		e.mu.Lock()
		locked := e.permTracked[inst.ID]
		e.mu.Unlock()
		if locked {
			return true, "wp-config.php đang khóa ở quyền 0600"
		}
		return false, "Chưa chuẩn hóa quyền 0600 cho wp-config.php"

	case RuleDisallowFileEdit:
		if v, ok := GetDefinedBool(wpConfigStr, "DISALLOW_FILE_EDIT"); ok && v {
			return true, "DISALLOW_FILE_EDIT = true"
		}
		return false, "Trình sửa code Theme/Plugin trong wp-admin vẫn đang mở"

	case RuleRefreshSecuritySalts:
		if HasRefreshedSalts(wpConfigStr) {
			return true, "8 khóa xác thực Security Salts đạt chuẩn độ mạnh"
		}
		return false, "Khóa xác thực mặc định hoặc chưa được làm mới"

	case RuleBlockUserEnumeration:
		webOK := e.WebServer != nil && e.WebServer.IsRuleApplied(acct, inst, RuleBlockUserEnumeration)
		muOK := strings.Contains(muStr, "DA_WPTK_BLOCK_REST_USERS")
		if webOK && muOK {
			return true, "Đã chặn cả ?author=N và REST /wp/v2/users"
		}
		return false, "Chưa chặn dò quét danh sách quản trị viên"

	case RuleRenameDefaultAdmin:
		adminName := strings.TrimSpace(inst.AdminUser)
		if adminName != "" && !strings.EqualFold(adminName, "admin") {
			return true, "Tài khoản quản trị hiện tại: " + adminName
		}
		return false, "Đang sử dụng hoặc chưa xác minh đổi khỏi tên 'admin'"

	case RuleChangeDBPrefix:
		pfx := strings.TrimSpace(inst.TablePrefix)
		if pfx != "" && !strings.EqualFold(pfx, "wp_") {
			return true, "Tiền tố bảng hiện tại: " + pfx
		}
		return false, "Đang dùng tiền tố mặc định 'wp_'"

	case RuleHideWPVersionHeaders:
		webOK := e.WebServer != nil && e.WebServer.IsRuleApplied(acct, inst, RuleHideWPVersionHeaders)
		muOK := strings.Contains(muStr, "DA_WPTK_HIDE_WP_GENERATOR")
		if webOK && muOK {
			return true, "Đã ẩn wp_generator và bật X-Content-Type-Options / X-Frame-Options"
		}
		return false, "Chưa bật ẩn phiên bản & HTTP Security Headers"

	case RuleForceHTTPS:
		webOK := e.WebServer != nil && e.WebServer.IsRuleApplied(acct, inst, RuleForceHTTPS)
		sslCfg, ok := GetDefinedBool(wpConfigStr, "FORCE_SSL_ADMIN")
		if webOK && ok && sslCfg {
			return true, "Redirect 301 HTTPS + FORCE_SSL_ADMIN đang bật"
		}
		return false, "Chưa ép buộc HTTPS toàn trang"
	}
	return false, ""
}

// ExpandPreset maps a preset name ("critical", "recommended", "all") to canonical rule IDs.
func ExpandPreset(preset string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(preset)) {
	case PresetCritical:
		return []string{
			RuleBlockUploadsPHP,
			RuleBlockIncludesPHP,
			RuleLockPermissions,
			RuleDisallowFileEdit,
			RuleBlockSensitiveFiles,
			RuleDisableXMLRPC,
		}, nil
	case PresetRecommended:
		// Applies all 10 zero-downtime rules automatically (leaves DB/login renames explicit unless already compliant).
		return []string{
			RuleBlockUploadsPHP,
			RuleBlockIncludesPHP,
			RuleLockPermissions,
			RuleDisallowFileEdit,
			RuleBlockSensitiveFiles,
			RuleDisableXMLRPC,
			RuleRefreshSecuritySalts,
			RuleBlockUserEnumeration,
			RuleHideWPVersionHeaders,
			RuleForceHTTPS,
		}, nil
	case PresetAll:
		out := make([]string, 0, len(catalog))
		for _, spec := range catalog {
			out = append(out, spec.ID)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown hardening preset %q (use critical, recommended, or all)", preset)
	}
}

// Apply enables the requested security hardening rules or preset on a WordPress instance.
func (e *Engine) Apply(ctx context.Context, acct dausers.Account, instanceID string, req ApplyRequest) (Report, error) {
	inst, err := e.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return Report{}, err
	}

	targetRules := make([]string, 0, len(catalog))
	if strings.TrimSpace(req.Preset) != "" {
		expanded, pErr := ExpandPreset(req.Preset)
		if pErr != nil {
			return Report{}, pErr
		}
		targetRules = append(targetRules, expanded...)
	}
	for _, r := range req.RuleIDs {
		trimmed := strings.TrimSpace(strings.ToLower(r))
		if trimmed != "" {
			targetRules = append(targetRules, trimmed)
		}
	}
	if len(targetRules) == 0 {
		return Report{}, errors.New("specify either preset or rule_ids to apply")
	}

	validSet := make(map[string]bool, len(targetRules))
	for _, r := range targetRules {
		if !isKnownRule(r) {
			return Report{}, fmt.Errorf("unknown security hardening rule %q", r)
		}
		validSet[r] = true
	}

	runMutation := func() error {
		return e.applyValidatedSet(ctx, acct, &inst, validSet, req)
	}

	if e.WithShieldSuppression != nil {
		if err := e.WithShieldSuppression(acct, inst, runMutation); err != nil {
			return Report{}, err
		}
	} else {
		if err := runMutation(); err != nil {
			return Report{}, err
		}
	}

	// Reload fresh instance state before computing report
	latestInst, gErr := e.Store.GetInstance(inst.ID)
	if gErr == nil {
		inst = latestInst
	}
	return e.evaluateInstance(acct, inst, true)
}

func (e *Engine) applyValidatedSet(
	ctx context.Context,
	acct dausers.Account,
	inst *store.InstanceRecord,
	want map[string]bool,
	req ApplyRequest,
) error {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return err
	}

	// 1. Batch Web Server rules in a single SyncRules transaction
	webUpdates := make(map[string]bool)
	for r := range want {
		if webserver.IsWebRule(r) {
			webUpdates[r] = true
		}
	}
	if len(webUpdates) > 0 && e.WebServer != nil {
		if err := e.WebServer.SyncRules(ctx, acct, *inst, webUpdates); err != nil {
			return err
		}
	}

	// 2. Apply wp-config.php mutations atomically
	wpCfgPath := filepath.Join(verifiedDocRoot, "wp-config.php")
	rawCfg, cfgErr := guard.ReadRegularFileSafe(wpCfgPath, 256*1024)
	if cfgErr != nil && (want[RuleDisallowFileEdit] || want[RuleRefreshSecuritySalts] || want[RuleForceHTTPS] || want[RuleChangeDBPrefix]) {
		return fmt.Errorf("read wp-config.php: %w", cfgErr)
	}
	cfgStr := string(rawCfg)
	cfgChanged := false

	if want[RuleDisallowFileEdit] {
		next, ch := SetDefinedBool(cfgStr, "DISALLOW_FILE_EDIT", true)
		if ch {
			cfgStr = next
			cfgChanged = true
		}
	}
	if want[RuleRefreshSecuritySalts] {
		next, sErr := RegenerateSalts(cfgStr)
		if sErr != nil {
			return sErr
		}
		cfgStr = next
		cfgChanged = true
	}
	if want[RuleForceHTTPS] {
		next, ch := SetDefinedBool(cfgStr, "FORCE_SSL_ADMIN", true)
		if ch {
			cfgStr = next
			cfgChanged = true
		}
		inst.SSLActive = true
		if strings.HasPrefix(inst.SiteURL, "http://") {
			inst.SiteURL = "https://" + strings.TrimPrefix(inst.SiteURL, "http://")
		}
	}

	// 3. Optional DB Prefix migration (Rule 10)
	if want[RuleChangeDBPrefix] && (strings.EqualFold(inst.TablePrefix, "wp_") || inst.TablePrefix == "" || req.NewTablePrefix != "") {
		newPfx := strings.ToLower(strings.TrimSpace(req.NewTablePrefix))
		if newPfx == "" {
			var b [2]byte
			_, _ = rand.Read(b[:])
			newPfx = "wp_" + hex.EncodeToString(b[:]) + "_"
		}
		if !reValidPrefix.MatchString(newPfx) || newPfx == "wp_" {
			return fmt.Errorf("invalid new_table_prefix %q (expected format like wp_9f3a_)", newPfx)
		}
		oldPfx := inst.TablePrefix
		if oldPfx == "" {
			oldPfx = "wp_"
		}
		if e.WPCLI != nil && oldPfx != newPfx {
			phpSel := e.resolvePHP(acct, *inst)
			phpScript := fmt.Sprintf(
				`global $wpdb; $old=%q; $new=%q; `+
					`$tables=$wpdb->get_col($wpdb->prepare("SHOW TABLES LIKE %%s", $wpdb->esc_like($old)."%%")); `+
					`foreach ($tables as $t) { $suffix=substr($t, strlen($old)); $wpdb->query("RENAME TABLE `+"`"+`{$t}`+"`"+` TO `+"`"+`{$new}{$suffix}`+"`"+`"); } `+
					`$wpdb->query($wpdb->prepare("UPDATE `+"`"+`{$new}options`+"`"+` SET option_name=%%s WHERE option_name=%%s", $new."user_roles", $old."user_roles")); `+
					`$wpdb->query($wpdb->prepare("UPDATE `+"`"+`{$new}usermeta`+"`"+` SET meta_key=CONCAT(%%s, SUBSTRING(meta_key, %d)) WHERE meta_key LIKE %%s", $new, $wpdb->esc_like($old)."%%"));`,
				oldPfx,
				newPfx,
				len(oldPfx)+1,
			)
			if _, wErr := e.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedDocRoot,
				PHP:         phpSel,
				Args:        []string{"eval", phpScript},
				SkipPlugins: true,
				SkipThemes:  true,
			}); wErr != nil {
				return fmt.Errorf("migrate database table prefix: %w", wErr)
			}
		}
		next, ch := SetTablePrefix(cfgStr, newPfx)
		if ch {
			cfgStr = next
			cfgChanged = true
		}
		inst.TablePrefix = newPfx
	}

	if cfgChanged {
		if err := writeCustomerFileAtomic(guard, acct, wpCfgPath, cfgStr, 0o600); err != nil {
			return err
		}
	}

	// 4. Optional Default Admin Username migration (Rule 9)
	if want[RuleRenameDefaultAdmin] && (strings.EqualFold(inst.AdminUser, "admin") || inst.AdminUser == "" || req.NewAdminUser != "") {
		newAdmin := strings.TrimSpace(req.NewAdminUser)
		if newAdmin == "" {
			var b [2]byte
			_, _ = rand.Read(b[:])
			newAdmin = "wpadmin_" + hex.EncodeToString(b[:])
		}
		if err := config.ValidateIdentifier(newAdmin); err != nil {
			return fmt.Errorf("invalid new_admin_user: %w", err)
		}
		switch strings.ToLower(newAdmin) {
		case "admin", "administrator", "root", "test", "user", "wordpress":
			return fmt.Errorf("new_admin_user %q is considered weak; choose a unique username", newAdmin)
		}
		if e.WPCLI != nil {
			phpSel := e.resolvePHP(acct, *inst)
			phpScript := fmt.Sprintf(
				`global $wpdb; $wpdb->update($wpdb->users, array('user_login' => %q, 'user_nicename' => sanitize_title(%q)), array('user_login' => 'admin')); wp_cache_flush();`,
				newAdmin,
				newAdmin,
			)
			if _, wErr := e.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedDocRoot,
				PHP:         phpSel,
				Args:        []string{"eval", phpScript},
				SkipPlugins: true,
				SkipThemes:  true,
			}); wErr != nil {
				return fmt.Errorf("rename default admin user: %w", wErr)
			}
		}
		inst.AdminUser = newAdmin
	}

	// 5. Lock permissions (Rule 3)
	if want[RuleLockPermissions] {
		if err := normalizeInstancePermissions(guard, acct, verifiedDocRoot, 0o600); err != nil {
			return err
		}
		e.mu.Lock()
		e.permTracked[inst.ID] = true
		e.saveStateLocked()
		e.mu.Unlock()
	}

	// 6. Sync MU-plugin security tweaks (Rules 8 & 11)
	if want[RuleBlockUserEnumeration] || want[RuleHideWPVersionHeaders] {
		if err := e.syncSecurityMUPlugin(guard, acct, verifiedDocRoot,
			want[RuleBlockUserEnumeration], want[RuleBlockUserEnumeration],
			want[RuleHideWPVersionHeaders], want[RuleHideWPVersionHeaders],
		); err != nil {
			return err
		}
	}

	_, err = e.Store.UpsertInstance(*inst)
	return err
}

// Revert rolls back reversible security hardening rules on an instance.
func (e *Engine) Revert(ctx context.Context, acct dausers.Account, instanceID string, ruleIDs []string) (Report, error) {
	inst, err := e.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return Report{}, err
	}
	if len(ruleIDs) == 0 {
		return Report{}, errors.New("rule_ids is required to revert hardening rules")
	}

	revertSet := make(map[string]bool, len(ruleIDs))
	for _, r := range ruleIDs {
		id := strings.ToLower(strings.TrimSpace(r))
		if id == "" {
			continue
		}
		if !isKnownRule(id) {
			return Report{}, fmt.Errorf("unknown security hardening rule %q", id)
		}
		if id == RuleRenameDefaultAdmin || id == RuleChangeDBPrefix || id == RuleRefreshSecuritySalts {
			return Report{}, fmt.Errorf("rule %q is a one-way security upgrade and is not downgraded", id)
		}
		revertSet[id] = true
	}

	runRevert := func() error {
		domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
		guard, gErr := fsguard.New(domainsRoot, nil)
		if gErr != nil {
			return gErr
		}
		verifiedDocRoot, gErr := guard.VerifyExistingPath(inst.DocRoot)
		if gErr != nil {
			return gErr
		}

		webUpdates := make(map[string]bool)
		for r := range revertSet {
			if webserver.IsWebRule(r) {
				webUpdates[r] = false
			}
		}
		if len(webUpdates) > 0 && e.WebServer != nil {
			if err := e.WebServer.SyncRules(ctx, acct, inst, webUpdates); err != nil {
				return err
			}
		}

		wpCfgPath := filepath.Join(verifiedDocRoot, "wp-config.php")
		if rawCfg, rErr := guard.ReadRegularFileSafe(wpCfgPath, 256*1024); rErr == nil {
			cfgStr := string(rawCfg)
			changed := false
			if revertSet[RuleDisallowFileEdit] {
				if next, ch := RemoveDefinedConstant(cfgStr, "DISALLOW_FILE_EDIT"); ch {
					cfgStr = next
					changed = true
				}
			}
			if revertSet[RuleForceHTTPS] {
				if next, ch := RemoveDefinedConstant(cfgStr, "FORCE_SSL_ADMIN"); ch {
					cfgStr = next
					changed = true
				}
			}
			if revertSet[RuleRefreshSecuritySalts] {
				if next, ch := UnmarkSalts(cfgStr); ch {
					cfgStr = next
					changed = true
				}
			}
			if changed {
				perm := os.FileMode(0o640)
				e.mu.Lock()
				if e.permTracked[inst.ID] && !revertSet[RuleLockPermissions] {
					perm = 0o600
				}
				e.mu.Unlock()
				if err := writeCustomerFileAtomic(guard, acct, wpCfgPath, cfgStr, perm); err != nil {
					return err
				}
			}
		}

		if revertSet[RuleLockPermissions] {
			_ = os.Chmod(wpCfgPath, 0o644)
			e.mu.Lock()
			delete(e.permTracked, inst.ID)
			e.saveStateLocked()
			e.mu.Unlock()
		}

		if revertSet[RuleBlockUserEnumeration] || revertSet[RuleHideWPVersionHeaders] {
			if err := e.syncSecurityMUPlugin(guard, acct, verifiedDocRoot,
				revertSet[RuleBlockUserEnumeration], false,
				revertSet[RuleHideWPVersionHeaders], false,
			); err != nil {
				return err
			}
		}
		return nil
	}

	if e.WithShieldSuppression != nil {
		if err := e.WithShieldSuppression(acct, inst, runRevert); err != nil {
			return Report{}, err
		}
	} else {
		if err := runRevert(); err != nil {
			return Report{}, err
		}
	}

	return e.evaluateInstance(acct, inst, true)
}

func (e *Engine) syncSecurityMUPlugin(
	guard *fsguard.Guard,
	acct dausers.Account,
	verifiedDocRoot string,
	touchUserEnum bool,
	enableUserEnum bool,
	touchHideVer bool,
	enableHideVer bool,
) error {
	muPath := filepath.Join(verifiedDocRoot, "wp-content", "mu-plugins", securityTweaksMUFile)
	existing, _ := guard.ReadRegularFileSafe(muPath, 64*1024)
	curStr := string(existing)

	userEnumOn := strings.Contains(curStr, "DA_WPTK_BLOCK_REST_USERS")
	hideVerOn := strings.Contains(curStr, "DA_WPTK_HIDE_WP_GENERATOR")

	if touchUserEnum {
		userEnumOn = enableUserEnum
	}
	if touchHideVer {
		hideVerOn = enableHideVer
	}

	if !userEnumOn && !hideVerOn {
		if st, err := os.Lstat(muPath); err == nil && st.Mode()&os.ModeSymlink == 0 {
			_ = os.Remove(muPath)
		}
		return nil
	}

	var php strings.Builder
	php.WriteString("<?php\n")
	php.WriteString("/**\n * Managed by WordPress Manager Security Hardener.\n */\n")
	php.WriteString("if ( ! defined( 'ABSPATH' ) ) { exit; }\n\n")

	if userEnumOn {
		php.WriteString("// DA_WPTK_BLOCK_REST_USERS\n")
		php.WriteString("add_filter( 'rest_endpoints', function( $endpoints ) {\n")
		php.WriteString("    if ( ! is_user_logged_in() ) {\n")
		php.WriteString("        unset( $endpoints['/wp/v2/users'] );\n")
		php.WriteString("        unset( $endpoints['/wp/v2/users/(?P<id>[\\d]+)'] );\n")
		php.WriteString("    }\n")
		php.WriteString("    return $endpoints;\n")
		php.WriteString("} );\n\n")
	}

	if hideVerOn {
		php.WriteString("// DA_WPTK_HIDE_WP_GENERATOR\n")
		php.WriteString("remove_action( 'wp_head', 'wp_generator' );\n")
		php.WriteString("add_filter( 'the_generator', '__return_empty_string' );\n")
	}

	return writeCustomerFileAtomic(guard, acct, muPath, php.String(), 0o644)
}

func normalizeInstancePermissions(guard *fsguard.Guard, acct dausers.Account, verifiedDocRoot string, wpConfigPerm os.FileMode) error {
	cfgPath := filepath.Join(verifiedDocRoot, "wp-config.php")
	if st, err := os.Lstat(cfgPath); err == nil && st.Mode().IsRegular() {
		if err := os.Chmod(cfgPath, wpConfigPerm); err != nil {
			return err
		}
		_ = chownNoFollow(cfgPath, acct.UID, acct.GID)
	}
	for _, sub := range []string{
		"",
		"wp-admin",
		"wp-includes",
		"wp-content",
		filepath.Join("wp-content", "upgrade"),
		filepath.Join("wp-content", "plugins"),
		filepath.Join("wp-content", "themes"),
		filepath.Join("wp-content", "languages"),
		filepath.Join("wp-content", "mu-plugins"),
		filepath.Join("wp-content", "uploads"),
	} {
		p := verifiedDocRoot
		if sub != "" {
			p = filepath.Join(verifiedDocRoot, sub)
		}
		if _, vErr := guard.VerifyExistingPath(p); vErr != nil {
			continue
		}
		if st, err := os.Lstat(p); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			_ = os.Chmod(p, 0o755)
			_ = chownNoFollow(p, acct.UID, acct.GID)
		}
	}
	return nil
}

func writeCustomerFileAtomic(guard *fsguard.Guard, acct dausers.Account, targetPath string, content string, perm os.FileMode) error {
	parent := filepath.Dir(targetPath)
	verifiedParent, err := guard.VerifyProspectivePath(parent)
	if err != nil {
		return err
	}
	// Safely create missing non-symlinked directories (e.g., wp-content/mu-plugins)
	rel, err := filepath.Rel(guard.AllowedRoot, verifiedParent)
	if err != nil {
		return err
	}
	cur := guard.AllowedRoot
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		if st, lErr := os.Lstat(cur); lErr != nil {
			if errors.Is(lErr, os.ErrNotExist) {
				if mkErr := os.Mkdir(cur, 0o755); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
					return mkErr
				}
				_ = chownNoFollow(cur, acct.UID, acct.GID)
			} else {
				return lErr
			}
		} else if st.Mode()&os.ModeSymlink != 0 {
			return fsguard.ErrSymlinkBlocked
		}
	}

	dest := filepath.Join(verifiedParent, filepath.Base(targetPath))
	if st, lErr := os.Lstat(dest); lErr == nil && st.Mode()&os.ModeSymlink != 0 {
		return fsguard.ErrSymlinkBlocked
	}

	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(verifiedParent, ".da-wptk-cfg-"+hex.EncodeToString(rnd[:]))
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		return err
	}
	_ = os.Chmod(tmp, perm)
	if err := chownNoFollow(tmp, acct.UID, acct.GID); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (e *Engine) resolvePHP(acct dausers.Account, inst store.InstanceRecord) daphp.Selection {
	if e.Domains != nil {
		if t, err := e.Domains.FindTarget(acct, inst.Domain); err == nil {
			return t.PHP
		}
	}
	return daphp.Selection{Slot: 1, Version: "8.3", BinaryPath: "/usr/local/php83/bin/php"}
}

func isKnownRule(id string) bool {
	for _, spec := range catalog {
		if spec.ID == id {
			return true
		}
	}
	return false
}
