package quicktools

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
)

const (
	DefaultMaintenanceHeadline = "Website đang bảo trì nâng cấp"
	DefaultMaintenanceMessage  = "Chúng tôi đang nâng cấp hệ thống để mang lại trải nghiệm tốt hơn. Vui lòng quay lại sau ít phút."
	maintenanceConfigFile      = ".da-wptk-maintenance.json"
)

// MaintenanceConfig defines customizable content for the HTTP 503 Maintenance Mode screen.
type MaintenanceConfig struct {
	Enabled          bool   `json:"enabled"`
	Headline         string `json:"headline"`
	Message          string `json:"message"`
	RetryAfterSec    int    `json:"retry_after_sec"`
	AllowAdminBypass bool   `json:"allow_admin_bypass"`
}

func defaultMaintenanceConfig() MaintenanceConfig {
	return MaintenanceConfig{
		Enabled:          false,
		Headline:         DefaultMaintenanceHeadline,
		Message:          DefaultMaintenanceMessage,
		RetryAfterSec:    600,
		AllowAdminBypass: true,
	}
}

func readMaintenanceConfig(guard *fsguard.Guard, verifiedDocRoot string) MaintenanceConfig {
	cfg := defaultMaintenanceConfig()
	if raw, err := guard.ReadRegularFileUnderVerifiedRoot(verifiedDocRoot, 16*1024, "wp-content", maintenanceConfigFile); err == nil {
		_ = json.Unmarshal(raw, &cfg)
	}
	if strings.TrimSpace(cfg.Headline) == "" {
		cfg.Headline = DefaultMaintenanceHeadline
	}
	if strings.TrimSpace(cfg.Message) == "" {
		cfg.Message = DefaultMaintenanceMessage
	}
	if cfg.RetryAfterSec < 60 || cfg.RetryAfterSec > 86400 {
		cfg.RetryAfterSec = 600
	}
	dotMaint := filepath.Join(verifiedDocRoot, ".maintenance")
	if st, err := os.Lstat(dotMaint); err == nil && st.Mode().IsRegular() {
		cfg.Enabled = true
	} else {
		cfg.Enabled = false
	}
	return cfg
}

func applyMaintenanceState(guard *fsguard.Guard, acct dausers.Account, verifiedDocRoot, siteTitle string, req MaintenanceConfig) (MaintenanceConfig, error) {
	cur := readMaintenanceConfig(guard, verifiedDocRoot)
	if strings.TrimSpace(req.Headline) != "" {
		cur.Headline = truncateRunes(strings.TrimSpace(req.Headline), 140)
	}
	if strings.TrimSpace(req.Message) != "" {
		cur.Message = truncateRunes(strings.TrimSpace(req.Message), 600)
	}
	if req.RetryAfterSec >= 60 && req.RetryAfterSec <= 86400 {
		cur.RetryAfterSec = req.RetryAfterSec
	}
	cur.AllowAdminBypass = req.AllowAdminBypass
	cur.Enabled = req.Enabled

	wpContent := filepath.Join(verifiedDocRoot, "wp-content")
	if st, err := os.Lstat(wpContent); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return MaintenanceConfig{}, errors.New("security violation: wp-content is a symlink")
	}
	if err := os.MkdirAll(wpContent, 0o755); err != nil {
		return MaintenanceConfig{}, err
	}
	_ = chownNoFollow(wpContent, acct.UID, acct.GID)

	// Persist custom headline/message JSON so user customizations survive toggle OFF -> ON
	cfgBytes, _ := json.MarshalIndent(cur, "", "  ")
	if err := writeCustomerFileAtomic(acct, filepath.Join(wpContent, maintenanceConfigFile), append(cfgBytes, '\n'), 0o600); err != nil {
		return MaintenanceConfig{}, err
	}

	dotMaint := filepath.Join(verifiedDocRoot, ".maintenance")
	if st, err := os.Lstat(dotMaint); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return MaintenanceConfig{}, errors.New("security violation: .maintenance is a symlink")
	}

	customTpl := filepath.Join(wpContent, "maintenance.php")
	if st, err := os.Lstat(customTpl); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return MaintenanceConfig{}, errors.New("security violation: wp-content/maintenance.php is a symlink")
	}

	if !cur.Enabled {
		_ = os.Remove(dotMaint)
		// Only remove wp-content/maintenance.php if it carries our DA-WPTK marker
		if raw, err := os.ReadFile(customTpl); err == nil && strings.Contains(string(raw), "DA-WPTK-CUSTOM-MAINTENANCE") {
			_ = os.Remove(customTpl)
		}
		return cur, nil
	}

	renderedPHP := renderCustomMaintenancePHP(siteTitle, cur)
	if err := writeCustomerFileAtomic(acct, customTpl, []byte(renderedPHP), 0o644); err != nil {
		return MaintenanceConfig{}, err
	}

	dotBody := "<?php\n// DA-WPTK-MAINTENANCE\n"
	if cur.AllowAdminBypass {
		dotBody += "$dawptk_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';\n" +
			"if (strpos($dawptk_uri, 'wp-login.php') === false && strpos($dawptk_uri, 'dawptk_sso') === false && !defined('WP_CLI')) {\n" +
			"    $upgrading = time();\n" +
			"}\n"
	} else {
		dotBody += "if (!defined('WP_CLI')) { $upgrading = time(); }\n"
	}
	if err := writeCustomerFileAtomic(acct, dotMaint, []byte(dotBody), 0o644); err != nil {
		return MaintenanceConfig{}, err
	}

	return cur, nil
}

func renderCustomMaintenancePHP(siteTitle string, cfg MaintenanceConfig) string {
	title := strings.TrimSpace(siteTitle)
	if title == "" {
		title = "WordPress"
	}
	escTitle := html.EscapeString(title)
	escHeadline := html.EscapeString(cfg.Headline)
	escMsg := html.EscapeString(cfg.Message)

	return fmt.Sprintf(`<?php
// DA-WPTK-CUSTOM-MAINTENANCE
$protocol = wp_get_server_protocol();
header( "$protocol 503 Service Unavailable", true, 503 );
header( 'Content-Type: text/html; charset=utf-8' );
header( 'Retry-After: %d' );
?>
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>%s — %s</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#0f172a;padding:24px}
.card{max-width:520px;width:100%%;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:40px 32px;box-shadow:0 10px 25px rgba(15,23,42,.05);text-align:center}
.badge{display:inline-flex;align-items:center;justify-content:center;width:52px;height:52px;border-radius:14px;background:#eef2ff;color:#4f46e5;font-size:24px;font-weight:700;margin-bottom:20px}
h1{margin:0 0 12px;font-size:22px;line-height:1.35;color:#1e293b}
p{margin:0;font-size:15px;line-height:1.65;color:#475569}
.site{margin-top:24px;font-size:13px;color:#94a3b8}
</style>
</head>
<body>
<div class="card">
  <div class="badge">&#9881;</div>
  <h1>%s</h1>
  <p>%s</p>
  <div class="site">%s</div>
</div>
</body>
</html>
<?php die(); ?>
`, cfg.RetryAfterSec, escTitle, escHeadline, escHeadline, escMsg, escTitle)
}

func truncateRunes(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

func writeCustomerFileAtomic(acct dausers.Account, targetPath string, content []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	tmp := filepath.Join(dir, fmt.Sprintf(".da-wptk-tmp-%d-%s", os.Getpid(), filepath.Base(targetPath)))
	if err := os.WriteFile(tmp, content, perm); err != nil {
		return err
	}
	_ = chownNoFollow(tmp, acct.UID, acct.GID)
	if err := os.Rename(tmp, targetPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
