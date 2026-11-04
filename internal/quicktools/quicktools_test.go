package quicktools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

func TestQuickToolsDebugTailMaintenanceDACronPasswordAndSearchReplace(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	daRoot := filepath.Join(tmp, "da_data")
	optionsConf := filepath.Join(tmp, "options.conf")
	_ = os.WriteFile(optionsConf, []byte("webserver=apache\n"), 0o644)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("package=pro\ndomain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	// Seed pre-existing customer cronjob in DirectAdmin crontab.conf
	_ = os.WriteFile(filepath.Join(userDir, "crontab.conf"), []byte(
		"MAILTO=owner@renolabs-audio.com\n"+
			"0=minute=5&hour=3&day_of_month=*&month=*&day_of_week=*&command=%2Fusr%2Flocal%2Fbin%2Fphp+%2Fhome%2Freno26%2Fcustom_report.php\n",
	), 0o600)

	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "litespeed", "cache"), 0o755)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-content", "litespeed", "cache", "page1.cache"), []byte("cached"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte(
		"<?php\ndefine( 'DB_NAME', 'reno26_wp1' );\ndefine( 'DB_USER', 'reno26_wp1' );\ndefine( 'DB_PASSWORD', 'TopSecretPass!' );\n$table_prefix = 'wp_';\n/* That's all, stop editing! Happy publishing. */\n",
	), 0o600)

	st, err := store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir, Package: "pro"}
	inst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:          "reno26",
		OwnerUID:       1005,
		Domain:         "renolabs-audio.com",
		DocRoot:        docRoot,
		SiteURL:        "https://renolabs-audio.com",
		SiteTitle:      "RENOLABS",
		WPVersion:      "6.7.1",
		SearchIndexing: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		joined := strings.Join(spec.Args, " ")
		if strings.Contains(joined, "search-replace") {
			return "Table,Column,Replacements,Type\nwp_options,option_value,4,PHP\nwp_postmeta,meta_value,19,PHP\n", "", nil
		}
		return "Success", "", nil
	}

	wsAdapter := webserver.NewAdapter(optionsConf, filepath.Join(tmp, "nginx"))
	var installedVixie string
	cronMgr := NewDACronManager(daRoot)
	cronMgr.InstallCrontab = func(_ context.Context, _ string, body string) error {
		installedVixie = body
		return nil
	}

	mgr := NewManager(domRes, wpRunner, wsAdapter, cronMgr, st)
	ctx := context.Background()

	// 1. Reverse 32KB Tail Log Viewer on an ~85 KB debug.log
	var bigLog strings.Builder
	for i := 1; i <= 1200; i++ {
		fmt.Fprintf(&bigLog, "[04-Nov-2026 15:00:00 UTC] PHP Notice: sample diagnostic line #%04d padding_text_for_32kb_window\n", i)
	}
	_ = os.WriteFile(filepath.Join(docRoot, "wp-content", "debug.log"), []byte(bigLog.String()), 0o600)

	tail, err := mgr.ReadDebugLog(acct, inst.ID, 0)
	if err != nil {
		t.Fatalf("ReadDebugLog failed: %v", err)
	}
	if !tail.Exists || !tail.Truncated || tail.ReadBytes != DefaultDebugLogTailBytes {
		t.Fatalf("expected 32KB truncated tail, got: exists=%v truncated=%v read=%d", tail.Exists, tail.Truncated, tail.ReadBytes)
	}
	if !strings.HasPrefix(tail.Lines[0], "[04-Nov-2026") || !strings.Contains(tail.Lines[len(tail.Lines)-1], "#1200") {
		t.Fatalf("expected clean full first & last lines, got first=%q last=%q", tail.Lines[0], tail.Lines[len(tail.Lines)-1])
	}
	if err := mgr.ClearDebugLog(acct, inst.ID); err != nil {
		t.Fatalf("ClearDebugLog failed: %v", err)
	}
	clearedTail, _ := mgr.ReadDebugLog(acct, inst.ID, 0)
	if clearedTail.TotalSizeBytes != 0 {
		t.Fatalf("expected 0-byte debug.log after ClearDebugLog, got %d", clearedTail.TotalSizeBytes)
	}

	// 2. Custom 503 Maintenance Mode with XSS escaping & persistent config
	maint, err := mgr.SetMaintenanceMode(ctx, acct, inst.ID, MaintenanceConfig{
		Enabled:          true,
		Headline:         "Bảo trì <script>alert(1)</script>",
		Message:          "Hệ thống nâng cấp dự kiến 10 phút.",
		AllowAdminBypass: true,
	})
	if err != nil || !maint.Enabled {
		t.Fatalf("SetMaintenanceMode ON failed: %+v (%v)", maint, err)
	}
	tplBytes, err := os.ReadFile(filepath.Join(docRoot, "wp-content", "maintenance.php"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(tplBytes), "<script>") || !strings.Contains(string(tplBytes), "&lt;script&gt;") {
		t.Fatal("expected HTML escaping in generated wp-content/maintenance.php")
	}
	maintOff, err := mgr.SetMaintenanceMode(ctx, acct, inst.ID, MaintenanceConfig{Enabled: false})
	if err != nil || maintOff.Enabled {
		t.Fatalf("SetMaintenanceMode OFF failed: %v", err)
	}
	if _, sErr := os.Stat(filepath.Join(docRoot, ".maintenance")); !os.IsNotExist(sErr) {
		t.Fatal("expected .maintenance to be removed when disabled")
	}

	// 3. Take over wp-cron.php -> DirectAdmin crontab.conf sync preserves customer job #0
	updatedInst, cronCmd, err := mgr.SetWPCronTakeover(ctx, acct, inst.ID, true, 15)
	if err != nil {
		t.Fatalf("SetWPCronTakeover ON failed: %v", err)
	}
	if !updatedInst.DisableWPCron || updatedInst.CronIntervalMin != 15 || !strings.Contains(cronCmd, "wp-cron.php") {
		t.Fatalf("unexpected wp-cron state: %+v cmd=%q", updatedInst, cronCmd)
	}
	if !strings.Contains(installedVixie, "custom_report.php") || !strings.Contains(installedVixie, "*/15 * * * *") {
		t.Fatalf("expected Vixie crontab to preserve custom_report.php and add */15 wp-cron, got:\n%s", installedVixie)
	}
	_, _, err = mgr.SetWPCronTakeover(ctx, acct, inst.ID, false, 15)
	if err != nil {
		t.Fatalf("SetWPCronTakeover OFF failed: %v", err)
	}
	if strings.Contains(installedVixie, "wp-cron.php") || !strings.Contains(installedVixie, "custom_report.php") {
		t.Fatalf("expected wp-cron entry removed while keeping customer cronjob, got:\n%s", installedVixie)
	}

	// 4. HTTP Password Protection (401 without creds -> 200 pass-through with APR1 Basic Auth)
	pwSt, err := mgr.SetPasswordProtection(ctx, acct, inst.ID, PasswordProtectionRequest{
		Enabled:  true,
		Username: "staging_review",
		Password: "Preview2026!",
		Realm:    "RENOLABS Staging",
	})
	if err != nil || !pwSt.Enabled {
		t.Fatalf("SetPasswordProtection failed: %+v (%v)", pwSt, err)
	}
	curInst, _ := st.GetInstance(inst.ID)

	reqNoAuth := httptest.NewRequest(http.MethodGet, "https://renolabs-audio.com/", nil)
	recNoAuth := httptest.NewRecorder()
	if !wsAdapter.EvaluateHTTPRequest(acct, curInst, recNoAuth, reqNoAuth) || recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized without Basic Auth, got code=%d", recNoAuth.Code)
	}

	reqValidAuth := httptest.NewRequest(http.MethodGet, "https://renolabs-audio.com/", nil)
	reqValidAuth.SetBasicAuth("staging_review", "Preview2026!")
	recValidAuth := httptest.NewRecorder()
	if wsAdapter.EvaluateHTTPRequest(acct, curInst, recValidAuth, reqValidAuth) {
		t.Fatalf("expected valid Basic Auth request to pass through to WordPress, got code=%d", recValidAuth.Code)
	}

	// 5. Safe wp-config.php editor + ClearCache + Dry-Run Search & Replace
	mem := "256M"
	rev := 5
	cfgView, err := mgr.UpdateSafeWPConfig(acct, inst.ID, SafeWPConfigUpdate{
		WPMemoryLimit:   &mem,
		WPPostRevisions: &rev,
	})
	if err != nil {
		t.Fatalf("UpdateSafeWPConfig failed: %v", err)
	}
	if cfgView.WPMemoryLimit != "256M" || cfgView.WPPostRevisions != 5 {
		t.Fatalf("unexpected SafeWPConfigView: %+v", cfgView)
	}

	srRes, err := mgr.SearchReplace(ctx, acct, inst.ID, SearchReplaceRequest{
		Search:  "http://old.renolabs-audio.com",
		Replace: "https://renolabs-audio.com",
		DryRun:  true,
	})
	if err != nil {
		t.Fatalf("SearchReplace Dry-Run failed: %v", err)
	}
	if !srRes.DryRun || srRes.TablesAffected != 2 || srRes.TotalReplacements != 23 {
		t.Fatalf("unexpected SearchReplace preview: %+v", srRes)
	}

	cacheOut, err := mgr.ClearCache(ctx, acct, inst.ID)
	if err != nil {
		t.Fatalf("ClearCache failed: %v", err)
	}
	if _, sErr := os.Stat(filepath.Join(docRoot, "wp-content", "litespeed", "cache", "page1.cache")); !os.IsNotExist(sErr) {
		t.Fatalf("expected litespeed cache file purged, cacheOut=%+v", cacheOut)
	}
}
