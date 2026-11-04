package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

func seedMockWPSite(t *testing.T, docRoot, wpVer, dbName string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(docRoot, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(docRoot, "wp-content", "plugins", "litespeed-cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(docRoot, "wp-content", "themes", "twentytwentyfive"), 0o755); err != nil {
		t.Fatal(err)
	}
	verPHP := fmt.Sprintf("<?php\n// WordPress Version\n$wp_version = '%s';\n$wp_local_package = 'vi';\n", wpVer)
	if err := os.WriteFile(filepath.Join(docRoot, "wp-includes", "version.php"), []byte(verPHP), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPHP := fmt.Sprintf(
		"<?php\n/* define('DB_NAME', 'commented_out_old_db'); */\n// define('DB_NAME', 'line_comment_db');\ndefine('DB_NAME', '%s');\ndefine('DB_USER', '%s_u');\ndefine('WP_DEBUG', true);\ndefine('DISABLE_WP_CRON', true);\n$table_prefix = 'wp_9a_';\n",
		dbName, dbName,
	)
	if err := os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte(cfgPHP), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTC03_MultiTopologyDomainSubdomainAndSubdirDiscovery verifies Acceptance Test Case TC-03:
// 2 main/addon domains + 2 classic public_html/sub subdomains + 1 custom-docroot subdomain + 1 /blog subdir = 6 exact instances.
func TestTC03_MultiTopologyDomainSubdomainAndSubdirDiscovery(t *testing.T) {
	tmp := t.TempDir()
	daRoot := filepath.Join(tmp, "da_data")
	homeDir := filepath.Join(tmp, "home", "reno26")
	optPath := filepath.Join(tmp, "options.conf")

	_ = os.WriteFile(optPath, []byte("php1_release=8.3\nphp2_release=8.1\nphp3_release=8.4\n"), 0o644)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\nsecond-site.vn\n"), 0o600)

	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=3\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.subdomains"), []byte("sub1\nsub2\ncustomsub\n"), 0o600)
	_ = os.WriteFile(
		filepath.Join(domDir, "renolabs-audio.com.subdomains.docroot.override"),
		[]byte("customsub=documentroot%3D%2Fdomains%2Frenolabs-audio.com%2Fsubdomains%2Fcustomsub%26php1_select%3D2\n"),
		0o600,
	)
	_ = os.WriteFile(filepath.Join(domDir, "second-site.vn.conf"), []byte("ssl=OFF\nphp1_select=1\n"), 0o600)

	// Seed 6 distinct WordPress installations:
	// 1. Main domain root
	mainRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	seedMockWPSite(t, mainRoot, "6.7.1", "reno26_main")
	// 2. Addon domain root
	addonRoot := filepath.Join(homeDir, "domains", "second-site.vn", "public_html")
	seedMockWPSite(t, addonRoot, "6.6.2", "reno26_addon")
	// 3 & 4. Classic subdomains inside mainRoot/sub1 and mainRoot/sub2
	seedMockWPSite(t, filepath.Join(mainRoot, "sub1"), "6.7.1", "reno26_sub1")
	seedMockWPSite(t, filepath.Join(mainRoot, "sub2"), "6.7.0", "reno26_sub2")
	// 5. Custom docroot override subdomain
	seedMockWPSite(t, filepath.Join(homeDir, "domains", "renolabs-audio.com", "subdomains", "customsub"), "6.5.5", "reno26_custom")
	// 6. Subdirectory install /blog inside mainRoot
	seedMockWPSite(t, filepath.Join(mainRoot, "blog"), "6.7.1", "reno26_blog")

	st, err := store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	pol := config.NewPolicyStore(filepath.Join(tmp, "pdata"), "")
	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver(optPath, filepath.Join(tmp, "usr_local")))
	scanner := NewScanner(domRes, st, pol)

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir, Package: "pro"}
	res, err := scanner.ScanAccount(acct, false)
	if err != nil {
		t.Fatalf("ScanAccount failed: %v", err)
	}

	if res.DiscoveredTotal != 6 {
		t.Fatalf("TC-03 FAILED: expected exactly 6 discovered instances (no duplicates), got %d", res.DiscoveredTotal)
	}

	foundKeys := make(map[string]store.InstanceRecord)
	for _, inst := range res.Instances {
		key := inst.Domain + inst.SubPath
		foundKeys[key] = inst
		if inst.DBName == "commented_out_old_db" || inst.DBName == "line_comment_db" {
			t.Fatalf("commented-out DB_NAME leaked into parser: %+v", inst)
		}
	}

	expected := map[string]string{
		"renolabs-audio.com":           "8.4",
		"renolabs-audio.com/blog":      "8.4",
		"sub1.renolabs-audio.com":      "8.4",
		"sub2.renolabs-audio.com":      "8.4",
		"customsub.renolabs-audio.com": "8.1",
		"second-site.vn":               "8.3",
	}
	for k, wantPHP := range expected {
		inst, ok := foundKeys[k]
		if !ok {
			t.Fatalf("TC-03 FAILED: missing expected instance %q", k)
		}
		if inst.PHPVersion != wantPHP {
			t.Fatalf("TC-03 FAILED: %s expected PHP %s, got %s", k, wantPHP, inst.PHPVersion)
		}
	}
	if _, wrong := foundKeys["renolabs-audio.com/sub1"]; wrong {
		t.Fatal("TC-03 FAILED: subdomain sub1 was misclassified as subdirectory renolabs-audio.com/sub1")
	}
}

func TestScan200WebsitesUnder1500msDoD(t *testing.T) {
	tmp := t.TempDir()
	daRoot := filepath.Join(tmp, "da_data")
	homeDir := filepath.Join(tmp, "home", "agency")
	userDir := filepath.Join(daRoot, "users", "agency")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=site0.com\n"), 0o600)

	var domList strings.Builder
	for i := 0; i < 200; i++ {
		dom := fmt.Sprintf("site%d.com", i)
		domList.WriteString(dom + "\n")
		_ = os.WriteFile(filepath.Join(domDir, dom+".conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
		seedMockWPSite(t, filepath.Join(homeDir, "domains", dom, "public_html"), "6.7.1", fmt.Sprintf("agency_wp%d", i))
	}
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte(domList.String()), 0o600)

	st, _ := store.Open(filepath.Join(tmp, "state"))
	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	scanner := NewScanner(domRes, st, nil)

	start := time.Now()
	res, err := scanner.ScanAccount(dausers.Account{Username: "agency", UID: 1020, GID: 1020, HomeDir: homeDir}, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ScanAccount 200 sites error: %v", err)
	}
	if res.DiscoveredTotal != 200 {
		t.Fatalf("expected 200 sites, got %d", res.DiscoveredTotal)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Phase 1 DoD FAILED: scanning 200 sites took %v (limit 1.5s)", elapsed)
	}
}
