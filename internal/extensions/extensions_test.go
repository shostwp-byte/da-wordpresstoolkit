package extensions

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

func buildTestZip(entries map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestValidateExtensionZipBlocksZipSlipAndAllowsCleanPlugin(t *testing.T) {
	tmp := t.TempDir()

	// 1. Malicious Zip-Slip archive MUST be rejected
	evilZip := filepath.Join(tmp, "evil.zip")
	_ = os.WriteFile(evilZip, buildTestZip(map[string]string{
		"my-plugin/../../shell.php": "<?php system($_GET['c']);",
	}), 0o600)
	if _, err := ValidateExtensionZip(evilZip); err == nil {
		t.Fatal("expected Zip-Slip traversal entry to be blocked")
	}

	// 2. Clean plugin archive passes and returns top-level slug
	goodBytes := buildTestZip(map[string]string{
		"pro-slider/pro-slider.php": "<?php\n/*\nPlugin Name: Pro Slider\nVersion: 2.1.0\n*/\n",
	})
	staged, slug, cleanup, err := StageCustomerZip(
		filepath.Join(tmp, "stage"),
		"",
		base64.StdEncoding.EncodeToString(goodBytes),
		1005,
		1005,
	)
	if err != nil {
		t.Fatalf("expected clean .zip to stage cleanly, got: %v", err)
	}
	defer cleanup()
	if slug != "pro-slider" || staged == "" {
		t.Fatalf("unexpected staged zip output: slug=%q path=%q", slug, staged)
	}
}

func TestListManageAggregateAndSearchWPOrgWithCVEEnrichment(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	daRoot := filepath.Join(tmp, "da_data")

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=site1.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("site1.com\nsite2.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "site1.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "site2.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	st, _ := store.Open(filepath.Join(tmp, "state"))
	vdb, _ := vulndb.Open(filepath.Join(tmp, "state"), "")
	_ = vdb.LoadStream(strings.NewReader(`{
		"wf-1": {
			"id": "wf-1",
			"title": "Elementor <= 3.18.2 - RCE",
			"cve": "CVE-2024-9999",
			"cvss": {"score": 9.1, "rating": "Critical"},
			"software": [{
				"type": "plugin",
				"slug": "elementor",
				"patched": true,
				"patched_versions": ["3.18.3"],
				"affected_versions": {"all": {"from_version": "*", "from_inclusive": true, "to_version": "3.18.2", "to_inclusive": true}}
			}]
		}
	}`), "inline")

	var instances []store.InstanceRecord
	for _, dom := range []string{"site1.com", "site2.com"} {
		docRoot := filepath.Join(homeDir, "domains", dom, "public_html")
		_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "plugins", "elementor"), 0o755)
		_ = os.WriteFile(
			filepath.Join(docRoot, "wp-content", "plugins", "elementor", "elementor.php"),
			[]byte("<?php\n/*\nPlugin Name: Elementor Website Builder\nVersion: 3.18.1\nAuthor: Elementor.com\n*/\n"),
			0o644,
		)
		_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "themes", "flavor"), 0o755)
		_ = os.WriteFile(
			filepath.Join(docRoot, "wp-content", "themes", "flavor", "style.css"),
			[]byte("/*\nTheme Name: Flavor Pro\nVersion: 1.0.0\n*/\n"),
			0o644,
		)
		rec, _ := st.UpsertInstance(store.InstanceRecord{
			Owner:     "reno26",
			OwnerUID:  1005,
			Domain:    dom,
			DocRoot:   docRoot,
			WPVersion: "6.7.1",
		})
		instances = append(instances, rec)
	}

	var sawSkipFlags bool
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		joined := strings.Join(spec.Args, " ")
		if strings.Contains(joined, "--skip-plugins") && strings.Contains(joined, "--skip-themes") {
			sawSkipFlags = true
		}
		if strings.Contains(joined, "plugin list") {
			return `[{"name":"elementor","status":"active","update":"available","version":"3.18.1","update_version":"3.18.3","auto_update":"off"}]`, "", nil
		}
		if strings.Contains(joined, "theme list") {
			return `[{"name":"flavor","status":"active","update":"none","version":"1.0.0","auto_update":"on"}]`, "", nil
		}
		return "Success", "", nil
	}

	wpOrgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"plugins":[{"slug":"elementor","name":"Elementor","version":"3.18.1","author":"Elementor","rating":94,"active_installs":5000000,"short_description":"Page builder","icons":{"1x":"https://ps.w.org/elementor/icon.png"}}]}`))
	}))
	defer wpOrgSrv.Close()

	mgr := NewManager(dadomains.NewResolver(daRoot, daphp.NewResolver("", "")), wpRunner, st, vdb)
	mgr.WPOrgAPIBase = wpOrgSrv.URL

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}

	// 1. Single-site WSOD-safe deactivate works with --skip-plugins --skip-themes
	items, err := mgr.ManagePlugin(context.Background(), acct, instances[0].ID, ActionRequest{
		Operation: "deactivate",
		Slug:      "elementor",
	})
	if err != nil {
		t.Fatalf("ManagePlugin deactivate failed: %v", err)
	}
	if !sawSkipFlags {
		t.Fatal("expected WSOD-safe --skip-plugins --skip-themes flags on WP-CLI call")
	}
	if len(items) != 1 || items[0].Title != "Elementor Website Builder" || len(items[0].Vulns) != 1 {
		t.Fatalf("expected enriched Elementor item with 1 CVE, got: %+v", items)
	}

	// 2. Cross-site Global Aggregation groups Elementor across both sites
	groups, err := mgr.AggregateAccountExtensions(context.Background(), acct, false)
	if err != nil {
		t.Fatalf("AggregateAccountExtensions failed: %v", err)
	}
	if len(groups) != 1 || groups[0].TotalSites != 2 || groups[0].VulnerableSites != 2 || groups[0].OutdatedSites != 2 {
		t.Fatalf("unexpected aggregated group: %+v", groups)
	}

	// 3. Vulnerability scan updates InstanceRecord.VulnCount
	vRep, err := mgr.ScanInstanceVulnerabilities(context.Background(), acct, instances[0].ID)
	if err != nil || vRep.TotalVulns != 1 || vRep.CriticalOrHigh != 1 {
		t.Fatalf("unexpected vuln report: %+v (err=%v)", vRep, err)
	}

	// 4. WordPress.org search enriches results with CVE alerts
	searchRes, err := mgr.SearchWPOrg(context.Background(), "plugin", "elementor", 1, 10)
	if err != nil || len(searchRes) != 1 || len(searchRes[0].Vulns) != 1 {
		t.Fatalf("unexpected SearchWPOrg result: %+v (err=%v)", searchRes, err)
	}
}
