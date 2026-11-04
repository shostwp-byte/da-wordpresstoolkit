package smartupdate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/extensions"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

func TestTC08_SmartSafeUpdateDetectsHTTP500AndAutoRollsBackUnder3Seconds(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	plugFile := filepath.Join(docRoot, "wp-content", "plugins", "faulty-plugin", "faulty-plugin.php")
	debugLog := filepath.Join(docRoot, "wp-content", "debug.log")

	if err := os.MkdirAll(filepath.Dir(plugFile), 0o755); err != nil {
		t.Fatal(err)
	}
	v1Code := "<?php\n/*\nPlugin Name: Faulty Plugin\nVersion: 1.0.0\n*/\n// Healthy v1.0.0\n"
	if err := os.WriteFile(plugFile, []byte(v1Code), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(debugLog, []byte("[init] log started\n"), 0o644)

	// Live HTTP server dynamically evaluates the current plugin code on disk!
	liveServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		raw, err := os.ReadFile(plugFile)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.Contains(string(raw), "throw new Error") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("PHP Fatal error: Uncaught Error in /home/reno26/domains/renolabs-audio.com/public_html/wp-content/plugins/faulty-plugin/faulty-plugin.php:7"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>RENOLABS Healthy 200 OK</body></html>"))
	}))
	defer liveServer.Close()

	st, _ := store.Open(filepath.Join(tmp, "state"))
	vdb, _ := vulndb.Open(filepath.Join(tmp, "state"), "")

	inst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:     "reno26",
		OwnerUID:  1005,
		Domain:    "renolabs-audio.com",
		DocRoot:   docRoot,
		SiteURL:   liveServer.URL, // Uses real DefaultLoopbackProber over HTTP!
		WPVersion: "6.7.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		joined := strings.Join(spec.Args, " ")
		if strings.Contains(joined, "plugin update") {
			// Simulate updating faulty-plugin to v2.0.0 containing `throw new Error`
			v2Broken := "<?php\n/*\nPlugin Name: Faulty Plugin\nVersion: 2.0.0\n*/\nthrow new Error('Crash on PHP 8.4');\n"
			_ = os.WriteFile(plugFile, []byte(v2Broken), 0o644)
			f, _ := os.OpenFile(debugLog, os.O_APPEND|os.O_WRONLY, 0o644)
			if f != nil {
				_, _ = f.WriteString("[04-Nov-2026] PHP Fatal error: Uncaught Error in /wp-content/plugins/faulty-plugin/faulty-plugin.php:6\n")
				_ = f.Close()
			}
		}
		if strings.Contains(joined, "plugin list") {
			raw, _ := os.ReadFile(plugFile)
			ver := "1.0.0"
			if strings.Contains(string(raw), "2.0.0") {
				ver = "2.0.0"
			}
			return `[{"name":"faulty-plugin","status":"active","update":"available","version":"` + ver + `","update_version":"2.0.0"}]`, "", nil
		}
		if strings.Contains(joined, "theme list") {
			return `[]`, "", nil
		}
		return "Success", "", nil
	}

	domRes := dadomains.NewResolver(filepath.Join(tmp, "da_data"), daphp.NewResolver("", ""))
	extMgr := extensions.NewManager(domRes, wpRunner, st, vdb)
	engine := NewEngine(domRes, wpRunner, extMgr, st, filepath.Join(tmp, "staging"))

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}

	start := time.Now()
	outcome, err := engine.UpdateInstance(context.Background(), acct, Request{
		InstanceID:  inst.ID,
		PluginSlugs: []string{"faulty-plugin"},
	}, nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("UpdateInstance returned unexpected fatal error: %v", err)
	}
	if elapsed >= 3*time.Second {
		t.Fatalf("Phase 2 DoD / TC-08 FAILED: rollback took %v (must be < 3s)", elapsed)
	}
	if !outcome.RolledBack || outcome.Status != "rolled_back" || !outcome.RestoredHealthy {
		t.Fatalf("TC-08 FAILED: expected automatic rollback & healthy recovery, got: %+v", outcome)
	}
	if len(outcome.CulpritSlugs) == 0 || outcome.CulpritSlugs[0] != "faulty-plugin" {
		t.Fatalf("TC-08 FAILED: expected culprit_slugs=[faulty-plugin], got: %+v", outcome.CulpritSlugs)
	}

	// Confirm plugin file on disk was restored to exact v1.0.0 code and live HTTP endpoint returns 200 OK
	restoredCode, _ := os.ReadFile(plugFile)
	if string(restoredCode) != v1Code {
		t.Fatalf("TC-08 FAILED: plugin file on disk was not restored to v1.0.0: %s", string(restoredCode))
	}
	resp, hErr := http.Get(liveServer.URL + "/")
	if hErr != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("TC-08 FAILED: live website did not recover to 200 OK (err=%v, resp=%+v)", hErr, resp)
	}
	_ = resp.Body.Close()
}

func TestBulkMultiSiteSmartUpdateIsolatesFaultySite(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	st, _ := store.Open(filepath.Join(tmp, "state"))

	var ids []string
	for _, dom := range []string{"ok1.com", "wsod2.com", "ok3.com"} {
		docRoot := filepath.Join(homeDir, "domains", dom, "public_html")
		plugDir := filepath.Join(docRoot, "wp-content", "plugins", "woo-helper")
		_ = os.MkdirAll(plugDir, 0o755)
		_ = os.WriteFile(filepath.Join(plugDir, "woo-helper.php"), []byte("<?php // v1.0\n"), 0o644)

		rec, _ := st.UpsertInstance(store.InstanceRecord{
			Owner:   "reno26",
			Domain:  dom,
			DocRoot: docRoot,
		})
		ids = append(ids, rec.ID)
	}

	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		if strings.Contains(strings.Join(spec.Args, " "), "plugin update") {
			_ = os.WriteFile(filepath.Join(spec.Dir, "wp-content", "plugins", "woo-helper", "woo-helper.php"), []byte("<?php // v2.0\n"), 0o644)
		}
		return "Success", "", nil
	}

	engine := NewEngine(nil, wpRunner, nil, st, filepath.Join(tmp, "staging"))
	engine.ProbeHealth = func(_ context.Context, inst store.InstanceRecord) HealthResult {
		raw, _ := os.ReadFile(filepath.Join(inst.DocRoot, "wp-content", "plugins", "woo-helper", "woo-helper.php"))
		if inst.Domain == "wsod2.com" && strings.Contains(string(raw), "v2.0") {
			return HealthResult{
				Healthy:      false,
				StatusCode:   200,
				FaultReason:  "WordPress Fatal/WSOD signature (\"there has been a critical error on this website\") detected",
				DetectedSlug: "woo-helper",
			}
		}
		return HealthResult{Healthy: true, StatusCode: 200}
	}

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}
	bulkOut, err := engine.RunBulkUpdate(
		context.Background(),
		func(_ string) (dausers.Account, error) { return acct, nil },
		BulkRequest{
			InstanceIDs: ids,
			PluginSlugs: []string{"woo-helper"},
		},
		nil,
	)
	if err != nil {
		t.Fatalf("RunBulkUpdate error: %v", err)
	}
	if bulkOut.TotalInstances != 3 || bulkOut.SucceededCount != 2 || bulkOut.RolledBackCount != 1 || bulkOut.FailedCount != 0 {
		t.Fatalf("unexpected BulkOutcome: %+v", bulkOut)
	}
}
