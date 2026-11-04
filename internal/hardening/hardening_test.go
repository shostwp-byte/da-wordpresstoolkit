package hardening

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

func TestTC07_HardeningBlocksUploadsPHPAcrossApacheOLSAndNginx(t *testing.T) {
	serverKinds := []webserver.ServerKind{
		webserver.KindApache,
		webserver.KindOpenLiteSpeed,
		webserver.KindNginx,
	}

	for _, kind := range serverKinds {
		t.Run(string(kind), func(t *testing.T) {
			tmp := t.TempDir()
			optConf := filepath.Join(tmp, "options.conf")
			if err := os.WriteFile(optConf, []byte("webserver="+string(kind)+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			homeDir := filepath.Join(tmp, "home", "reno26")
			docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
			uploadsDir := filepath.Join(docRoot, "wp-content", "uploads")
			if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte("<?php\n$table_prefix = 'wp_';\n/* That's all, stop editing! */\n"), 0o644)
			_ = os.WriteFile(filepath.Join(uploadsDir, "test.php"), []byte("<?php echo 'PWNED';"), 0o644)
			_ = os.WriteFile(filepath.Join(uploadsDir, "banner.png"), []byte("PNGDATA"), 0o644)

			st, err := store.Open(filepath.Join(tmp, "state"))
			if err != nil {
				t.Fatal(err)
			}
			inst, err := st.UpsertInstance(store.InstanceRecord{
				Owner:       "reno26",
				OwnerUID:    1005,
				Domain:      "renolabs-audio.com",
				DocRoot:     docRoot,
				SiteURL:     "http://renolabs-audio.com",
				AdminUser:   "radmin",
				TablePrefix: "wp_8a2f_",
			})
			if err != nil {
				t.Fatal(err)
			}

			ws := webserver.NewAdapter(optConf, filepath.Join(tmp, "nginx"))
			ws.OLSReloadDebounce = 25 * time.Millisecond
			ws.ExecCommand = func(_ context.Context, _ string, _ ...string) (string, error) {
				return "OK", nil
			}

			eng := NewEngine(filepath.Join(tmp, "state"), ws, nil, nil, st)
			acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}

			// Spin up simulated HTTP server backed by webserver.Adapter
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ws.EvaluateHTTPRequest(acct, inst, w, r) {
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("200 OK"))
			}))
			defer srv.Close()

			// Before hardening: /wp-content/uploads/test.php is reachable (200)
			respPre, err := http.Get(srv.URL + "/wp-content/uploads/test.php")
			if err != nil {
				t.Fatal(err)
			}
			_ = respPre.Body.Close()
			if respPre.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 before hardening, got %d", respPre.StatusCode)
			}

			// Apply Rule 1: block_uploads_php
			rep, err := eng.Apply(context.Background(), acct, inst.ID, ApplyRequest{
				RuleIDs: []string{RuleBlockUploadsPHP},
			})
			if err != nil {
				t.Fatalf("Apply(block_uploads_php) failed on %s: %v", kind, err)
			}
			if kind == webserver.KindOpenLiteSpeed {
				// Wait for debounced OLS graceful reload to commit .htaccess
				if err := ws.FlushPendingReloads(context.Background()); err != nil {
					t.Fatal(err)
				}
				if ws.OLSReloadCount() < 1 {
					t.Fatal("expected OpenLiteSpeed lswsctrl reload to be executed")
				}
			}

			// Verify HTTP 403 Forbidden on /wp-content/uploads/test.php!
			respPost, err := http.Get(srv.URL + "/wp-content/uploads/test.php")
			if err != nil {
				t.Fatal(err)
			}
			_ = respPost.Body.Close()
			if respPost.StatusCode != http.StatusForbidden {
				t.Fatalf("TC-07 FAILED on %s: expected 403 Forbidden on /wp-content/uploads/test.php, got %d", kind, respPost.StatusCode)
			}

			// Verify static media in uploads (/wp-content/uploads/banner.png) still returns 200 OK!
			respImg, err := http.Get(srv.URL + "/wp-content/uploads/banner.png")
			if err != nil {
				t.Fatal(err)
			}
			_ = respImg.Body.Close()
			if respImg.StatusCode != http.StatusOK {
				t.Fatalf("static media in uploads must remain 200 OK on %s, got %d", kind, respImg.StatusCode)
			}

			// Verify score updated in report (block_uploads_php + non-default radmin + non-default wp_8a2f_ = 3/12)
			if rep.Score != 3 || rep.Total != 12 {
				t.Fatalf("expected score 3/12, got %d/%d", rep.Score, rep.Total)
			}
		})
	}
}

func TestAll12HardeningRulesApplyCheckAndRevert(t *testing.T) {
	tmp := t.TempDir()
	optConf := filepath.Join(tmp, "options.conf")
	_ = os.WriteFile(optConf, []byte("webserver=apache\n"), 0o644)

	homeDir := filepath.Join(tmp, "home", "reno26")
	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "uploads"), 0o755)
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-includes"), 0o755)

	initialCfg := strings.Join([]string{
		"<?php",
		"define( 'DB_NAME', 'reno26_wp1' );",
		"define( 'AUTH_KEY', 'put your unique phrase here' );",
		"$table_prefix = 'wp_';",
		"/* That's all, stop editing! Happy publishing. */",
		"require_once ABSPATH . 'wp-settings.php';",
		"",
	}, "\n")
	_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte(initialCfg), 0o644)

	st, _ := store.Open(filepath.Join(tmp, "state"))
	inst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:       "reno26",
		OwnerUID:    1005,
		Domain:      "renolabs-audio.com",
		DocRoot:     docRoot,
		SiteURL:     "http://renolabs-audio.com",
		AdminUser:   "admin",
		TablePrefix: "wp_",
	})
	if err != nil {
		t.Fatal(err)
	}

	ws := webserver.NewAdapter(optConf, filepath.Join(tmp, "nginx"))
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, _ wpcli.ExecSpec) (string, string, error) {
		return "Success", "", nil
	}

	eng := NewEngine(filepath.Join(tmp, "state"), ws, nil, wpRunner, st)
	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}

	// Apply PresetAll (all 12 rules!)
	rep, err := eng.Apply(context.Background(), acct, inst.ID, ApplyRequest{
		Preset:         PresetAll,
		NewAdminUser:   "reno_secadmin",
		NewTablePrefix: "wp_7c4d_",
	})
	if err != nil {
		t.Fatalf("Apply(PresetAll) failed: %v", err)
	}
	if rep.Score != 12 || rep.Total != 12 {
		for _, r := range rep.Rules {
			if !r.Applied {
				t.Logf("UNAPPLIED RULE: %s (%s)", r.ID, r.Detail)
			}
		}
		t.Fatalf("expected 12/12 score after PresetAll, got %d/%d", rep.Score, rep.Total)
	}

	// Revert all 9 toggleable rules (leaving the 3 permanent cryptographic/DB upgrades applied = 3/12)
	reversibleIDs := []string{
		RuleBlockUploadsPHP,
		RuleBlockIncludesPHP,
		RuleLockPermissions,
		RuleDisallowFileEdit,
		RuleBlockSensitiveFiles,
		RuleDisableXMLRPC,
		RuleBlockUserEnumeration,
		RuleHideWPVersionHeaders,
		RuleForceHTTPS,
	}
	repAfterRevert, err := eng.Revert(context.Background(), acct, inst.ID, reversibleIDs)
	if err != nil {
		t.Fatalf("Revert failed: %v", err)
	}
	if repAfterRevert.Score != 3 {
		t.Fatalf("expected score 3/12 after reverting 9 toggleable rules, got %d/12", repAfterRevert.Score)
	}
}
