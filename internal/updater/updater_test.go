package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

func buildTestReleaseTarGz(t *testing.T, outTarGz string, binPayload string, confVer string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(outTarGz), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(outTarGz)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	now := time.Now().UTC()
	paddedBin := binPayload + "\n" + strings.Repeat("#BINARY_PADDING#", 128)
	files := map[string]struct {
		body string
		mode int64
	}{
		"bin/da-wptoolkit":        {body: paddedBin, mode: 0o755},
		"plugin/plugin.conf":      {body: "name=DA WordPress Toolkits\nid=da_wp_toolkits\nversion=" + confVer + "\n", mode: 0o644},
		"plugin/admin/index.html": {body: "#!/bin/sh\necho admin-" + confVer + "\n", mode: 0o755},
		"plugin/user/index.html":  {body: "#!/bin/sh\necho user-" + confVer + "\n", mode: 0o755},
		"scripts/da_hooks/domain_create_post.sh": {
			body: "#!/usr/bin/env bash\nexit 0\n",
			mode: 0o755,
		},
		"scripts/update.sh": {
			body: "#!/usr/bin/env bash\nexit 0\n",
			mode: 0o755,
		},
	}

	for name, item := range files {
		if err := addTarBytes(tw, name, []byte(item.body), item.mode, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTC10Ed25519SignatureVerificationTamperBlockAndAutoRollback(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "state")
	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	// Seed active WordPress instance in Registry — MUST remain 100% intact across updates & rollbacks!
	seededInst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:     "reno26",
		OwnerUID:  1005,
		Domain:    "renolabs-audio.com",
		DocRoot:   "/home/reno26/domains/renolabs-audio.com/public_html",
		SiteTitle: "RENOLABS PRODUCTION",
		WPVersion: "6.7.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed live installation (v0.6.0) + live customer package policy in plugin/data/
	binPath := filepath.Join(tmp, "sbin", "da-wptoolkit")
	pluginDir := filepath.Join(tmp, "plugins", "da_wp_toolkits")
	hooksDir := filepath.Join(tmp, "da_custom_hooks")
	shareDir := filepath.Join(tmp, "share", "da-wptoolkit")

	_ = os.MkdirAll(filepath.Dir(binPath), 0o755)
	_ = os.MkdirAll(filepath.Join(pluginDir, "data"), 0o755)
	_ = os.MkdirAll(filepath.Join(pluginDir, "user"), 0o755)

	origBinContent := "HEALTHY_DAEMON_V0.6.0\n" + strings.Repeat("A", 2048)
	_ = os.WriteFile(binPath, []byte(origBinContent), 0o755)
	_ = os.WriteFile(filepath.Join(pluginDir, "plugin.conf"), []byte("version=0.6.0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(pluginDir, "user", "index.html"), []byte("#!/bin/sh\necho user-0.6.0\n"), 0o755)
	livePolicyContent := "max_instances=25\nallow_clone=yes\n"
	_ = os.WriteFile(filepath.Join(pluginDir, "data", "default_policy.conf"), []byte(livePolicyContent), 0o640)

	// Generate Ed25519 release signing keypair
	privHex, pubHex, err := GenerateKeyPairHex()
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := ParsePrivateKey(privHex)
	if err != nil {
		t.Fatal(err)
	}

	// Prepare 3 release directories served over mock GitHub API + Asset server:
	//   1) v1.0.0-forged  -> tampered checksums.txt signature (MUST fail with ErrInvalidSignature)
	//   2) v1.0.0-corrupt -> valid Ed25519 signature, but tampered .tar.gz bytes (MUST fail with ErrChecksumMismatch)
	//   3) v1.0.0-broken  -> valid Ed25519 + SHA-256, but new binary crashes on start (MUST auto-rollback to v0.6.0!)
	//   4) v1.0.0         -> valid Ed25519 + SHA-256 + healthy binary (MUST upgrade cleanly!)
	relRoot := filepath.Join(tmp, "gh_releases")
	makeSignedRelease := func(sub, binMarker, confVer string) string {
		dir := filepath.Join(relRoot, sub)
		_ = os.MkdirAll(dir, 0o755)
		tarPath := filepath.Join(dir, "da-wptoolkit-linux-amd64.tar.gz")
		buildTestReleaseTarGz(t, tarPath, binMarker, confVer)
		if _, _, _, sErr := SignChecksumsDir(dir, privKey); sErr != nil {
			t.Fatal(sErr)
		}
		return dir
	}

	dirForged := makeSignedRelease("forged", "HEALTHY_DAEMON_V1.0.0", "1.0.0")
	// Tamper checksums.txt.sig in forged release
	_ = os.WriteFile(filepath.Join(dirForged, "checksums.txt.sig"), []byte(strings.Repeat("ab", 64)+"\n"), 0o644)

	dirCorrupt := makeSignedRelease("corrupt", "HEALTHY_DAEMON_V1.0.0", "1.0.0")
	// Tamper tarball AFTER Ed25519 signing (simulating MITM / corrupted CDN download)
	corruptTar := filepath.Join(dirCorrupt, "da-wptoolkit-linux-amd64.tar.gz")
	origTarBytes, _ := os.ReadFile(corruptTar)
	origTarBytes[len(origTarBytes)-1] ^= 0xFF
	_ = os.WriteFile(corruptTar, origTarBytes, 0o644)

	_ = makeSignedRelease("broken", "CRASH_ON_START_V1.0.0_BROKEN", "1.0.0")
	_ = makeSignedRelease("healthy", "HEALTHY_DAEMON_V1.0.0", "1.0.0")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		if strings.HasPrefix(r.URL.Path, "/repos/shostwp-byte/da-wordpresstoolkit/releases") {
			mkAssets := func(folder string) []ghAssetDTO {
				return []ghAssetDTO{
					{Name: "da-wptoolkit-linux-amd64.tar.gz", BrowserDownloadURL: fmt.Sprintf("%s/dl/%s/da-wptoolkit-linux-amd64.tar.gz", base, folder)},
					{Name: "checksums.txt", BrowserDownloadURL: fmt.Sprintf("%s/dl/%s/checksums.txt", base, folder)},
					{Name: "checksums.txt.sig", BrowserDownloadURL: fmt.Sprintf("%s/dl/%s/checksums.txt.sig", base, folder)},
				}
			}
			rels := []ghReleaseDTO{
				{TagName: "v1.0.0", Name: "DA-WordPressToolkits v1.0.0", Body: "Production Release", Assets: mkAssets("healthy")},
				{TagName: "v1.0.0-broken", Name: "Broken Startup Simulation", Prerelease: true, Assets: mkAssets("broken")},
				{TagName: "v1.0.0-corrupt", Name: "Corrupt Tarball Simulation", Prerelease: true, Assets: mkAssets("corrupt")},
				{TagName: "v1.0.0-forged", Name: "Forged Signature Simulation", Prerelease: true, Assets: mkAssets("forged")},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rels)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/dl/") {
			relFile := strings.TrimPrefix(r.URL.Path, "/dl/")
			http.ServeFile(w, r, filepath.Join(relRoot, filepath.FromSlash(relFile)))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	mgr := NewManager(stateDir, st)
	mgr.BinPath = binPath
	mgr.PluginDir = pluginDir
	mgr.HooksBaseDir = hooksDir
	mgr.ShareDir = shareDir
	mgr.GitHubRepo = "shostwp-byte/da-wordpresstoolkit"
	mgr.PublicKeyHex = pubHex
	mgr.APIBaseURL = srv.URL
	mgr.TargetArch = "amd64"
	mgr.CurrentVersion = "v0.6.0"

	restarts := 0
	mgr.RestartDaemon = func(_ context.Context) error {
		restarts++
		return nil
	}
	mgr.HealthCheck = func(_ context.Context) error {
		raw, rErr := os.ReadFile(binPath)
		if rErr != nil {
			return rErr
		}
		if bytes.Contains(raw, []byte("CRASH_ON_START")) {
			return errors.New("simulated daemon startup crash: ping socket connection refused")
		}
		if !bytes.Contains(raw, []byte("HEALTHY_DAEMON")) {
			return errors.New("unexpected binary image")
		}
		return nil
	}

	updCfg := config.UpdaterConfig{
		GitHubRepo:      "shostwp-byte/da-wordpresstoolkit",
		UpdateChannel:   config.DefaultChannelStable,
		BackupRetention: 3,
	}

	// Case 1: Forged Ed25519 signature MUST be blocked immediately
	if _, err := mgr.PerformUpdate(context.Background(), updCfg, "v1.0.0-forged", true, false); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for forged release, got: %v", err)
	}

	// Case 2: Valid Ed25519 signature over checksums.txt, but tampered .tar.gz bytes MUST be blocked
	if _, err := mgr.PerformUpdate(context.Background(), updCfg, "v1.0.0-corrupt", true, false); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch for corrupted archive, got: %v", err)
	}

	// Case 3 (TC-10): Valid signature + SHA-256, but new binary fails healthcheck -> MUST Auto-Rollback < 10s!
	outBroken, err := mgr.PerformUpdate(context.Background(), updCfg, "v1.0.0-broken", true, false)
	if err == nil {
		t.Fatal("expected PerformUpdate to report healthcheck failure & auto-rollback")
	}
	if !outBroken.RolledBack {
		t.Fatalf("TC-10 FAILED: expected RolledBack=true, got %+v", outBroken)
	}
	if outBroken.ElapsedMs > 10000 {
		t.Fatalf("TC-10 FAILED: auto-rollback took %dms (limit 10000ms)", outBroken.ElapsedMs)
	}

	// Verify old v0.6.0 binary and plugin.conf were automatically restored and healthy!
	afterBrokenBin, _ := os.ReadFile(binPath)
	if !strings.HasPrefix(string(afterBrokenBin), "HEALTHY_DAEMON_V0.6.0") {
		t.Fatalf("TC-10 FAILED: binary was not rolled back to v0.6.0")
	}
	afterBrokenConf, _ := os.ReadFile(filepath.Join(pluginDir, "plugin.conf"))
	if !strings.Contains(string(afterBrokenConf), "version=0.6.0") {
		t.Fatalf("TC-10 FAILED: plugin.conf was not rolled back to 0.6.0: %s", string(afterBrokenConf))
	}

	// Verify Registry & live policy were 100% preserved!
	gotInst, gErr := st.GetInstance(seededInst.ID)
	if gErr != nil || gotInst.SiteTitle != "RENOLABS PRODUCTION" {
		t.Fatalf("TC-10 FAILED: Registry data lost or corrupted during auto-rollback: err=%v inst=%+v", gErr, gotInst)
	}
	gotPol, _ := os.ReadFile(filepath.Join(pluginDir, "data", "default_policy.conf"))
	if string(gotPol) != livePolicyContent {
		t.Fatalf("TC-10 FAILED: live plugin/data/default_policy.conf was overwritten!")
	}

	// Case 4: Valid healthy v1.0.0 release upgrades cleanly!
	outOK, err := mgr.PerformUpdate(context.Background(), updCfg, "", false, false)
	if err != nil {
		t.Fatalf("healthy v1.0.0 PerformUpdate failed: %v", err)
	}
	if outOK.RolledBack || outOK.TargetVersion != "v1.0.0" {
		t.Fatalf("unexpected healthy UpdateOutcome: %+v", outOK)
	}
	upgradedBin, _ := os.ReadFile(binPath)
	if !strings.HasPrefix(string(upgradedBin), "HEALTHY_DAEMON_V1.0.0") {
		t.Fatalf("expected upgraded v1.0.0 binary, got: %s", string(upgradedBin[:30]))
	}
	upgradedConf, _ := os.ReadFile(filepath.Join(pluginDir, "plugin.conf"))
	if !strings.Contains(string(upgradedConf), "version=1.0.0") {
		t.Fatalf("expected upgraded plugin.conf version=1.0.0, got: %s", string(upgradedConf))
	}
	if _, hErr := os.Stat(filepath.Join(hooksDir, "domain_create_post", "da_wp_toolkits.sh")); hErr != nil {
		t.Fatalf("expected DirectAdmin hook to be installed during update: %v", hErr)
	}

	// Case 5: Instant manual Rollback restores v0.6.0 on demand
	restoredBkp, rbErr := mgr.RestoreBackup(context.Background(), "", true)
	if rbErr != nil {
		t.Fatalf("manual RestoreBackup failed: %v", rbErr)
	}
	if restoredBkp.Version != "v0.6.0" {
		t.Fatalf("expected restored backup version v0.6.0, got %s", restoredBkp.Version)
	}
	manualRbBin, _ := os.ReadFile(binPath)
	if !strings.HasPrefix(string(manualRbBin), "HEALTHY_DAEMON_V0.6.0") {
		t.Fatalf("manual rollback did not restore v0.6.0 binary")
	}
}
