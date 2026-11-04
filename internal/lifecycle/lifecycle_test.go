package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/database"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

type mockDBProvisioner struct {
	created []string
	dropped []string
}

func (m *mockDBProvisioner) CreateDatabase(_ context.Context, acct dausers.Account, _ string) (database.Credentials, error) {
	name := acct.Username + "_wp101"
	m.created = append(m.created, name)
	return database.Credentials{
		DBName:   name,
		DBUser:   name,
		Password: "StrongRandomPassword1234",
		Host:     "localhost",
	}, nil
}

func (m *mockDBProvisioner) DropDatabase(_ context.Context, _ dausers.Account, dbName, _ string) error {
	m.dropped = append(m.dropped, dbName)
	return nil
}

func TestInstallFromLocalCoreCacheEphemeralSSOAndSafeUninstall(t *testing.T) {
	tmp := t.TempDir()
	daRoot := filepath.Join(tmp, "da_data")
	homeDir := filepath.Join(tmp, "home", "reno26")
	corePool := filepath.Join(tmp, "core_cache")

	// Seed DirectAdmin domain + classic subdomain 'shop' under public_html/shop
	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.subdomains"), []byte("shop\n"), 0o600)

	// Create sibling subdomain file inside public_html/shop/keep.txt so we verify Uninstall preserves it!
	shopSubDir := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html", "shop")
	_ = os.MkdirAll(shopSubDir, 0o755)
	_ = os.WriteFile(filepath.Join(shopSubDir, "keep.txt"), []byte("shop subdomain data"), 0o644)

	// Seed Local Verified Core Cache (latest-vi)
	cachedWP := filepath.Join(corePool, "latest-vi")
	_ = os.MkdirAll(filepath.Join(cachedWP, "wp-includes"), 0o755)
	_ = os.WriteFile(filepath.Join(cachedWP, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '6.7.1';\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cachedWP, "index.php"), []byte("<?php // Silence is golden.\n"), 0o644)

	st, err := store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	pol := config.NewPolicyStore(filepath.Join(tmp, "pdata"), "")
	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	mockDB := &mockDBProvisioner{}

	var recordedSpecs []wpcli.ExecSpec
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", corePool)
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		recordedSpecs = append(recordedSpecs, spec)
		return "Success", "", nil
	}

	mgr := NewManager(domRes, mockDB, wpRunner, st, pol, corePool)
	mgr.ReapDelayOverride = 350 * time.Millisecond

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir, Package: "pro"}

	// 1. Weak admin username 'admin' MUST be rejected
	if _, err := mgr.Install(context.Background(), acct, InstallRequest{
		Domain:    "renolabs-audio.com",
		AdminUser: "admin",
	}, nil); err == nil {
		t.Fatal("expected weak username 'admin' to be blocked")
	}

	// 2. 1-Click Install succeeds in milliseconds from Local Core Cache, never leaking real password in cmdline
	secretAdminPass := "MySuperSecretPass!2026"
	res, err := mgr.Install(context.Background(), acct, InstallRequest{
		Domain:        "renolabs-audio.com",
		SiteTitle:     "RENOLABS",
		AdminUser:     "radmin",
		AdminPassword: secretAdminPass,
		SetID:         "set_lscache_speed",
	}, nil)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if !res.PopulatedFromCorePool || res.Instance.WPVersion != "6.7.1" || res.AppliedPluginsCount != 1 {
		t.Fatalf("unexpected InstallResult: %+v", res)
	}

	// Verify real admin password NEVER appeared in any command-line argument!
	for _, sp := range recordedSpecs {
		if strings.Contains(strings.Join(sp.Args, " "), secretAdminPass) {
			t.Fatal("SECURITY FAILURE: plaintext admin password leaked into process command-line arguments!")
		}
	}

	// Verify wp-config.php contains isolated WP_CACHE_KEY_SALT and DISALLOW_FILE_EDIT
	cfgRaw, err := os.ReadFile(filepath.Join(res.Instance.DocRoot, "wp-config.php"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfgRaw), "WP_CACHE_KEY_SALT") || !strings.Contains(string(cfgRaw), "DISALLOW_FILE_EDIT") {
		t.Fatalf("wp-config.php missing expected hardening constants:\n%s", string(cfgRaw))
	}

	// 3. Test Zero-Residue Ephemeral 1-Click SSO (creates MU-plugin and auto-reaps on expiry!)
	ssoRes, err := mgr.CreateEphemeralSSO(acct, res.Instance, "radmin")
	if err != nil || !strings.Contains(ssoRes.LoginURL, "https://renolabs-audio.com/wp-login.php?dawptk_sso=") {
		t.Fatalf("CreateEphemeralSSO failed: err=%v res=%+v", err, ssoRes)
	}
	muEntries, _ := os.ReadDir(filepath.Join(res.Instance.DocRoot, "wp-content", "mu-plugins"))
	if len(muEntries) != 1 {
		t.Fatalf("expected 1 ephemeral SSO mu-plugin file, got %d", len(muEntries))
	}
	reapDeadline := time.Now().Add(2 * time.Second)
	var muAfterReap []os.DirEntry
	for {
		muAfterReap, _ = os.ReadDir(filepath.Join(res.Instance.DocRoot, "wp-content", "mu-plugins"))
		if len(muAfterReap) == 0 || time.Now().After(reapDeadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(muAfterReap) != 0 {
		t.Fatalf("expected background reaper to remove expired SSO mu-plugin, still found %d files", len(muAfterReap))
	}

	// 4. Uninstall removes main domain WP files + drops DB while PRESERVING sibling subdomain public_html/shop!
	if err := mgr.Uninstall(context.Background(), acct, res.Instance.ID, true); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(shopSubDir, "keep.txt")); err != nil {
		t.Fatalf("CRITICAL: Uninstall wiped sibling subdomain public_html/shop! err=%v", err)
	}
	if len(mockDB.dropped) != 1 {
		t.Fatalf("expected database to be dropped on uninstall, dropped=%v", mockDB.dropped)
	}
}
