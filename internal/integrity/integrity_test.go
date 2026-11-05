package integrity

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

func setupTestWPFixture(t *testing.T) (tmp string, acct dausers.Account, st *store.Store, shield *Shield, inst store.InstanceRecord) {
	t.Helper()
	tmp = t.TempDir()

	daData := filepath.Join(tmp, "da_data")
	passwdPath := filepath.Join(tmp, "passwd")
	homeDir := filepath.Join(tmp, "home", "reno26")
	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")

	_ = os.MkdirAll(filepath.Join(daData, "users", "reno26"), 0o755)
	_ = os.WriteFile(filepath.Join(daData, "users", "reno26", "user.conf"), []byte("package=pro\nsuspended=no\n"), 0o644)
	_ = os.WriteFile(passwdPath, []byte("reno26:x:1005:1005::"+homeDir+":/bin/bash\n"), 0o644)

	users := dausers.NewRegistry(daData, passwdPath)
	if err := users.Reload(); err != nil {
		t.Fatal(err)
	}
	var ok bool
	acct, ok = users.LookupByUsername("reno26")
	if !ok {
		t.Fatal("failed to lookup test user reno26")
	}

	// Build realistic WordPress Core tree
	coreFiles := map[string]string{
		"index.php":                 "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
		"wp-load.php":               "<?php\n/** Bootstrap file for setting the ABSPATH constant */\nif ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n",
		"wp-settings.php":           "<?php\n// Verified wp-settings.php\n",
		"wp-includes/version.php":   "<?php\n$wp_version = '6.7.1';\n",
		"wp-includes/functions.php": "<?php\nfunction wp_clean_core_helper() { return true; }\n",
		"wp-admin/admin.php":        "<?php\n// Verified wp-admin/admin.php\n",
	}
	for rel, body := range coreFiles {
		p := filepath.Join(docRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "uploads"), 0o755)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte("<?php\ndefine('DB_NAME','reno26_wp');\n"), 0o600)

	var err error
	st, err = store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	pol := config.NewPolicyStore(filepath.Join(tmp, "policy"), filepath.Join(tmp, "updater.conf"))

	shield, err = NewShield(st, users, pol, ShieldConfig{
		StateDir:        filepath.Join(tmp, "state"),
		CoreCacheDir:    filepath.Join(tmp, "core_cache"),
		QuarantineDir:   filepath.Join(tmp, "quarantine"),
		PollInterval:    20 * time.Millisecond,
		AuditInterval:   5 * time.Minute,
		ThrashThreshold: 5,
		ThrashWindow:    30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed clean Core Cache from verified tree
	if _, err := shield.Cache.SeedVerifiedTree("6.7.1", "en_US", docRoot); err != nil {
		t.Fatal(err)
	}

	inst, err = st.UpsertInstance(store.InstanceRecord{
		Owner:              "reno26",
		OwnerUID:           1005,
		Domain:             "renolabs-audio.com",
		DocRoot:            docRoot,
		WPVersion:          "6.7.1",
		Locale:             "en_US",
		CoreShieldMode:     config.ShieldModeAutoHeal,
		CoreIntegrityClean: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		// Ensure read-only locks are cleared before t.TempDir() cleanup on Windows
		_ = shield.Locker.UnlockInstance(acct, inst, nil)
	})

	return tmp, acct, st, shield, inst
}

func TestTC04_RealTimeAutoHealAndQuarantineUnder1Second(t *testing.T) {
	_, acct, _, shield, inst := setupTestWPFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := shield.Start(ctx); err != nil {
		t.Fatalf("Shield.Start: %v", err)
	}

	wpLoadPath := filepath.Join(inst.DocRoot, "wp-load.php")
	origBytes, err := os.ReadFile(wpLoadPath)
	if err != nil {
		t.Fatal(err)
	}
	origSHA := sha256.Sum256(origBytes)

	backdoorPath := filepath.Join(inst.DocRoot, "wp-includes", "backdoor.php")

	// Inject unauthorized code into wp-load.php AND drop wp-includes/backdoor.php simultaneously!
	attackStart := time.Now()
	injected := string(origBytes) + "\n/* tc04_unauthorized_core_patch */\n$dawptk_tamper_flag = 1;\n"
	if err := os.WriteFile(wpLoadPath, []byte(injected), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backdoorPath, []byte("<?php /* tc04_rogue_executable_probe */ $rogue = true; ?>\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Poll until both anomalies are healed/quarantined, enforcing strict < 1s SLA (TC-04)
	deadline := time.Now().Add(950 * time.Millisecond)
	healedOK := false
	backdoorGone := false

	for time.Now().Before(deadline) {
		curBytes, rErr := os.ReadFile(wpLoadPath)
		if rErr == nil {
			curSHA := sha256.Sum256(curBytes)
			healedOK = (curSHA == origSHA)
		}
		_, bErr := os.Stat(backdoorPath)
		backdoorGone = errors.Is(bErr, os.ErrNotExist)
		if healedOK && backdoorGone {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	elapsed := time.Since(attackStart)

	if !healedOK || !backdoorGone || elapsed >= time.Second {
		t.Fatalf("TC-04 FAILED: healedOK=%v backdoorGone=%v elapsed=%v (SLA < 1s)", healedOK, backdoorGone, elapsed)
	}

	// Verify Quarantine Vault stored both items with full Diff preview
	qItems := shield.Quarantine.List("reno26", inst.ID, false, true)
	if len(qItems) < 2 {
		t.Fatalf("expected >= 2 quarantined artifacts (wp-load.php + backdoor.php), got %d", len(qItems))
	}

	var foundWPLoadDiff, foundBackdoor bool
	var backdoorQID string
	for _, it := range qItems {
		if it.RelPath == "wp-load.php" && strings.Contains(it.DiffPreview, "+$dawptk_tamper_flag = 1;") {
			foundWPLoadDiff = true
		}
		if it.RelPath == "wp-includes/backdoor.php" && it.Reason == ReasonUnknownExecutable {
			foundBackdoor = true
			backdoorQID = it.ID
		}
	}
	if !foundWPLoadDiff {
		t.Fatal("TC-04 FAILED: Quarantine Diff Viewer missing injected line diff for wp-load.php")
	}
	if !foundBackdoor {
		t.Fatal("TC-04 FAILED: Quarantine Vault missing wp-includes/backdoor.php record")
	}

	// Verify RestoreItem + Whitelist exemption works when customer explicitly restores a custom file
	if _, err := shield.Quarantine.RestoreItem(acct, inst, backdoorQID, true, false); err != nil {
		t.Fatalf("RestoreItem failed: %v", err)
	}
	if !shield.Quarantine.IsWhitelisted(inst.ID, "wp-includes/backdoor.php") {
		t.Fatal("expected restored path to be added to Core Whitelist")
	}
	time.Sleep(70 * time.Millisecond)
	if _, err := os.Stat(backdoorPath); err != nil {
		t.Fatalf("whitelisted restored file must NOT be re-quarantined: %v", err)
	}
}

func TestTC05_AntiThrashingEscalatesToFortressCoreLockAfter5Overwrites(t *testing.T) {
	_, _, st, shield, inst := setupTestWPFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := shield.Start(ctx); err != nil {
		t.Fatal(err)
	}

	indexPath := filepath.Join(inst.DocRoot, "index.php")
	cleanIndex, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}

	blockedCount := 0
	for attempt := 1; attempt <= 10; attempt++ {
		payload := []byte("<?php /* MALWARE LOOP #" + string(rune('0'+attempt)) + " */ ?>\n")
		wErr := os.WriteFile(indexPath, payload, 0o644)
		if wErr != nil {
			if errors.Is(wErr, os.ErrPermission) {
				blockedCount++
				continue
			}
			t.Fatalf("unexpected write error on attempt %d: %v", attempt, wErr)
		}

		// Wait briefly for real-time watcher to heal this overwrite before next loop iteration
		deadline := time.Now().Add(3500 * time.Millisecond)
		for time.Now().Before(deadline) {
			cur, _ := os.ReadFile(indexPath)
			curInst, _ := st.GetInstance(inst.ID)
			qCount := len(shield.Quarantine.List("reno26", inst.ID, false, false))
			if bytes.Equal(cur, cleanIndex) && qCount >= attempt {
				if attempt >= 5 && curInst.CoreShieldMode == config.ShieldModeFortressLock {
					break
				}
				if attempt < 5 {
					break
				}
			}
			time.Sleep(15 * time.Millisecond)
		}
	}

	updatedInst, err := st.GetInstance(inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updatedInst.CoreShieldMode != config.ShieldModeFortressLock {
		t.Fatalf("TC-05 FAILED: expected CoreShieldMode to auto-escalate to fortress_lock, got %s", updatedInst.CoreShieldMode)
	}
	if blockedCount != 5 {
		t.Fatalf("TC-05 FAILED: expected overwrites #6..#10 (5 attempts) to be blocked by OS Permission denied, got %d blocked", blockedCount)
	}

	finalBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(finalBytes, cleanIndex) {
		t.Fatal("TC-05 FAILED: index.php must remain 100% clean under Fortress Core Lock")
	}

	events := st.RecentSecurityEvents(20)
	foundThrashEvent := false
	for _, ev := range events {
		if ev.Category == "core_thrash_lock" && ev.InstanceID == inst.ID {
			foundThrashEvent = true
			break
		}
	}
	if !foundThrashEvent {
		t.Fatal("TC-05 FAILED: expected critical core_thrash_lock security audit event")
	}
}

func TestTC06_DirectAdminBackupPreAndPostHooksWithFortressCoreLock(t *testing.T) {
	tmp, acct, _, shield, inst := setupTestWPFixture(t)

	ctx := context.Background()
	lockedInst, err := shield.SetMode(ctx, acct, inst.ID, config.ShieldModeFortressLock, true)
	if err != nil {
		t.Fatalf("SetMode(fortress_lock): %v", err)
	}
	if lockedInst.CoreShieldMode != config.ShieldModeFortressLock {
		t.Fatalf("expected fortress_lock mode, got %s", lockedInst.CoreShieldMode)
	}

	indexPath := filepath.Join(inst.DocRoot, "index.php")
	if err := os.WriteFile(indexPath, []byte("hacked"), 0o644); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("expected Permission denied while Fortress Lock is active, got: %v", err)
	}

	// Customer wp-content/uploads and .htaccess MUST remain writable even while Fortress Lock is active!
	uploadSample := filepath.Join(inst.DocRoot, "wp-content", "uploads", "product.jpg")
	if err := os.WriteFile(uploadSample, []byte("JPEG"), 0o644); err != nil {
		t.Fatalf("wp-content/uploads must stay writable under Fortress Lock: %v", err)
	}
	htPath := filepath.Join(inst.DocRoot, ".htaccess")
	if err := os.WriteFile(htPath, []byte("# LSCache\n"), 0o644); err != nil {
		t.Fatalf(".htaccess must stay writable in-place under Fortress Lock: %v", err)
	}

	// Step 1: Simulate DirectAdmin user_backup_pre.sh hook
	unlockedIDs, err := shield.PrepareUserBackup("reno26")
	if err != nil {
		t.Fatalf("PrepareUserBackup failed: %v", err)
	}
	if len(unlockedIDs) != 1 || unlockedIDs[0] != inst.ID {
		t.Fatalf("expected [%s] to be unlocked for backup, got %v", inst.ID, unlockedIDs)
	}

	// Verify DirectAdmin backup archiver can read/archive every file and modify/touch under user permissions cleanly
	backupTarPath := filepath.Join(tmp, "reno26_backup.tar.gz")
	if err := createTestTarGz(backupTarPath, acct.HomeDir); err != nil {
		t.Fatalf("TC-06 FAILED: DirectAdmin backup archive creation failed: %v", err)
	}

	// Step 2: Simulate DirectAdmin user_backup_post.sh hook
	relockedIDs, err := shield.FinishUserBackup("reno26")
	if err != nil {
		t.Fatalf("FinishUserBackup failed: %v", err)
	}
	if len(relockedIDs) != 1 || relockedIDs[0] != inst.ID {
		t.Fatalf("expected [%s] to be re-locked after backup, got %v", inst.ID, relockedIDs)
	}

	// Verify Fortress Core Lock is back in force immediately after backup completes!
	if err := os.WriteFile(indexPath, []byte("hacked_post_backup"), 0o644); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("TC-06 FAILED: expected Fortress Core Lock to block writes after FinishUserBackup, got: %v", err)
	}
}

func TestVerifiedCoreCacheDownloadsAndRejectsTamperedTarball(t *testing.T) {
	tmp := t.TempDir()

	files := map[string]string{
		"index.php":               "<?php // Official WP 6.7.2\n",
		"wp-includes/version.php": "<?php $wp_version = '6.7.2';\n",
		"wp-content/hello.php":    "<?php // Ignored wp-content plugin\n",
	}

	checksums := make(map[string]string)
	for rel, content := range files {
		sum := md5.Sum([]byte(content))
		checksums[rel] = hex.EncodeToString(sum[:])
	}

	var corruptArchive atomic.Bool
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/checksums") {
			_ = json.NewEncoder(w).Encode(map[string]any{"checksums": checksums})
			return
		}
		if r.URL.Path == "/wordpress-6.7.2.tar.gz" {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			for rel, content := range files {
				body := []byte(content)
				if corruptArchive.Load() && rel == "index.php" {
					body = []byte("<?php // MITM TAMPERED!\n")
				}
				_ = tw.WriteHeader(&tar.Header{
					Name: "wordpress/" + rel,
					Mode: 0o644,
					Size: int64(len(body)),
				})
				_, _ = tw.Write(body)
			}
			_ = tw.Close()
			_ = gz.Close()
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(buf.Bytes())
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer apiSrv.Close()

	cache := NewCoreCache(filepath.Join(tmp, "cache"))
	cache.ChecksumsAPIBase = apiSrv.URL + "/checksums"
	cache.DownloadBaseURL = apiSrv.URL

	// 1. Tampered tarball MUST be rejected!
	corruptArchive.Store(true)
	if _, err := cache.EnsureVerifiedCore(context.Background(), "6.7.2", "vi"); err == nil {
		t.Fatal("expected MITM-corrupted WordPress tarball to fail official MD5 verification")
	}

	// 2. Authentic tarball MUST verify and cache cleanly (excluding wp-content/*)!
	corruptArchive.Store(false)
	manifest, err := cache.EnsureVerifiedCore(context.Background(), "6.7.2", "vi")
	if err != nil {
		t.Fatalf("EnsureVerifiedCore failed on authentic archive: %v", err)
	}
	if len(manifest.Files) != 2 {
		t.Fatalf("expected 2 non-wp-content Core files in manifest, got %d", len(manifest.Files))
	}
	if _, hasWPContent := manifest.Files["wp-content/hello.php"]; hasWPContent {
		t.Fatal("wp-content/* files must never be enforced as immutable Core files")
	}
}

func TestNativeWPAdminCoreUpgradeDoesNotRevertOrEscalateToFortressLock(t *testing.T) {
	tmp, _, st, shield, inst := setupTestWPFixture(t)

	// Prepare verified WordPress 6.7.2 tree (7 changed/added Core files > ThrashThreshold=5)
	wp672Dir := filepath.Join(tmp, "wp672_clean")
	wp672Files := map[string]string{
		"index.php":                   "<?php\n// WP 6.7.2\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
		"wp-load.php":                 "<?php\n// WP 6.7.2\nif ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n",
		"wp-settings.php":             "<?php\n// Verified wp-settings.php 6.7.2\n",
		"wp-includes/version.php":     "<?php\n$wp_version = '6.7.2';\n",
		"wp-includes/functions.php":   "<?php\nfunction wp_clean_core_helper() { return '6.7.2'; }\n",
		"wp-includes/block-hooks.php": "<?php\nfunction wp_new_672_block_hook() { return true; }\n",
		"wp-admin/admin.php":          "<?php\n// Verified wp-admin/admin.php 6.7.2\n",
	}
	for rel, body := range wp672Files {
		p := filepath.Join(wp672Dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := shield.Cache.SeedVerifiedTree("6.7.2", "en_US", wp672Dir); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := shield.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Simulate native wp-admin Core_Upgrader (.maintenance -> unpack Core -> remove .maintenance)
	maintPath := filepath.Join(inst.DocRoot, ".maintenance")
	if err := os.WriteFile(maintPath, []byte("<?php $upgrading = 1730000000; ?>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(35 * time.Millisecond)

	for rel, body := range wp672Files {
		p := filepath.Join(inst.DocRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(35 * time.Millisecond)
	_ = os.Remove(maintPath)

	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		cur, err := st.GetInstance(inst.ID)
		if err == nil && cur.WPVersion == "6.7.2" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(80 * time.Millisecond)

	updated, err := st.GetInstance(inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CoreShieldMode != config.ShieldModeAutoHeal {
		t.Fatalf("expected CoreShieldMode to remain auto_heal after native wp-admin Core upgrade, got %s", updated.CoreShieldMode)
	}
	if updated.WPVersion != "6.7.2" {
		t.Fatalf("expected WPVersion to adopt 6.7.2, got %s", updated.WPVersion)
	}
	if qItems := shield.Quarantine.List("reno26", inst.ID, false, false); len(qItems) != 0 {
		t.Fatalf("expected 0 false-positive quarantine items after legitimate Core upgrade, got %d", len(qItems))
	}
	verOnDisk, err := os.ReadFile(filepath.Join(inst.DocRoot, "wp-includes", "version.php"))
	if err != nil || !strings.Contains(string(verOnDisk), "6.7.2") {
		t.Fatalf("expected wp-includes/version.php to stay at 6.7.2, got: %s", string(verOnDisk))
	}
	if _, err := os.Stat(filepath.Join(inst.DocRoot, "wp-includes", "block-hooks.php")); err != nil {
		t.Fatalf("expected newly added official Core file wp-includes/block-hooks.php to remain intact: %v", err)
	}
}

func TestFortressCoreLockInstallsDirectFSBridgeAndUnlockCleansUp(t *testing.T) {
	_, acct, _, shield, inst := setupTestWPFixture(t)
	ctx := context.Background()

	if _, err := shield.SetMode(ctx, acct, inst.ID, config.ShieldModeFortressLock, true); err != nil {
		t.Fatalf("SetMode(fortress_lock): %v", err)
	}

	upgradeDir := filepath.Join(inst.DocRoot, "wp-content", "upgrade")
	if st, err := os.Stat(upgradeDir); err != nil || !st.IsDir() {
		t.Fatalf("expected wp-content/upgrade directory to exist for WP_Upgrader: %v", err)
	}

	muBridge := filepath.Join(inst.DocRoot, "wp-content", "mu-plugins", fortressDirectFSMUFile)
	rawMU, err := os.ReadFile(muBridge)
	if err != nil {
		t.Fatalf("expected Fortress direct-FS MU bridge %s to exist: %v", muBridge, err)
	}
	if !strings.Contains(string(rawMU), "filesystem_method") || !strings.Contains(string(rawMU), "'direct'") {
		t.Fatal("expected MU bridge to register filesystem_method -> 'direct' filter")
	}

	if _, err := shield.SetMode(ctx, acct, inst.ID, config.ShieldModeAutoHeal, true); err != nil {
		t.Fatalf("SetMode(auto_heal): %v", err)
	}
	if _, err := os.Stat(muBridge); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected Fortress direct-FS MU bridge to be removed upon UnlockInstance, got err=%v", err)
	}
	indexPath := filepath.Join(inst.DocRoot, "index.php")
	orig, _ := os.ReadFile(indexPath)
	if err := os.WriteFile(indexPath, orig, 0o644); err != nil {
		t.Fatalf("expected Core files to be customer-writable again after UnlockInstance: %v", err)
	}
}

func TestStartupMigrationUnlocksPriorThrashLockedInstances(t *testing.T) {
	tmp, acct, st, shield, inst := setupTestWPFixture(t)

	// Simulate an instance previously auto-locked by false-positive core_thrash_lock
	manifest, _ := shield.Cache.GetCachedManifest(inst.WPVersion, inst.Locale)
	if err := shield.Locker.LockInstance(acct, inst, manifest); err != nil {
		t.Fatal(err)
	}
	inst.CoreShieldMode = config.ShieldModeFortressLock
	if _, err := st.UpsertInstance(inst); err != nil {
		t.Fatal(err)
	}
	st.RecordSecurityEvent(store.SecurityAuditEvent{
		Severity:   "critical",
		Category:   "core_thrash_lock",
		Owner:      inst.Owner,
		InstanceID: inst.ID,
		Message:    "Anti-Thrashing guard triggered",
	})

	// Simulate daemon restart (re-opening Store from disk so security_events.jsonl is tested too!)
	reopenedStore, err := store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	users := dausers.NewRegistry(filepath.Join(tmp, "da_data"), filepath.Join(tmp, "passwd"))
	_ = users.Reload()
	pol := config.NewPolicyStore(filepath.Join(tmp, "policy"), filepath.Join(tmp, "updater.conf"))

	restartedShield, err := NewShield(reopenedStore, users, pol, ShieldConfig{
		StateDir:        filepath.Join(tmp, "state"),
		CoreCacheDir:    filepath.Join(tmp, "core_cache"),
		QuarantineDir:   filepath.Join(tmp, "quarantine"),
		PollInterval:    50 * time.Millisecond,
		AuditInterval:   5 * time.Minute,
		ThrashThreshold: 5,
		ThrashWindow:    30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := restartedShield.Start(ctx); err != nil {
		t.Fatal(err)
	}

	migrated, err := reopenedStore.GetInstance(inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.CoreShieldMode != config.ShieldModeAutoHeal {
		t.Fatalf("expected prior thrash-locked site to migrate back to auto_heal on startup, got %s", migrated.CoreShieldMode)
	}
	indexPath := filepath.Join(inst.DocRoot, "index.php")
	orig, _ := os.ReadFile(indexPath)
	if err := os.WriteFile(indexPath, orig, 0o644); err != nil {
		t.Fatalf("expected Core index.php to be unlocked and writable after migration: %v", err)
	}
}

func createTestTarGz(destTarGz, sourceDir string) error {
	f, err := os.Create(destTarGz)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.WalkDir(sourceDir, func(cur string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, cur)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		src, err := os.Open(cur)
		if err != nil {
			return err
		}
		defer src.Close()

		if err := tw.WriteHeader(&tar.Header{
			Name: filepath.ToSlash(rel),
			Mode: int64(info.Mode().Perm()),
			Size: info.Size(),
		}); err != nil {
			return err
		}
		_, err = io.Copy(tw, src)
		return err
	})
}
