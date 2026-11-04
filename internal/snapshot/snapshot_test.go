package snapshot

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

func setupSnapshotFixture(t *testing.T, maxSnapshotsPerSite int) (dausers.Account, store.InstanceRecord, *Manager, *string) {
	t.Helper()
	tmp := t.TempDir()

	homeDir := filepath.Join(tmp, "home", "reno26")
	mainDocRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	shopSubDocRoot := filepath.Join(mainDocRoot, "shop")
	daDataRoot := filepath.Join(tmp, "da_data")
	userDir := filepath.Join(daDataRoot, "users", "reno26")
	domainsConfDir := filepath.Join(userDir, "domains")
	policyDir := filepath.Join(tmp, "policies")
	stateDir := filepath.Join(tmp, "state")

	for _, d := range []string{
		filepath.Join(mainDocRoot, "wp-content", "uploads"),
		shopSubDocRoot,
		domainsConfDir,
		policyDir,
		stateDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// DirectAdmin domain + classic subdomain metadata (`shop.renolabs-audio.com` -> `public_html/shop`)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=renolabs-audio.com\npackage=pro\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domainsConfDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domainsConfDir, "renolabs-audio.com.subdomains"), []byte("shop\n"), 0o600)

	// Sibling classic subdomain files that MUST NEVER be overwritten or included in parent snapshot
	if err := os.WriteFile(filepath.Join(shopSubDocRoot, "shop-marker.txt"), []byte("sibling-subdomain-v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Main WordPress instance files
	if err := os.WriteFile(filepath.Join(mainDocRoot, "wp-config.php"), []byte("<?php define('DB_NAME','reno26_wp1');\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mainDocRoot, "index.php"), []byte("<?php // Original WP Front Controller v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mainDocRoot, "wp-content", "uploads", "banner.txt"), []byte("RENOLABS-BANNER-V1"), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	policies := config.NewPolicyStore(policyDir, filepath.Join(policyDir, "updater.conf"))
	pol := config.DefaultPackagePolicy()
	pol.MaxSnapshotsPerSite = maxSnapshotsPerSite
	if err := policies.SavePackagePolicy("pro", pol); err != nil {
		t.Fatal(err)
	}

	acct := dausers.Account{
		Username: "reno26",
		UID:      1026,
		GID:      1026,
		HomeDir:  homeDir,
		Package:  "pro",
	}

	inst, err := st.UpsertInstance(store.InstanceRecord{
		ID:          "wp_snaptest0001",
		Owner:       acct.Username,
		OwnerUID:    acct.UID,
		Domain:      "renolabs-audio.com",
		DomainType:  dadomains.DomainTypeMain,
		DocRoot:     mainDocRoot,
		SiteURL:     "https://renolabs-audio.com",
		SiteTitle:   "RENOLABS",
		WPVersion:   "6.7.1",
		DBName:      "reno26_wp1",
		DBUser:      "reno26_wp1",
		TablePrefix: "wp_",
	})
	if err != nil {
		t.Fatal(err)
	}

	liveDBSQL := "CREATE TABLE `wp_options` (`option_name` varchar(191), `option_value` longtext);\nINSERT INTO `wp_options` VALUES ('blogname','RENOLABS V1');\n"

	runner := wpcli.NewRunner("/usr/local/bin/wp", filepath.Join(tmp, "core-cache"))
	runner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		for i := 0; i < len(spec.Args); i++ {
			if spec.Args[i] == "db" && i+2 < len(spec.Args) {
				sub := spec.Args[i+1]
				sqlFile := spec.Args[i+2]
				switch sub {
				case "export":
					if err := os.WriteFile(sqlFile, []byte(liveDBSQL), 0o600); err != nil {
						return "", err.Error(), err
					}
					return "Success: Exported to " + sqlFile, "", nil
				case "import":
					raw, err := os.ReadFile(sqlFile)
					if err != nil {
						return "", err.Error(), err
					}
					liveDBSQL = string(raw)
					return "Success: Imported from " + sqlFile, "", nil
				}
			}
		}
		return "Success", "", nil
	}

	domResolver := dadomains.NewResolver(daDataRoot, daphp.NewResolver("", ""))
	mgr, err := NewManager(stateDir, domResolver, runner, st, policies)
	if err != nil {
		t.Fatal(err)
	}
	// Force pure-Go RFC 8878 Zstd path in unit test to validate deterministic `.tar.zst` framing everywhere
	mgr.ZstdBin = filepath.Join(tmp, "nonexistent-zstd")

	return acct, inst, mgr, &liveDBSQL
}

func TestCreateAndRestoreZstdSnapshotPreservesSiblingSubdomainAndDB(t *testing.T) {
	acct, inst, mgr, liveDBSQL := setupSnapshotFixture(t, 5)
	ctx := context.Background()

	snap, err := mgr.CreateSnapshot(ctx, acct, CreateRequest{
		InstanceID: inst.ID,
		Note:       "Before theme redesign",
	}, nil)
	if err != nil {
		t.Fatalf("CreateSnapshot failed: %v", err)
	}
	if !strings.HasSuffix(snap.FileName, ".tar.zst") || snap.SizeBytes <= 0 {
		t.Fatalf("unexpected snapshot metadata: %+v", snap)
	}

	archivePath, _, err := mgr.ResolveDownloadPath(acct, inst.ID, snap.ID)
	if err != nil {
		t.Fatalf("ResolveDownloadPath failed: %v", err)
	}
	rawArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawArchive) < 4 || !bytes.Equal(rawArchive[:4], ZstdMagicBytes) {
		t.Fatalf("expected RFC 8878 Zstandard magic header 28 B5 2F FD, got %x", rawArchive[:4])
	}

	// Mutate main WordPress files, add a rogue file, mutate DB, and update sibling subdomain marker
	_ = os.WriteFile(filepath.Join(inst.DocRoot, "index.php"), []byte("<?php // BROKEN INDEX V2"), 0o644)
	_ = os.Remove(filepath.Join(inst.DocRoot, "wp-content", "uploads", "banner.txt"))
	_ = os.WriteFile(filepath.Join(inst.DocRoot, "rogue-extra.php"), []byte("<?php // stale file"), 0o644)
	*liveDBSQL = "INSERT INTO `wp_options` VALUES ('blogname','CORRUPTED V2');\n"

	shopMarkerPath := filepath.Join(inst.DocRoot, "shop", "shop-marker.txt")
	_ = os.WriteFile(shopMarkerPath, []byte("sibling-subdomain-v2-live"), 0o644)

	suppressedCalled := false
	mgr.WithShieldSuppression = func(_ dausers.Account, _ store.InstanceRecord, fn func() error) error {
		suppressedCalled = true
		return fn()
	}

	res, err := mgr.RestoreSnapshot(ctx, acct, inst.ID, snap.ID, nil)
	if err != nil {
		t.Fatalf("RestoreSnapshot failed: %v", err)
	}
	if !suppressedCalled || !res.DatabaseRestored {
		t.Fatalf("expected shield suppression & DB restore, got suppressed=%v dbRestored=%v", suppressedCalled, res.DatabaseRestored)
	}

	restoredIndex, err := os.ReadFile(filepath.Join(inst.DocRoot, "index.php"))
	if err != nil || !strings.Contains(string(restoredIndex), "Original WP Front Controller v1") {
		t.Fatalf("index.php was not restored cleanly: %q (err=%v)", string(restoredIndex), err)
	}
	restoredBanner, err := os.ReadFile(filepath.Join(inst.DocRoot, "wp-content", "uploads", "banner.txt"))
	if err != nil || string(restoredBanner) != "RENOLABS-BANNER-V1" {
		t.Fatalf("banner.txt was not restored: %q (err=%v)", string(restoredBanner), err)
	}
	if _, err := os.Stat(filepath.Join(inst.DocRoot, "rogue-extra.php")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale rogue-extra.php to be cleaned during restore, stat err=%v", err)
	}
	if !strings.Contains(*liveDBSQL, "RENOLABS V1") {
		t.Fatalf("expected MariaDB state to revert to RENOLABS V1, got %q", *liveDBSQL)
	}

	// Sibling classic subdomain `public_html/shop` MUST remain untouched!
	shopMarkerAfter, err := os.ReadFile(shopMarkerPath)
	if err != nil || string(shopMarkerAfter) != "sibling-subdomain-v2-live" {
		t.Fatalf("sibling classic subdomain was damaged by parent restore: %q (err=%v)", string(shopMarkerAfter), err)
	}
}

func TestSnapshotAutoRotationAndDelete(t *testing.T) {
	acct, inst, mgr, _ := setupSnapshotFixture(t, 3)
	ctx := context.Background()

	var createdIDs []string
	var createdPaths []string
	for i := 1; i <= 5; i++ {
		rec, err := mgr.CreateSnapshot(ctx, acct, CreateRequest{
			InstanceID: inst.ID,
			Note:       "rot",
		}, nil)
		if err != nil {
			t.Fatalf("CreateSnapshot #%d failed: %v", i, err)
		}
		createdIDs = append(createdIDs, rec.ID)
		createdPaths = append(createdPaths, filepath.Join(acct.HomeDir, SnapshotsSubdirName, inst.ID, rec.FileName))
		time.Sleep(5 * time.Millisecond)
	}

	list, err := mgr.ListSnapshots(acct, inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected MaxSnapshotsPerSite=3 retained snapshots, got %d", len(list))
	}

	// Oldest 2 archives must be deleted from disk; newest 3 must remain
	for i := 0; i < 2; i++ {
		if _, err := os.Stat(createdPaths[i]); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected pruned archive #%d (%s) to be removed from disk", i+1, createdPaths[i])
		}
	}
	for i := 2; i < 5; i++ {
		if _, err := os.Stat(createdPaths[i]); err != nil {
			t.Fatalf("expected retained archive #%d (%s) on disk: %v", i+1, createdPaths[i], err)
		}
	}

	reloadedInst, err := mgr.Store.GetInstanceForOwner(inst.ID, acct.Username)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedInst.SnapshotCount != 3 {
		t.Fatalf("expected InstanceRecord.SnapshotCount == 3, got %d", reloadedInst.SnapshotCount)
	}

	if err := mgr.DeleteSnapshot(acct, inst.ID, createdIDs[4]); err != nil {
		t.Fatalf("DeleteSnapshot failed: %v", err)
	}
	reloadedInst, _ = mgr.Store.GetInstanceForOwner(inst.ID, acct.Username)
	if reloadedInst.SnapshotCount != 2 {
		t.Fatalf("expected InstanceRecord.SnapshotCount == 2 after delete, got %d", reloadedInst.SnapshotCount)
	}
}

func TestTC02_SnapshotBlocksSymlinkEscapeInsideDocRoot(t *testing.T) {
	acct, inst, mgr, _ := setupSnapshotFixture(t, 5)
	ctx := context.Background()

	outsideSecretDir := filepath.Join(filepath.Dir(acct.HomeDir), "outside_secret_dir")
	if err := os.MkdirAll(outsideSecretDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideSecretDir, "secret.txt"), []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	evilLink := filepath.Join(inst.DocRoot, "wp-content", "evil-link")
	symErr := os.Symlink(outsideSecretDir, evilLink)
	if symErr != nil && runtime.GOOS == "windows" {
		symErr = exec.Command("cmd", "/c", "mklink", "/J", evilLink, outsideSecretDir).Run()
	}
	if symErr != nil {
		t.Skipf("OS does not allow symlink/junction creation in test environment: %v", symErr)
	}
	defer func() { _ = os.Remove(evilLink) }()

	_, err := mgr.CreateSnapshot(ctx, acct, CreateRequest{InstanceID: inst.ID}, nil)
	if !errors.Is(err, fsguard.ErrSymlinkBlocked) {
		t.Fatalf("TC-02 FAILED: expected ErrSymlinkBlocked during snapshot creation, got %v", err)
	}

	events := mgr.Store.RecentSecurityEvents(10)
	if len(events) == 0 || events[0].Category != "symlink_guard" {
		t.Fatalf("expected symlink_guard SecurityAuditEvent to be recorded, got %+v", events)
	}

	// Remove evil link, create a valid snapshot, then tamper with archive to inject a TypeSymlink entry -> Restore must reject!
	_ = os.Remove(evilLink)
	validSnap, err := mgr.CreateSnapshot(ctx, acct, CreateRequest{InstanceID: inst.ID}, nil)
	if err != nil {
		t.Fatalf("expected clean snapshot after removing symlink: %v", err)
	}
	archivePath, _, err := mgr.ResolveDownloadPath(acct, inst.ID, validSnap.ID)
	if err != nil {
		t.Fatal(err)
	}

	var rawTar bytes.Buffer
	tw := tar.NewWriter(&rawTar)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "files/evil-symlink.php",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
		Mode:     0o777,
	})
	_ = tw.Close()

	var forgedZst bytes.Buffer
	if err := encodeNativeRFC8878Zstd(&rawTar, &forgedZst); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, forgedZst.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.RestoreSnapshot(ctx, acct, inst.ID, validSnap.ID, nil); err == nil {
		t.Fatal("expected RestoreSnapshot to reject forged TypeSymlink tar entry")
	}
}
