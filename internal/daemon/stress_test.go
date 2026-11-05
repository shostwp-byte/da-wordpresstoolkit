package daemon

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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/discovery"
	"github.com/shostwp-byte/da-wptoolkits/internal/integrity"
	"github.com/shostwp-byte/da-wptoolkits/internal/ipc"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/updater"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
)

func seedTinyWP(t *testing.T, docRoot, wpVer, dbName string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(docRoot, "wp-includes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(docRoot, "wp-admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(docRoot, "wp-content", "plugins", "elementor"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(docRoot, "index.php"), []byte("<?php // WP\n"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '"+wpVer+"';\n"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte(
		"<?php\ndefine('DB_NAME', '"+dbName+"');\ndefine('DB_USER', '"+dbName+"');\ndefine('WP_MEMORY_LIMIT', '256M');\n$table_prefix = 'wp_';\n",
	), 0o600)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-content", "plugins", "elementor", "elementor.php"), []byte(
		"<?php\n/*\nPlugin Name: Elementor\nVersion: 3.18.0\n*/\n",
	), 0o644)
}

func makeSignedReleaseBundleForDaemonTest(t *testing.T, dir string, privKeyHex string, binContent string, ver string) {
	t.Helper()
	_ = os.MkdirAll(dir, 0o755)
	tarPath := filepath.Join(dir, "da-wptoolkit-linux-amd64.tar.gz")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	now := time.Now().UTC()
	padded := binContent + "\n" + strings.Repeat("#PAD#", 300)
	items := map[string]string{
		"bin/da-wptoolkit":       padded,
		"plugin/plugin.conf":     "name=WordPress Manager\nid=da_wp_toolkits\nversion=" + ver + "\n",
		"plugin/user/index.html": "#!/bin/sh\necho user-" + ver + "\n",
	}
	for name, body := range items {
		b := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(b)), Mode: 0o755, ModTime: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	priv, err := updater.ParsePrivateKey(privKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := updater.SignChecksumsDir(dir, priv); err != nil {
		t.Fatal(err)
	}
}

func TestPhase6DirectAdminHooksAndEd25519UpdaterOverAdminIPC(t *testing.T) {
	tmp := t.TempDir()
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	homeCust1 := filepath.Join(tmp, "home", "cust1")
	stateDir := filepath.Join(tmp, "state")
	dataDir := filepath.Join(tmp, "pdata")

	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"diradmin:x:991:991:DA:/usr/local/directadmin:/bin/false\n"+
			"cust1:x:1010:1010::"+homeCust1+":/bin/bash\n",
	), 0o644)

	cust1ConfDir := filepath.Join(daRoot, "users", "cust1")
	_ = os.MkdirAll(filepath.Join(cust1ConfDir, "domains"), 0o755)
	_ = os.WriteFile(filepath.Join(cust1ConfDir, "user.conf"), []byte("package=business\nsuspended=no\n"), 0o600)
	_ = os.WriteFile(filepath.Join(cust1ConfDir, "domains.list"), []byte("alpha.vn\n"), 0o600)
	_ = os.WriteFile(filepath.Join(cust1ConfDir, "domains", "alpha.vn.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
	_ = os.WriteFile(filepath.Join(cust1ConfDir, "domains", "alpha.vn.subdomains"), []byte("blog\n"), 0o600)

	seedTinyWP(t, filepath.Join(homeCust1, "domains", "alpha.vn", "public_html"), "6.7.1", "cust1_wp1")
	seedTinyWP(t, filepath.Join(homeCust1, "domains", "alpha.vn", "public_html", "blog"), "6.7.1", "cust1_wp2")

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	jm, err := store.NewJobManager(stateDir, 2)
	if err != nil {
		t.Fatal(err)
	}
	pol := config.NewPolicyStore(dataDir, filepath.Join(tmp, "updater.conf"))
	// Restricted package 'starter' forbids Fortress Core Lock
	starterPol := config.DefaultPackagePolicy()
	starterPol.AllowCoreFortressLock = false
	if err := pol.SavePackagePolicy("starter", starterPol); err != nil {
		t.Fatal(err)
	}

	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()

	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	scanner := discovery.NewScanner(domRes, st, pol)
	wsAdapter := webserver.NewAdapter("", filepath.Join(tmp, "nginx_snippets"))
	shield, err := integrity.NewShield(st, users, pol, integrity.ShieldConfig{
		StateDir:      stateDir,
		CoreCacheDir:  filepath.Join(tmp, "core_cache"),
		QuarantineDir: filepath.Join(tmp, "quarantine"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanSrc := filepath.Join(tmp, "clean_wp_671")
	_ = os.MkdirAll(filepath.Join(cleanSrc, "wp-includes"), 0o755)
	_ = os.MkdirAll(filepath.Join(cleanSrc, "wp-admin"), 0o755)
	_ = os.WriteFile(filepath.Join(cleanSrc, "index.php"), []byte("<?php // WP\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cleanSrc, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '6.7.1';\n"), 0o644)
	if _, err := shield.Cache.SeedVerifiedTree("6.7.1", "en_US", cleanSrc); err != nil {
		t.Fatalf("SeedVerifiedTree failed: %v", err)
	}

	guard := auth.NewGuard(users, st, filepath.Join(tmp, "proc"), filepath.Join(daRoot, "sessions"), filepath.Join(tmp, "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Domains = domRes
	svc.Scanner = scanner
	svc.WebServer = wsAdapter
	svc.Shield = shield

	ctx := context.Background()
	rootCred := auth.PeerCred{UID: 0, GID: 0, PID: 1}

	// 1) Hook: domain_create & subdomain_create discover both alpha.vn and blog.alpha.vn
	r1 := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "domain_create", "domain": "alpha.vn"},
	})
	if !r1.OK || len(st.ListInstancesByOwner("cust1")) != 2 {
		t.Fatalf("domain_create hook failed: resp=%+v count=%d", r1, len(st.ListInstancesByOwner("cust1")))
	}

	rSubCreate := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "subdomain_create", "domain": "alpha.vn", "subdomain": "blog"},
	})
	if !rSubCreate.OK {
		t.Fatalf("subdomain_create hook failed: %+v", rSubCreate)
	}

	// Lock main instance into Fortress Core Lock, then test user_backup_pre / user_backup_post & user_modify downgrade!
	var mainInst store.InstanceRecord
	for _, it := range st.ListInstancesByOwner("cust1") {
		if it.Domain == "alpha.vn" {
			mainInst = it
		}
	}
	rLock := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:     "lock_core",
		InstanceID: mainInst.ID,
	})
	if !rLock.OK {
		t.Fatalf("lock_core failed: %+v", rLock)
	}

	// 2) Hook: user_backup_pre & user_backup_post (TC-06)
	rPre := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "user_backup_pre"},
	})
	rPost := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "user_backup_post"},
	})
	if !rPre.OK || !rPost.OK {
		t.Fatalf("backup hooks failed: pre=%+v post=%+v", rPre, rPost)
	}

	// 3) Hook: user_modify downgrades cust1 from 'business' -> 'starter' (AllowCoreFortressLock=false)
	_ = os.WriteFile(filepath.Join(cust1ConfDir, "user.conf"), []byte("package=starter\nsuspended=no\n"), 0o600)
	rMod := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "user_modify"},
	})
	if !rMod.OK {
		t.Fatalf("user_modify hook failed: %+v", rMod)
	}
	afterMod, _ := st.GetInstance(mainInst.ID)
	if afterMod.CoreShieldMode != config.ShieldModeAutoHeal {
		t.Fatalf("expected user_modify onto restricted package to downgrade fortress_lock -> auto_heal, got %s", afterMod.CoreShieldMode)
	}

	// 4) Hook: subdomain_destroy removes ONLY blog.alpha.vn while preserving alpha.vn!
	rSubDel := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "subdomain_destroy", "domain": "alpha.vn", "subdomain": "blog"},
	})
	if !rSubDel.OK || len(st.ListInstancesByOwner("cust1")) != 1 {
		t.Fatalf("subdomain_destroy failed: resp=%+v remaining=%d", rSubDel, len(st.ListInstancesByOwner("cust1")))
	}

	// 5) Hook: domain_destroy removes alpha.vn cleanly
	rDomDel := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "cust1",
		Params:   map[string]any{"event": "domain_destroy", "domain": "alpha.vn"},
	})
	if !rDomDel.OK || len(st.ListInstancesByOwner("cust1")) != 0 {
		t.Fatalf("domain_destroy failed: resp=%+v remaining=%d", rDomDel, len(st.ListInstancesByOwner("cust1")))
	}

	// 6) Hook: user_restore dynamically reloads /etc/passwd & discovers newly migrated cPanel/DA account 'migrated9'
	homeMig := filepath.Join(tmp, "home", "migrated9")
	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"diradmin:x:991:991:DA:/usr/local/directadmin:/bin/false\n"+
			"cust1:x:1010:1010::"+homeCust1+":/bin/bash\n"+
			"migrated9:x:1099:1099::"+homeMig+":/bin/bash\n",
	), 0o644)
	migConfDir := filepath.Join(daRoot, "users", "migrated9")
	_ = os.MkdirAll(filepath.Join(migConfDir, "domains"), 0o755)
	_ = os.WriteFile(filepath.Join(migConfDir, "user.conf"), []byte("package=pro\nsuspended=no\n"), 0o600)
	_ = os.WriteFile(filepath.Join(migConfDir, "domains.list"), []byte("restored-shop.vn\n"), 0o600)
	_ = os.WriteFile(filepath.Join(migConfDir, "domains", "restored-shop.vn.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
	seedTinyWP(t, filepath.Join(homeMig, "domains", "restored-shop.vn", "public_html"), "6.7.1", "mig9_wp1")

	rRestore := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "migrated9",
		Params:   map[string]any{"event": "user_restore"},
	})
	if !rRestore.OK || len(st.ListInstancesByOwner("migrated9")) != 1 {
		t.Fatalf("user_restore hook failed to reload /etc/passwd and discover migrated WP site: resp=%+v", rRestore)
	}

	// 7) Ed25519 GitHub Self-Updater over Admin IPC (apply_github_update + list_update_backups + rollback_github_update)
	privHex, pubHex, _ := updater.GenerateKeyPairHex()
	relBase := filepath.Join(tmp, "gh_rel")
	makeSignedReleaseBundleForDaemonTest(t, filepath.Join(relBase, "ok"), privHex, "DAEMON_OK_V1.0.0", "1.0.0")
	makeSignedReleaseBundleForDaemonTest(t, filepath.Join(relBase, "bad"), privHex, "DAEMON_CRASH_V1.0.1", "1.0.1")

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			assetsFor := func(sub string) []map[string]any {
				return []map[string]any{
					{"name": "da-wptoolkit-linux-amd64.tar.gz", "browser_download_url": base + "/dl/" + sub + "/da-wptoolkit-linux-amd64.tar.gz"},
					{"name": "checksums.txt", "browser_download_url": base + "/dl/" + sub + "/checksums.txt"},
					{"name": "checksums.txt.sig", "browser_download_url": base + "/dl/" + sub + "/checksums.txt.sig"},
				}
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"tag_name": "v1.0.1-broken", "name": "Broken v1.0.1", "prerelease": true, "assets": assetsFor("bad")},
				{"tag_name": "v1.0.0", "name": "Release v1.0.0", "prerelease": false, "assets": assetsFor("ok")},
			})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/dl/") {
			http.ServeFile(w, r, filepath.Join(relBase, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/dl/"))))
			return
		}
		http.NotFound(w, r)
	}))
	defer ghSrv.Close()

	binPath := filepath.Join(tmp, "sbin", "da-wptoolkit")
	pluginDir := filepath.Join(tmp, "plugin_live")
	_ = os.MkdirAll(filepath.Dir(binPath), 0o755)
	_ = os.MkdirAll(pluginDir, 0o755)
	_ = os.WriteFile(binPath, []byte("DAEMON_OK_V0.6.0\n"+strings.Repeat("X", 2048)), 0o755)
	_ = os.WriteFile(filepath.Join(pluginDir, "plugin.conf"), []byte("version=0.6.0\n"), 0o644)

	updMgr := updater.NewManager(stateDir, st)
	updMgr.BinPath = binPath
	updMgr.PluginDir = pluginDir
	updMgr.HooksBaseDir = filepath.Join(tmp, "hooks_live")
	updMgr.ShareDir = filepath.Join(tmp, "share_live")
	updMgr.PublicKeyHex = pubHex
	updMgr.APIBaseURL = ghSrv.URL
	updMgr.TargetArch = "amd64"
	updMgr.CurrentVersion = "v0.6.0"
	updMgr.RestartDaemon = func(_ context.Context) error { return nil }
	updMgr.HealthCheck = func(_ context.Context) error {
		b, _ := os.ReadFile(binPath)
		if bytes.Contains(b, []byte("DAEMON_CRASH")) {
			return errors.New("ping healthcheck failed after startup")
		}
		return nil
	}
	svc.Updater = updMgr
	svc.GitHubAPIBase = ghSrv.URL

	// Broken release over Admin IPC triggers auto-rollback, preserving migrated9's Registry entry!
	rBrokenUpd := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "apply_github_update",
		Params: map[string]any{"tag": "v1.0.1-broken", "force": true, "sync": true},
	})
	if rBrokenUpd.OK {
		t.Fatal("expected broken release update to return error after auto-rollback")
	}
	if len(st.ListInstancesByOwner("migrated9")) != 1 {
		t.Fatal("Registry lost migrated9 instance during auto-rollback!")
	}

	// Healthy v1.0.0 release succeeds over Admin IPC
	rGoodUpd := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "apply_github_update",
		Params: map[string]any{"tag": "v1.0.0", "force": true, "sync": true},
	})
	if !rGoodUpd.OK {
		t.Fatalf("healthy v1.0.0 apply_github_update failed: %+v", rGoodUpd)
	}

	rBkps := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{Action: "list_update_backups"})
	if !rBkps.OK {
		t.Fatalf("list_update_backups failed: %+v", rBkps)
	}

	rRb := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "rollback_github_update",
		Params: map[string]any{"sync": true},
	})
	if !rRb.OK {
		t.Fatalf("rollback_github_update failed: %+v", rRb)
	}

	// 8) Hook: user_destroy purges migrated9 completely
	rDestroy := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "handle_da_hook",
		Username: "migrated9",
		Params:   map[string]any{"event": "user_destroy"},
	})
	if !rDestroy.OK || len(st.ListInstancesByOwner("migrated9")) != 0 {
		t.Fatalf("user_destroy hook failed: %+v", rDestroy)
	}
}

func TestPhase6HighDensityStress500Accounts1000Instances(t *testing.T) {
	const (
		accountCount  = 500
		expectedSites = 1000 // 2 sites per account (main domain + shop subdomain)
	)

	tmp := t.TempDir()
	passwdPath := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")
	stateDir := filepath.Join(tmp, "state")

	_ = os.MkdirAll(sessDir, 0o700)
	_ = os.MkdirAll(filepath.Join(daRoot, "admin"), 0o755)
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "packages.list"), []byte("basic\npro\nbusiness\n"), 0o644)

	// Valid DirectAdmin process lineage: PID 500 (directadmin) -> PID 2500 (CGI php)
	// Plus rogue PHP-FPM process PID 9999 (must be blocked by Layer 2 TC-01!)
	_ = os.MkdirAll(filepath.Join(procRoot, "500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "stat"), []byte("500 (directadmin) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "exe_path"), []byte("/usr/local/directadmin/directadmin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "status"), []byte("Name:\tdirectadmin\nUid:\t0\t0\t0\t0\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "2500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "2500", "stat"), []byte("2500 (php) S 500 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 200 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2500", "exe_path"), []byte("/usr/local/php83/bin/php\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2500", "cgroup"), []byte("0::/system.slice/directadmin.service\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "9999"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "9999", "stat"), []byte("9999 (php-fpm83) S 1 9999 9999 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 300 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "9999", "exe_path"), []byte("/usr/local/php83/sbin/php-fpm83\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "9999", "cgroup"), []byte("0::/system.slice/php-fpm83.service\n"), 0o644)

	var passwdBuf strings.Builder
	passwdBuf.WriteString("root:x:0:0:root:/root:/bin/bash\n")
	passwdBuf.WriteString("diradmin:x:991:991:DA:/usr/local/directadmin:/bin/false\n")

	pkgs := []string{"basic", "pro", "business"}
	for i := 0; i < accountCount; i++ {
		uname := fmt.Sprintf("user%03d", i)
		uid := 2000 + i
		homeDir := filepath.Join(tmp, "home", uname)
		passwdBuf.WriteString(fmt.Sprintf("%s:x:%d:%d::%s:/bin/bash\n", uname, uid, uid, homeDir))
	}
	if err := os.WriteFile(passwdPath, []byte(passwdBuf.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	// Parallel fixture seeding for 500 accounts / 1,000 WordPress sites
	idxCh := make(chan int, accountCount)
	for i := 0; i < accountCount; i++ {
		idxCh <- i
	}
	close(idxCh)

	var seedWG sync.WaitGroup
	for w := 0; w < 16; w++ {
		seedWG.Add(1)
		go func() {
			defer seedWG.Done()
			for i := range idxCh {
				uname := fmt.Sprintf("user%03d", i)
				homeDir := filepath.Join(tmp, "home", uname)
				uDir := filepath.Join(daRoot, "users", uname)
				dDir := filepath.Join(uDir, "domains")
				_ = os.MkdirAll(dDir, 0o755)
				dom := fmt.Sprintf("site%03d.vn", i)
				pkg := pkgs[i%len(pkgs)]
				_ = os.WriteFile(filepath.Join(uDir, "user.conf"), []byte("package="+pkg+"\nsuspended=no\n"), 0o600)
				_ = os.WriteFile(filepath.Join(uDir, "domains.list"), []byte(dom+"\n"), 0o600)
				_ = os.WriteFile(filepath.Join(dDir, dom+".conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
				_ = os.WriteFile(filepath.Join(dDir, dom+".subdomains"), []byte("shop\n"), 0o600)

				// Active DirectAdmin session for first 64 users used in concurrent tenant IPC flood
				if i < 64 {
					sessID := fmt.Sprintf("stress_da_session_user_%03d", i)
					_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+sessID), []byte("username="+uname+"\n"), 0o600)
				}

				seedTinyWP(t, filepath.Join(homeDir, "domains", dom, "public_html"), "6.7.1", uname+"_wp1")
				seedTinyWP(t, filepath.Join(homeDir, "domains", dom, "public_html", "shop"), "6.7.1", uname+"_wp2")
			}
		}()
	}
	seedWG.Wait()

	// Seed local CVE feed matching Elementor <= 3.18.3 so CVE matcher is stressed across all 1,000 sites!
	vulnFile := filepath.Join(tmp, "wordfence_feed.json")
	_ = os.WriteFile(vulnFile, []byte(`{
		"wf-cve-2026-0001": {
			"id": "wf-cve-2026-0001",
			"title": "Elementor <= 3.18.3 Authenticated RCE",
			"software": [{
				"type": "plugin",
				"slug": "elementor",
				"affected_versions": {"* - 3.18.3": {"from_version": "*", "from_inclusive": true, "to_version": "3.18.3", "to_inclusive": true}},
				"patched": true,
				"patched_versions": ["3.18.4"]
			}],
			"cvss": {"score": 8.8, "rating": "High"},
			"cves": ["CVE-2026-0001"]
		}
	}`), 0o644)

	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	jm, err := store.NewJobManager(stateDir, 4)
	if err != nil {
		t.Fatal(err)
	}
	pol := config.NewPolicyStore(filepath.Join(tmp, "pdata"), filepath.Join(tmp, "updater.conf"))
	users := dausers.NewRegistry(daRoot, passwdPath)
	if err := users.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := len(users.ListAccounts()); got != accountCount {
		t.Fatalf("expected %d accounts in registry, got %d", accountCount, got)
	}

	vdb, err := vulndb.Open(stateDir, vulnFile)
	if err != nil {
		t.Fatal(err)
	}

	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	scanner := discovery.NewScanner(domRes, st, pol)
	scanner.Vulns = vdb

	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Domains = domRes
	svc.Scanner = scanner
	svc.Vulns = vdb

	if syncResp := svc.HandleAdminRequest(context.Background(), auth.PeerCred{UID: 0, GID: 0, PID: 1}, ipc.Request{
		Action: "sync_vulndb",
		Params: map[string]any{"source": vulnFile},
	}); !syncResp.OK {
		t.Fatalf("sync_vulndb failed: %+v", syncResp)
	}

	// Step 1: Server-wide scan across 500 accounts / 1,000 WordPress instances
	scanStart := time.Now()
	scanResp := svc.HandleAdminRequest(context.Background(), auth.PeerCred{UID: 0, GID: 0, PID: 1}, ipc.Request{
		Action: "scan_instances",
	})
	scanElapsed := time.Since(scanStart)
	if !scanResp.OK {
		t.Fatalf("500-account scan_instances failed: %+v", scanResp)
	}
	if total := len(st.ListAllInstances(false)); total != expectedSites {
		t.Fatalf("expected %d discovered WordPress instances across 500 accounts, got %d", expectedSites, total)
	}

	// Step 2: Verify steady-state daemon memory footprint (< 25 MB DoD for 500 accounts / 1,000 instances!)
	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	var heapDeltaBytes uint64
	if memAfter.HeapAlloc > memBefore.HeapAlloc {
		heapDeltaBytes = memAfter.HeapAlloc - memBefore.HeapAlloc
	}
	heapDeltaMB := float64(heapDeltaBytes) / (1024.0 * 1024.0)
	t.Logf("Stress Test Telemetry: 500 accounts / 1,000 WP instances scanned in %v | Steady-state Heap Delta = %.2f MB", scanElapsed, heapDeltaMB)
	if heapDeltaMB > 25.0 {
		t.Fatalf("Phase 6 Memory DoD FAILED: steady-state heap delta %.2f MB exceeds 25 MB budget!", heapDeltaMB)
	}

	// Step 3: High-concurrency multi-tenant IPC flood (48 workers, 1,200 concurrent requests + rogue webshell blocks)
	const (
		workers     = 48
		totalOps    = 1200
		rogueEveryN = 10
	)
	opCh := make(chan int, totalOps)
	for n := 0; n < totalOps; n++ {
		opCh <- n
	}
	close(opCh)

	var (
		wg          sync.WaitGroup
		failures    atomic.Int64
		rogueBlocks atomic.Int64
		firstErrMsg atomic.Value
	)
	recordFail := func(msg string) {
		if failures.Add(1) == 1 {
			firstErrMsg.Store(msg)
		}
	}

	floodStart := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			for n := range opCh {
				uIdx := n % 64
				uname := fmt.Sprintf("user%03d", uIdx)
				uid := uint32(2000 + uIdx)
				sessID := fmt.Sprintf("stress_da_session_user_%03d", uIdx)

				// Every 10th op simulates a compromised PHP-FPM webshell under same UID (TC-01)
				if n%rogueEveryN == 0 {
					err := svc.AuthorizeSocketPeer(auth.PeerCred{UID: uid, GID: uid, PID: 9999}, false)
					if err == nil {
						recordFail("SECURITY FAILURE: rogue PHP-FPM PID 9999 bypassed AuthorizeSocketPeer under concurrency!")
						continue
					}
					rogueBlocks.Add(1)
				}

				switch n % 4 {
				case 0:
					resp := svc.HandleUserRequest(ctx, auth.PeerCred{UID: uid, GID: uid, PID: 2500}, ipc.Request{
						Action:    "get_bootstrap",
						Username:  uname,
						SessionID: sessID,
					})
					if !resp.OK || resp.CSRFToken == "" {
						recordFail(fmt.Sprintf("get_bootstrap failed for %s: %+v", uname, resp))
						continue
					}
					dataMap, _ := resp.Data.(map[string]any)
					instSlice, _ := dataMap["instances"].([]store.InstanceRecord)
					if len(instSlice) != 2 {
						recordFail(fmt.Sprintf("tenant isolation violation for %s: expected 2 instances, got %d", uname, len(instSlice)))
						continue
					}
					for _, inst := range instSlice {
						if inst.Owner != uname || inst.VulnCount != 1 {
							recordFail(fmt.Sprintf("corrupted instance record for %s: %+v", uname, inst))
						}
					}

				case 1:
					resp := svc.HandleUserRequest(ctx, auth.PeerCred{UID: uid, GID: uid, PID: 2500}, ipc.Request{
						Action:    "list_domains",
						Username:  uname,
						SessionID: sessID,
					})
					if !resp.OK {
						recordFail(fmt.Sprintf("list_domains failed for %s: %+v", uname, resp))
					}

				case 2:
					resp := svc.HandleAdminRequest(ctx, auth.PeerCred{UID: 0, GID: 0, PID: 1}, ipc.Request{
						Action: "get_overview",
					})
					if !resp.OK {
						recordFail(fmt.Sprintf("admin get_overview failed: %+v", resp))
					}

				case 3:
					resp := svc.HandleAdminRequest(ctx, auth.PeerCred{UID: 0, GID: 0, PID: 1}, ipc.Request{
						Action: "list_packages",
					})
					if !resp.OK {
						recordFail(fmt.Sprintf("admin list_packages failed: %+v", resp))
					}
				}
			}
		}()
	}
	wg.Wait()
	floodElapsed := time.Since(floodStart)

	if failures.Load() > 0 {
		t.Fatalf("Concurrent stress flood had %d failures (first: %v)", failures.Load(), firstErrMsg.Load())
	}
	t.Logf("Concurrent IPC Flood PASSED: %d requests (%d rogue webshells blocked) across %d workers in %v", totalOps, rogueBlocks.Load(), workers, floodElapsed)
}
