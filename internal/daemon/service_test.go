package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
	"github.com/shostwp-byte/da-wptoolkits/internal/clonesync"
	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/database"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/discovery"
	"github.com/shostwp-byte/da-wptoolkits/internal/extensions"
	"github.com/shostwp-byte/da-wptoolkits/internal/hardening"
	"github.com/shostwp-byte/da-wptoolkits/internal/integrity"
	"github.com/shostwp-byte/da-wptoolkits/internal/ipc"
	"github.com/shostwp-byte/da-wptoolkits/internal/lifecycle"
	"github.com/shostwp-byte/da-wptoolkits/internal/quicktools"
	"github.com/shostwp-byte/da-wptoolkits/internal/smartupdate"
	"github.com/shostwp-byte/da-wptoolkits/internal/snapshot"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

type testDBProv struct {
	dropped []string
}

func (m *testDBProv) CreateDatabase(_ context.Context, acct dausers.Account, _ string) (database.Credentials, error) {
	name := acct.Username + "_wp201"
	return database.Credentials{
		DBName:   name,
		DBUser:   name,
		Password: "StrongRandomPassword1234",
		Host:     "localhost",
	}, nil
}

func (m *testDBProv) DropDatabase(_ context.Context, _ dausers.Account, dbName, _ string) error {
	m.dropped = append(m.dropped, dbName)
	return nil
}

func TestEndToEndUserBootstrapAndMutatingDetachOverIPC(t *testing.T) {
	tmp := t.TempDir()
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")

	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"diradmin:x:991:991:DA:/usr/local/directadmin:/bin/false\n"+
			"reno26:x:1005:1005::/home/reno26:/bin/bash\n",
	), 0o644)
	_ = os.MkdirAll(sessDir, 0o700)
	_ = os.MkdirAll(filepath.Join(daRoot, "users", "reno26"), 0o755)
	_ = os.WriteFile(filepath.Join(daRoot, "users", "reno26", "user.conf"), []byte("package=pro\nsuspended=no\n"), 0o600)

	sessID := "valid_da_session_987654321"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+sessID), []byte("username=reno26\n"), 0o600)

	// Fake /proc lineage: PID 500 (directadmin) -> PID 2005 (CGI php)
	_ = os.MkdirAll(filepath.Join(procRoot, "500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "stat"), []byte("500 (directadmin) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "exe_path"), []byte("/usr/local/directadmin/directadmin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "status"), []byte("Name:\tdirectadmin\nUid:\t0\t0\t0\t0\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "2005"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "stat"), []byte("2005 (php) S 500 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 200 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "exe_path"), []byte("/usr/local/php83/bin/php\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "cgroup"), []byte("0::/system.slice/directadmin.service\n"), 0o644)

	st, err := store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:     "reno26",
		OwnerUID:  1005,
		Domain:    "renolabs-audio.com",
		DocRoot:   "/home/reno26/domains/renolabs-audio.com/public_html",
		SiteTitle: "RENOLABS",
		WPVersion: "6.7.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	jm, err := store.NewJobManager(filepath.Join(tmp, "state"), 2)
	if err != nil {
		t.Fatal(err)
	}
	pol := config.NewPolicyStore(filepath.Join(tmp, "plugin_data"), "")
	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()
	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "secret", "csrf.key"))

	svc := NewService(st, jm, pol, users, guard)
	ipcSrv := ipc.NewServer("", "", svc)
	ipcSrv.GetPeerCred = func(_ net.Conn) (auth.PeerCred, error) {
		return auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, nil
	}

	callUserIPC := func(req ipc.Request) ipc.Response {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go ipcSrv.ServeConn(context.Background(), c2, false)
		raw, _ := json.Marshal(req)
		_, _ = c1.Write(append(raw, '\n'))
		line, rErr := bufio.NewReader(c1).ReadBytes('\n')
		if rErr != nil {
			t.Fatalf("pipe read error: %v", rErr)
		}
		var resp ipc.Response
		if uErr := json.Unmarshal(line, &resp); uErr != nil {
			t.Fatalf("unmarshal error: %v", uErr)
		}
		return resp
	}

	// 1. Bootstrap returns CSRF token and 1 instance
	boot := callUserIPC(ipc.Request{
		Action:    "get_bootstrap",
		Username:  "reno26",
		SessionID: sessID,
	})
	if !boot.OK || len(boot.CSRFToken) != 64 {
		t.Fatalf("bootstrap failed: %+v", boot)
	}

	// 2. Detach without CSRF fails with 403
	badDetach := callUserIPC(ipc.Request{
		Action:     "detach_instance",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: inst.ID,
	})
	if badDetach.OK || badDetach.Code != 403 {
		t.Fatalf("expected detach without CSRF to fail with 403, got: %+v", badDetach)
	}

	// 3. Detach WITH valid CSRF succeeds
	okDetach := callUserIPC(ipc.Request{
		Action:     "detach_instance",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  boot.CSRFToken,
		InstanceID: inst.ID,
	})
	if !okDetach.OK {
		t.Fatalf("expected detach with valid CSRF to succeed, got: %+v", okDetach)
	}

	if remaining := st.ListInstancesByOwner("reno26"); len(remaining) != 0 {
		t.Fatalf("expected 0 active instances after detach, got %d", len(remaining))
	}
}

func TestPhase1EndToEndDomainListInstallSSOScanAndUninstallOverIPC(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")
	corePool := filepath.Join(tmp, "core_cache")

	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"reno26:x:1005:1005::"+filepath.ToSlash(homeDir)+":/bin/bash\n",
	), 0o644)
	_ = os.MkdirAll(sessDir, 0o700)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("package=pro\nsuspended=no\ndomain=renolabs-audio.com\nemail=owner@renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html"), 0o755)

	sessID := "valid_phase1_session_123456"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+sessID), []byte("username=reno26\n"), 0o600)

	// Fake /proc lineage: PID 500 (directadmin) -> PID 2005 (CGI php)
	_ = os.MkdirAll(filepath.Join(procRoot, "500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "stat"), []byte("500 (directadmin) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "exe_path"), []byte("/usr/local/directadmin/directadmin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "status"), []byte("Name:\tdirectadmin\nUid:\t0\t0\t0\t0\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "2005"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "stat"), []byte("2005 (php) S 500 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 200 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "exe_path"), []byte("/usr/local/php84/bin/php\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "cgroup"), []byte("0::/system.slice/directadmin.service\n"), 0o644)

	// Seed Local Verified Core Cache (latest-vi)
	cachedWP := filepath.Join(corePool, "latest-vi")
	_ = os.MkdirAll(filepath.Join(cachedWP, "wp-includes"), 0o755)
	_ = os.WriteFile(filepath.Join(cachedWP, "wp-includes", "version.php"), []byte("<?php\n$wp_version = '6.7.1';\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cachedWP, "index.php"), []byte("<?php // Silence is golden.\n"), 0o644)

	st, err := store.Open(filepath.Join(tmp, "state"))
	if err != nil {
		t.Fatal(err)
	}
	jm, err := store.NewJobManager(filepath.Join(tmp, "state"), 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		jm.Wait()
	}()
	jm.Start(ctx)

	pol := config.NewPolicyStore(filepath.Join(tmp, "plugin_data"), "")
	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()

	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	dbProv := &testDBProv{}
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", corePool)
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, _ wpcli.ExecSpec) (string, string, error) {
		return "Success", "", nil
	}

	scanner := discovery.NewScanner(domRes, st, pol)
	lifeMgr := lifecycle.NewManager(domRes, dbProv, wpRunner, st, pol, corePool)
	lifeMgr.ReapDelayOverride = 60 * time.Millisecond

	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "secret", "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Domains = domRes
	svc.Scanner = scanner
	svc.Lifecycle = lifeMgr

	ipcSrv := ipc.NewServer("", "", svc)
	ipcSrv.GetPeerCred = func(_ net.Conn) (auth.PeerCred, error) {
		return auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, nil
	}

	sendUser := func(req ipc.Request) ipc.Response {
		c1, c2 := net.Pipe()
		defer c1.Close()
		go ipcSrv.ServeConn(ctx, c2, false)
		raw, _ := json.Marshal(req)
		_, _ = c1.Write(append(raw, '\n'))
		line, rErr := bufio.NewReader(c1).ReadBytes('\n')
		if rErr != nil {
			t.Fatalf("pipe read error: %v", rErr)
		}
		var resp ipc.Response
		if uErr := json.Unmarshal(line, &resp); uErr != nil {
			t.Fatalf("unmarshal error: %v", uErr)
		}
		return resp
	}

	// 1. list_domains returns renolabs-audio.com + CSRF token
	domResp := sendUser(ipc.Request{
		Action:    "list_domains",
		Username:  "reno26",
		SessionID: sessID,
	})
	if !domResp.OK || domResp.CSRFToken == "" {
		t.Fatalf("list_domains failed: %+v", domResp)
	}
	csrf := domResp.CSRFToken

	// 2. Weak admin username 'admin' rejected immediately on async install_instance (400)
	weakResp := sendUser(ipc.Request{
		Action:    "install_instance",
		Username:  "reno26",
		SessionID: sessID,
		CSRFToken: csrf,
		Params: map[string]any{
			"domain":     "renolabs-audio.com",
			"admin_user": "admin",
		},
	})
	if weakResp.OK || weakResp.Code != 400 {
		t.Fatalf("expected weak admin username to fail with 400, got: %+v", weakResp)
	}

	// 3. Async 1-Click Express Install enqueues background job & returns one-time generated password in memory
	instResp := sendUser(ipc.Request{
		Action:    "install_instance",
		Username:  "reno26",
		SessionID: sessID,
		CSRFToken: csrf,
		Params: map[string]any{
			"domain":     "renolabs-audio.com",
			"site_title": "RENOLABS",
		},
	})
	if !instResp.OK || instResp.JobID == "" {
		t.Fatalf("install_instance enqueue failed: %+v", instResp)
	}

	// Poll get_job until completed
	var completed bool
	for i := 0; i < 40; i++ {
		jobResp := sendUser(ipc.Request{
			Action:    "get_job",
			Username:  "reno26",
			SessionID: sessID,
			JobID:     instResp.JobID,
		})
		raw, _ := json.Marshal(jobResp.Data)
		var jr store.JobRecord
		_ = json.Unmarshal(raw, &jr)
		if jr.Status == store.JobStatusSucceeded {
			completed = true
			break
		}
		if jr.Status == store.JobStatusFailed {
			t.Fatalf("async install job failed: %s", jr.Error)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !completed {
		t.Fatal("timed out waiting for async install job to complete")
	}

	instances := st.ListInstancesByOwner("reno26")
	if len(instances) != 1 {
		t.Fatalf("expected 1 installed instance, got %d", len(instances))
	}
	wpID := instances[0].ID

	// 4. Generate 1-Click Ephemeral SSO URL
	ssoResp := sendUser(ipc.Request{
		Action:     "sso_login",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: wpID,
	})
	if !ssoResp.OK {
		t.Fatalf("sso_login failed: %+v", ssoResp)
	}
	time.Sleep(90 * time.Millisecond) // allow reaper cleanup

	// 5. scan_instances reconciles existing site cleanly
	scanResp := sendUser(ipc.Request{
		Action:    "scan_instances",
		Username:  "reno26",
		SessionID: sessID,
		CSRFToken: csrf,
	})
	if !scanResp.OK {
		t.Fatalf("scan_instances failed: %+v", scanResp)
	}

	// 6. uninstall_instance with drop_db=true removes site and drops DB
	unResp := sendUser(ipc.Request{
		Action:     "uninstall_instance",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: wpID,
		Params:     map[string]any{"drop_db": true},
	})
	if !unResp.OK {
		t.Fatalf("uninstall_instance failed: %+v", unResp)
	}
	if len(st.ListInstancesByOwner("reno26")) != 0 || len(dbProv.dropped) != 1 {
		t.Fatalf("expected 0 instances and 1 dropped DB after uninstall, got instances=%d dropped=%v", len(st.ListInstancesByOwner("reno26")), dbProv.dropped)
	}
}

func TestPhase2EndToEndPluginsVulnScanSetsAndSmartRollbackOverIPC(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")

	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"reno26:x:1005:1005::"+filepath.ToSlash(homeDir)+":/bin/bash\n",
	), 0o644)
	_ = os.MkdirAll(sessDir, 0o700)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("package=pro\nsuspended=no\ndomain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	plugFile := filepath.Join(docRoot, "wp-content", "plugins", "elementor", "elementor.php")
	_ = os.MkdirAll(filepath.Dir(plugFile), 0o755)
	_ = os.WriteFile(plugFile, []byte("<?php\n/*\nPlugin Name: Elementor\nVersion: 3.18.1\n*/\n"), 0o644)

	sessID := "valid_phase2_session_555555"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+sessID), []byte("username=reno26\n"), 0o600)

	_ = os.MkdirAll(filepath.Join(procRoot, "500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "stat"), []byte("500 (directadmin) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "exe_path"), []byte("/usr/local/directadmin/directadmin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "status"), []byte("Name:\tdirectadmin\nUid:\t0\t0\t0\t0\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "2005"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "stat"), []byte("2005 (php) S 500 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 200 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "exe_path"), []byte("/usr/local/php84/bin/php\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "cgroup"), []byte("0::/system.slice/directadmin.service\n"), 0o644)

	// Live HTTP server simulating site health vs HTTP 500 after broken plugin update
	liveHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		raw, _ := os.ReadFile(plugFile)
		if strings.Contains(string(raw), "throw new Error") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Fatal error in /wp-content/plugins/elementor/elementor.php"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Healthy"))
	}))
	defer liveHTTP.Close()

	feedFile := filepath.Join(tmp, "feed.json")
	_ = os.WriteFile(feedFile, []byte(`{
		"wf-elem-1": {
			"id": "wf-elem-1",
			"title": "Elementor <= 3.18.2 - RCE",
			"cve": "CVE-2024-7777",
			"cvss": {"score": 9.0, "rating": "Critical"},
			"software": [{
				"type": "plugin",
				"slug": "elementor",
				"patched": true,
				"patched_versions": ["3.18.3"],
				"affected_versions": {"all": {"from_version": "*", "from_inclusive": true, "to_version": "3.18.2", "to_inclusive": true}}
			}]
		}
	}`), 0o600)

	st, _ := store.Open(filepath.Join(tmp, "state"))
	inst, _ := st.UpsertInstance(store.InstanceRecord{
		Owner:     "reno26",
		OwnerUID:  1005,
		Domain:    "renolabs-audio.com",
		DocRoot:   docRoot,
		SiteURL:   liveHTTP.URL,
		WPVersion: "6.7.1",
	})
	jm, _ := store.NewJobManager(filepath.Join(tmp, "state"), 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		jm.Wait()
	}()
	jm.Start(ctx)

	pol := config.NewPolicyStore(filepath.Join(tmp, "plugin_data"), "")
	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()

	vdb, _ := vulndb.Open(filepath.Join(tmp, "state"), "")
	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		joined := strings.Join(spec.Args, " ")
		if strings.Contains(joined, "plugin list") {
			return `[{"name":"elementor","status":"active","update":"available","version":"3.18.1","update_version":"3.18.3"}]`, "", nil
		}
		if strings.Contains(joined, "theme list") {
			return `[]`, "", nil
		}
		if strings.Contains(joined, "plugin update") {
			_ = os.WriteFile(plugFile, []byte("<?php throw new Error('broken v3.18.3');\n"), 0o644)
		}
		return "Success", "", nil
	}

	extMgr := extensions.NewManager(domRes, wpRunner, st, vdb)
	smartEng := smartupdate.NewEngine(domRes, wpRunner, extMgr, st, filepath.Join(tmp, "staging"))

	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "secret", "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Domains = domRes
	svc.Vulns = vdb
	svc.Extensions = extMgr
	svc.SmartUpdate = smartEng

	// 1. Root Admin Socket syncs CVE feed from local JSON source
	syncResp := svc.HandleAdminRequest(ctx, auth.PeerCred{PID: 1, UID: 0, GID: 0}, ipc.Request{
		Action: "sync_vulndb",
		Params: map[string]any{"source": feedFile},
	})
	if !syncResp.OK {
		t.Fatalf("sync_vulndb failed: %+v", syncResp)
	}

	// 2. End-User Socket scans vulnerabilities & aggregates Global Plugins
	vulnResp := svc.HandleUserRequest(ctx, auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, ipc.Request{
		Action:     "get_vulns",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: inst.ID,
	})
	if !vulnResp.OK || vulnResp.CSRFToken == "" {
		t.Fatalf("get_vulns failed: %+v", vulnResp)
	}
	csrf := vulnResp.CSRFToken

	allPlugResp := svc.HandleUserRequest(ctx, auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, ipc.Request{
		Action:    "list_all_plugins",
		Username:  "reno26",
		SessionID: sessID,
	})
	if !allPlugResp.OK {
		t.Fatalf("list_all_plugins failed: %+v", allPlugResp)
	}

	// 3. End-User creates custom PluginSet & verifies built-in set cannot be deleted
	saveSetResp := svc.HandleUserRequest(ctx, auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, ipc.Request{
		Action:    "save_set",
		Username:  "reno26",
		SessionID: sessID,
		CSRFToken: csrf,
		Params: map[string]any{
			"name":    "My Agency Stack",
			"plugins": []string{"litespeed-cache", "seo-by-rank-math"},
		},
	})
	if !saveSetResp.OK {
		t.Fatalf("save_set failed: %+v", saveSetResp)
	}

	delBuiltIn := svc.HandleUserRequest(ctx, auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, ipc.Request{
		Action:    "delete_set",
		Username:  "reno26",
		SessionID: sessID,
		CSRFToken: csrf,
		Params:    map[string]any{"set_id": "set_lscache_speed"},
	})
	if delBuiltIn.OK {
		t.Fatal("expected built-in set deletion by end user to be blocked")
	}

	// 4. Smart Safe Update triggers HTTP 500 Auto-Rollback (TC-08) over IPC
	updResp := svc.HandleUserRequest(ctx, auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}, ipc.Request{
		Action:     "smart_update",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: inst.ID,
		Params: map[string]any{
			"sync":         true,
			"plugin_slugs": []string{"elementor"},
		},
	})
	if !updResp.OK {
		t.Fatalf("smart_update IPC failed: %+v", updResp)
	}
	rawOut, _ := json.Marshal(updResp.Data)
	var out smartupdate.Outcome
	_ = json.Unmarshal(rawOut, &out)
	if !out.RolledBack || !out.RestoredHealthy {
		t.Fatalf("expected IPC smart_update auto-rollback & healthy recovery, got: %+v", out)
	}
}

func TestPhase3EndToEndSecurityHardeningCoreShieldQuarantineAndBackupHooksOverIPC(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")
	stateDir := filepath.Join(tmp, "state")
	coreCacheDir := filepath.Join(tmp, "core_cache")
	quarantineDir := filepath.Join(tmp, "quarantine")
	optionsConf := filepath.Join(tmp, "options.conf")

	_ = os.WriteFile(optionsConf, []byte("webserver=openlitespeed\n"), 0o644)
	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"reno26:x:1005:1005::"+filepath.ToSlash(homeDir)+":/bin/bash\n",
	), 0o644)
	_ = os.MkdirAll(sessDir, 0o700)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("package=pro\nsuspended=no\ndomain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	// Prepare clean WordPress Core release in cleanSourceDir and customer DocRoot
	cleanSrc := filepath.Join(tmp, "clean_wp_671")
	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	cleanFiles := map[string]string{
		"index.php":                 "<?php\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n",
		"wp-includes/version.php":   "<?php\n$wp_version = '6.7.1';\n",
		"wp-includes/functions.php": "<?php\nfunction wp_clean_core_helper() {\n\treturn 'clean-6.7.1';\n}\n",
		"wp-admin/index.php":        "<?php\nrequire_once __DIR__ . '/admin.php';\n",
	}
	for rel, body := range cleanFiles {
		for _, base := range []string{cleanSrc, docRoot} {
			p := filepath.Join(base, filepath.FromSlash(rel))
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, []byte(body), 0o644)
		}
	}
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "uploads"), 0o755)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte(
		"<?php\ndefine( 'DB_NAME', 'reno26_wp1' );\n$table_prefix = 'wp_';\n/* That's all, stop editing! Happy publishing. */\n",
	), 0o644)

	sessID := "valid_phase3_session_777777"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+sessID), []byte("username=reno26\n"), 0o600)

	_ = os.MkdirAll(filepath.Join(procRoot, "500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "stat"), []byte("500 (directadmin) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "exe_path"), []byte("/usr/local/directadmin/directadmin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "status"), []byte("Name:\tdirectadmin\nUid:\t0\t0\t0\t0\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "2005"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "stat"), []byte("2005 (php) S 500 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 200 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "exe_path"), []byte("/usr/local/php84/bin/php\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2005", "cgroup"), []byte("0::/system.slice/directadmin.service\n"), 0o644)

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:          "reno26",
		OwnerUID:       1005,
		Domain:         "renolabs-audio.com",
		DocRoot:        docRoot,
		SiteURL:        "https://renolabs-audio.com",
		WPVersion:      "6.7.1",
		Locale:         "en_US",
		CoreShieldMode: config.ShieldModeAutoHeal,
	})
	if err != nil {
		t.Fatal(err)
	}

	jm, _ := store.NewJobManager(stateDir, 2)
	pol := config.NewPolicyStore(filepath.Join(tmp, "plugin_data"), "")
	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()

	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, _ wpcli.ExecSpec) (string, string, error) {
		return "Success", "", nil
	}

	wsAdapter := webserver.NewAdapter(optionsConf, filepath.Join(tmp, "nginx_snippets"))
	wsAdapter.OLSReloadDebounce = 20 * time.Millisecond
	wsAdapter.ExecCommand = func(_ context.Context, _ string, _ ...string) (string, error) {
		return "OK", nil
	}

	shield, err := integrity.NewShield(st, users, pol, integrity.ShieldConfig{
		StateDir:      stateDir,
		CoreCacheDir:  coreCacheDir,
		QuarantineDir: quarantineDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := shield.Cache.SeedVerifiedTree("6.7.1", "en_US", cleanSrc); err != nil {
		t.Fatalf("SeedVerifiedTree failed: %v", err)
	}

	hardEng := hardening.NewEngine(stateDir, wsAdapter, domRes, wpRunner, st)
	hardEng.WithShieldSuppression = shield.WithUpdatingSuppression

	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "secret", "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Domains = domRes
	svc.WebServer = wsAdapter
	svc.Hardening = hardEng
	svc.Shield = shield

	ctx, cancel := context.WithCancel(context.Background())
	rootCred := auth.PeerCred{PID: 1, UID: 0, GID: 0}
	userCred := auth.PeerCred{PID: 2005, UID: 1005, GID: 1005}
	t.Cleanup(func() {
		_ = svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
			Action:     "unlock_core",
			InstanceID: inst.ID,
		})
		cancel()
	})

	// 1. User Socket fetches get_security_status + CSRF token
	secResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "get_security_status",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: inst.ID,
	})
	if !secResp.OK || secResp.CSRFToken == "" {
		t.Fatalf("get_security_status failed: %+v", secResp)
	}
	csrf := secResp.CSRFToken

	// 2. Apply critical hardening preset (6/12 rules) over User Socket
	applyResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "apply_hardening",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: inst.ID,
		Params:     map[string]any{"preset": hardening.PresetCritical},
	})
	if !applyResp.OK {
		t.Fatalf("apply_hardening failed: %+v", applyResp)
	}
	var hRep hardening.Report
	rawH, _ := json.Marshal(applyResp.Data)
	_ = json.Unmarshal(rawH, &hRep)
	if hRep.Score != 6 || hRep.Total != 12 {
		t.Fatalf("expected critical preset score 6/12, got %d/%d", hRep.Score, hRep.Total)
	}

	// 3. Revert single toggleable rule (disable_xmlrpc -> 5/12)
	revResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "revert_hardening",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: inst.ID,
		Params:     map[string]any{"rule_ids": []string{hardening.RuleDisableXMLRPC}},
	})
	if !revResp.OK {
		t.Fatalf("revert_hardening failed: %+v", revResp)
	}
	rawRev, _ := json.Marshal(revResp.Data)
	_ = json.Unmarshal(rawRev, &hRep)
	if hRep.Score != 5 {
		t.Fatalf("expected score 5/12 after reverting disable_xmlrpc, got %d/%d", hRep.Score, hRep.Total)
	}

	// 4. Tamper wp-includes/functions.php & plant benign rogue executable in wp-admin/
	funcPath := filepath.Join(docRoot, "wp-includes", "functions.php")
	roguePath := filepath.Join(docRoot, "wp-admin", "custom_probe.php")
	_ = os.WriteFile(funcPath, []byte("<?php\nfunction wp_clean_core_helper() {\n\treturn 'tampered-line';\n}\n"), 0o644)
	_ = os.WriteFile(roguePath, []byte("<?php /* benign_phase3_ipc_probe */ $probe_flag = 42;\n"), 0o644)

	verResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "verify_core",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: inst.ID,
		Params:     map[string]any{"heal": true},
	})
	if !verResp.OK {
		t.Fatalf("verify_core failed: %+v", verResp)
	}
	var vRep integrity.VerifyReport
	rawVer, _ := json.Marshal(verResp.Data)
	_ = json.Unmarshal(rawVer, &vRep)
	if !vRep.Clean || len(vRep.HealedFiles) != 2 || len(vRep.QuarantinedIDs) != 2 {
		t.Fatalf("unexpected verify_core report: %+v", vRep)
	}
	restoredFunc, _ := os.ReadFile(funcPath)
	if string(restoredFunc) != cleanFiles["wp-includes/functions.php"] {
		t.Fatalf("wp-includes/functions.php was not restored cleanly: %q", string(restoredFunc))
	}
	if _, sErr := os.Stat(roguePath); !os.IsNotExist(sErr) {
		t.Fatalf("expected rogue executable %s to be quarantined and removed", roguePath)
	}

	// 5. Inspect Quarantine Vault & Diff Preview, then Restore + Whitelist custom_probe.php
	qListResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "list_quarantine",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: inst.ID,
	})
	if !qListResp.OK {
		t.Fatalf("list_quarantine failed: %+v", qListResp)
	}
	var qWrap struct {
		Items []integrity.QuarantineItem `json:"items"`
	}
	rawQL, _ := json.Marshal(qListResp.Data)
	_ = json.Unmarshal(rawQL, &qWrap)
	if len(qWrap.Items) != 2 {
		t.Fatalf("expected 2 quarantine items, got %d", len(qWrap.Items))
	}

	var funcQID, rogueQID string
	for _, it := range qWrap.Items {
		if it.RelPath == "wp-includes/functions.php" {
			funcQID = it.ID
		}
		if it.RelPath == "wp-admin/custom_probe.php" {
			rogueQID = it.ID
		}
	}

	diffResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:    "get_quarantine_diff",
		Username:  "reno26",
		SessionID: sessID,
		Params:    map[string]any{"quarantine_id": funcQID},
	})
	if !diffResp.OK {
		t.Fatalf("get_quarantine_diff failed: %+v", diffResp)
	}
	var diffItem integrity.QuarantineItem
	rawDiff, _ := json.Marshal(diffResp.Data)
	_ = json.Unmarshal(rawDiff, &diffItem)
	if !strings.Contains(diffItem.DiffPreview, "--- a/wp-includes/functions.php") {
		t.Fatalf("expected unified diff header in DiffPreview, got: %q", diffItem.DiffPreview)
	}

	restResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:    "restore_quarantine",
		Username:  "reno26",
		SessionID: sessID,
		CSRFToken: csrf,
		Params: map[string]any{
			"quarantine_id": rogueQID,
			"whitelist":     true,
		},
	})
	if !restResp.OK {
		t.Fatalf("restore_quarantine failed: %+v", restResp)
	}
	if _, sErr := os.Stat(roguePath); sErr != nil {
		t.Fatalf("expected restored file at %s, stat error: %v", roguePath, sErr)
	}

	wlResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "list_whitelist",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: inst.ID,
	})
	if !wlResp.OK {
		t.Fatalf("list_whitelist failed: %+v", wlResp)
	}
	rawWL, _ := json.Marshal(wlResp.Data)
	if !strings.Contains(string(rawWL), "wp-admin/custom_probe.php") {
		t.Fatalf("expected wp-admin/custom_probe.php in whitelist, got %s", string(rawWL))
	}

	// 6. Enable Fortress Core Lock & test DirectAdmin Backup Pre/Post Hooks over Admin Socket
	lockResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "lock_core",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: inst.ID,
	})
	if !lockResp.OK {
		t.Fatalf("lock_core failed: %+v", lockResp)
	}
	if wErr := os.WriteFile(funcPath, []byte("blocked"), 0o644); wErr == nil {
		t.Fatal("expected Core file write to fail with permission error while Fortress Core Lock is active")
	}
	if uErr := os.WriteFile(filepath.Join(docRoot, "wp-content", "uploads", "customer.txt"), []byte("allowed"), 0o644); uErr != nil {
		t.Fatalf("expected wp-content/uploads to remain writable under Fortress Core Lock: %v", uErr)
	}

	preResp := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "backup_pre_unlock",
		Username: "reno26",
	})
	if !preResp.OK {
		t.Fatalf("backup_pre_unlock failed: %+v", preResp)
	}
	if wErr := os.WriteFile(funcPath, []byte(cleanFiles["wp-includes/functions.php"]), 0o644); wErr != nil {
		t.Fatalf("expected Core file to be writable during DirectAdmin backup window: %v", wErr)
	}

	postResp := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action:   "backup_post_relock",
		Username: "reno26",
	})
	if !postResp.OK {
		t.Fatalf("backup_post_relock failed: %+v", postResp)
	}
	if wErr := os.WriteFile(funcPath, []byte("blocked-again"), 0o644); wErr == nil {
		t.Fatal("expected Core file to be re-locked immediately after backup_post_relock")
	}

	pingResp := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{Action: "ping"})
	rawPing, _ := json.Marshal(pingResp.Data)
	var pd ipc.PingData
	_ = json.Unmarshal(rawPing, &pd)
	if pd.WebServer != string(webserver.KindOpenLiteSpeed) {
		t.Fatalf("expected ping WebServer=openlitespeed, got %q", pd.WebServer)
	}

	unlockResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "unlock_core",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: inst.ID,
	})
	if !unlockResp.OK {
		t.Fatalf("unlock_core failed: %+v", unlockResp)
	}
}

func TestPhase4EndToEndQuickToolsSnapshotsCloneAndStagingSyncOverIPC(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")
	stateDir := filepath.Join(tmp, "state")
	optionsConf := filepath.Join(tmp, "options.conf")

	_ = os.WriteFile(optionsConf, []byte("webserver=openlitespeed\n"), 0o644)
	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"reno26:x:1005:1005::"+filepath.ToSlash(homeDir)+":/bin/bash\n",
	), 0o644)
	_ = os.MkdirAll(sessDir, 0o700)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("package=pro\nsuspended=no\ndomain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-content", "themes", "audib"), 0o755)
	_ = os.MkdirAll(filepath.Join(docRoot, "wp-includes"), 0o755)
	_ = os.WriteFile(filepath.Join(docRoot, "index.php"), []byte("<?php // Prod v1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.7.1';\n"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-content", "themes", "audib", "style.css"), []byte("/* Audib v1 */\n"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-content", "debug.log"), []byte("[05-Nov-2026 01:00:00 UTC] PHP Notice: sample tail line\n"), 0o644)
	_ = os.WriteFile(filepath.Join(docRoot, "wp-config.php"), []byte(
		"<?php\ndefine( 'DB_NAME', 'reno26_wp1' );\ndefine( 'DB_USER', 'reno26_wp1' );\ndefine( 'DB_PASSWORD', 'SecretProd1' );\ndefine( 'DB_HOST', 'localhost' );\n$table_prefix = 'wp_';\ndefine( 'WP_CACHE_KEY_SALT', 'prod_salt_ipc' );\nrequire_once ABSPATH . 'wp-settings.php';\n",
	), 0o600)

	sessID := "valid_phase4_session_888888"
	_ = os.WriteFile(filepath.Join(sessDir, "da_sess_"+sessID), []byte("username=reno26\n"), 0o600)

	_ = os.MkdirAll(filepath.Join(procRoot, "500"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "stat"), []byte("500 (directadmin) S 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 100 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "exe_path"), []byte("/usr/local/directadmin/directadmin\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "500", "status"), []byte("Name:\tdirectadmin\nUid:\t0\t0\t0\t0\n"), 0o644)

	_ = os.MkdirAll(filepath.Join(procRoot, "2006"), 0o755)
	_ = os.WriteFile(filepath.Join(procRoot, "2006", "stat"), []byte("2006 (php) S 500 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 200 1000 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2006", "exe_path"), []byte("/usr/local/php84/bin/php\n"), 0o644)
	_ = os.WriteFile(filepath.Join(procRoot, "2006", "cgroup"), []byte("0::/system.slice/directadmin.service\n"), 0o644)

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	prodInst, err := st.UpsertInstance(store.InstanceRecord{
		Owner:          "reno26",
		OwnerUID:       1005,
		Domain:         "renolabs-audio.com",
		DomainType:     dadomains.DomainTypeMain,
		DocRoot:        docRoot,
		SiteURL:        "https://renolabs-audio.com",
		SiteTitle:      "RENOLABS",
		AdminUser:      "radmin",
		WPVersion:      "6.7.1",
		DBName:         "reno26_wp1",
		DBUser:         "reno26_wp1",
		TablePrefix:    "wp_",
		SSLActive:      true,
		SearchIndexing: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	jm, _ := store.NewJobManager(stateDir, 2)
	pol := config.NewPolicyStore(filepath.Join(tmp, "plugin_data"), "")
	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()

	domRes := dadomains.NewResolver(daRoot, daphp.NewResolver("", ""))
	wpRunner := wpcli.NewRunner("/usr/local/bin/wp", "")
	wpRunner.NiceBin = ""
	wpRunner.IoniceBin = ""
	wpRunner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		for i := 0; i < len(spec.Args); i++ {
			if spec.Args[i] == "db" && i+2 < len(spec.Args) && spec.Args[i+1] == "export" {
				_ = os.WriteFile(spec.Args[i+2], []byte("INSERT INTO `wp_options` VALUES ('siteurl','https://renolabs-audio.com');\n"), 0o600)
				return "Success", "", nil
			}
			if spec.Args[i] == "search-replace" {
				return "Table,Column,Replacements,Type\nwp_options,option_value,2,PHP\n", "", nil
			}
		}
		return "Success", "", nil
	}

	wsAdapter := webserver.NewAdapter(optionsConf, filepath.Join(tmp, "nginx_snippets"))
	wsAdapter.OLSReloadDebounce = 15 * time.Millisecond
	wsAdapter.ExecCommand = func(_ context.Context, _ string, _ ...string) (string, error) {
		return "OK", nil
	}

	cronMgr := quicktools.NewDACronManager(daRoot)
	cronMgr.InstallCrontab = func(_ context.Context, _ string, _ string) error { return nil }
	qtMgr := quicktools.NewManager(domRes, wpRunner, wsAdapter, cronMgr, st)

	snapMgr, err := snapshot.NewManager(stateDir, domRes, wpRunner, st, pol)
	if err != nil {
		t.Fatal(err)
	}
	snapMgr.ZstdBin = filepath.Join(tmp, "no-zstd")

	dbProv := &testDBProv{}
	cloneEng := clonesync.NewEngine(domRes, dbProv, wpRunner, snapMgr, st, pol)

	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "secret", "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Domains = domRes
	svc.WebServer = wsAdapter
	svc.QuickTools = qtMgr
	svc.Snapshots = snapMgr
	svc.CloneSync = cloneEng

	ctx := context.Background()
	userCred := auth.PeerCred{PID: 2006, UID: 1005, GID: 1005}

	// 1. Read-only get_tools_status & read_debug_log over User Socket
	statusResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "get_tools_status",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: prodInst.ID,
	})
	if !statusResp.OK || statusResp.CSRFToken == "" {
		t.Fatalf("get_tools_status failed: %+v", statusResp)
	}
	csrf := statusResp.CSRFToken

	logResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "read_debug_log",
		Username:   "reno26",
		SessionID:  sessID,
		InstanceID: prodInst.ID,
	})
	if !logResp.OK {
		t.Fatalf("read_debug_log failed: %+v", logResp)
	}

	// 2. Toggle Maintenance Mode, HTTP Password Protection, WP-Cron Takeover, and Dry-Run Search & Replace
	maintResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "set_maintenance_mode",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: prodInst.ID,
		Params:     map[string]any{"enabled": true, "headline": "Nâng cấp hệ thống"},
	})
	if !maintResp.OK {
		t.Fatalf("set_maintenance_mode failed: %+v", maintResp)
	}

	pwResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "set_password_protection",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: prodInst.ID,
		Params:     map[string]any{"enabled": true, "username": "vipclient", "password": "StrongStagePass99"},
	})
	if !pwResp.OK {
		t.Fatalf("set_password_protection failed: %+v", pwResp)
	}

	cronResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "set_wp_cron",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: prodInst.ID,
		Params:     map[string]any{"disable_wp_cron": true, "interval_min": 15},
	})
	if !cronResp.OK {
		t.Fatalf("set_wp_cron failed: %+v", cronResp)
	}

	srResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "search_replace",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: prodInst.ID,
		Params: map[string]any{
			"search":  "http://renolabs-audio.com",
			"replace": "https://renolabs-audio.com",
			"dry_run": true,
		},
	})
	if !srResp.OK {
		t.Fatalf("search_replace dry_run failed: %+v", srResp)
	}

	// 3. Create & list Zstd Snapshot over User Socket
	snapResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "create_snapshot",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: prodInst.ID,
		Params:     map[string]any{"sync": true, "note": "IPC snapshot test"},
	})
	if !snapResp.OK {
		t.Fatalf("create_snapshot failed: %+v", snapResp)
	}

	// 4. Clone Production -> `staging.renolabs-audio.com` (sync=true) & push Staging -> Production via `sync_instance`
	cloneResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "clone_instance",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: prodInst.ID,
		Params: map[string]any{
			"sync":          true,
			"target_domain": "staging.renolabs-audio.com",
		},
	})
	if !cloneResp.OK {
		t.Fatalf("clone_instance failed: %+v", cloneResp)
	}
	var cRes clonesync.CloneResult
	rawClone, _ := json.Marshal(cloneResp.Data)
	_ = json.Unmarshal(rawClone, &cRes)
	if cRes.Instance.ID == "" || cRes.CacheKeySalt == "prod_salt_ipc" || cRes.Instance.SearchIndexing {
		t.Fatalf("unexpected clone_instance result: %+v", cRes)
	}

	syncResp := svc.HandleUserRequest(ctx, userCred, ipc.Request{
		Action:     "sync_instance",
		Username:   "reno26",
		SessionID:  sessID,
		CSRFToken:  csrf,
		InstanceID: cRes.Instance.ID,
		Params: map[string]any{
			"sync":               true,
			"target_instance_id": prodInst.ID,
			"mode":               "both",
		},
	})
	if !syncResp.OK {
		t.Fatalf("sync_instance failed: %+v", syncResp)
	}
	var sRes clonesync.SyncResult
	rawSync, _ := json.Marshal(syncResp.Data)
	_ = json.Unmarshal(rawSync, &sRes)
	if sRes.PreSyncSnapshotID == "" {
		t.Fatalf("expected sync_instance to record pre_sync_snapshot_id, got %+v", sRes)
	}
}

func TestPhase5AdminPoliciesCoreCachePruneAndGitHubUpdaterOverIPC(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")
	procRoot := filepath.Join(tmp, "proc")
	sessDir := filepath.Join(daRoot, "sessions")
	stateDir := filepath.Join(tmp, "state")
	coreCacheDir := filepath.Join(tmp, "core_cache")

	_ = os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"admin:x:1001:1001::/home/admin:/bin/bash\n"+
			"reno26:x:1005:1005::"+filepath.ToSlash(homeDir)+":/bin/bash\n",
	), 0o644)
	_ = os.MkdirAll(sessDir, 0o700)
	_ = os.MkdirAll(filepath.Join(daRoot, "admin"), 0o755)
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "admin.list"), []byte("admin\n"), 0o600)
	_ = os.WriteFile(filepath.Join(daRoot, "admin", "packages.list"), []byte("starter\npro\nbusiness\n"), 0o600)

	userDir := filepath.Join(daRoot, "users", "reno26")
	_ = os.MkdirAll(userDir, 0o755)
	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("package=pro\nsuspended=no\n"), 0o600)

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	jm, _ := store.NewJobManager(stateDir, 1)
	pol := config.NewPolicyStore(filepath.Join(tmp, "plugin_data"), filepath.Join(tmp, "etc", "updater.conf"))
	users := dausers.NewRegistry(daRoot, passwd)
	_ = users.Reload()

	shield, err := integrity.NewShield(st, users, pol, integrity.ShieldConfig{
		StateDir:      stateDir,
		CoreCacheDir:  coreCacheDir,
		QuarantineDir: filepath.Join(tmp, "quarantine"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cleanSrc := filepath.Join(tmp, "clean_core")
	_ = os.MkdirAll(filepath.Join(cleanSrc, "wp-includes"), 0o755)
	_ = os.WriteFile(filepath.Join(cleanSrc, "index.php"), []byte("<?php // clean\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cleanSrc, "wp-includes", "version.php"), []byte("<?php $wp_version='6.7.1';\n"), 0o644)
	if _, err := shield.Cache.SeedVerifiedTree("6.7.1", "en_US", cleanSrc); err != nil {
		t.Fatal(err)
	}

	var gotAuthHeader string
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"tag_name":"v1.2.0","name":"DA-WordPressToolkits v1.2.0","draft":false,"prerelease":false,"published_at":"2026-11-05T00:00:00Z","html_url":"https://github.com/shostwp-byte/da-wordpresstoolkit/releases/tag/v1.2.0","body":"### Highlights\n- Ed25519 Signed Release"}]`))
	}))
	defer ghServer.Close()

	guard := auth.NewGuard(users, st, procRoot, sessDir, filepath.Join(tmp, "secret", "csrf.key"))
	svc := NewService(st, jm, pol, users, guard)
	svc.Shield = shield
	svc.GitHubAPIBase = ghServer.URL

	ctx := context.Background()
	rootCred := auth.PeerCred{PID: 1, UID: 0, GID: 0}

	// 1. list_packages discovers starter, pro (1 account), business
	pkgResp := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{Action: "list_packages"})
	if !pkgResp.OK {
		t.Fatalf("list_packages failed: %+v", pkgResp)
	}
	rawPkgs, _ := json.Marshal(pkgResp.Data)
	if !strings.Contains(string(rawPkgs), `"name":"pro"`) || !strings.Contains(string(rawPkgs), `"account_count":1`) {
		t.Fatalf("expected pro package with account_count=1, got %s", string(rawPkgs))
	}

	// 2. save_package_policy + delete_package_policy
	savePkg := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "save_package_policy",
		Params: map[string]any{
			"package_name":           "starter",
			"max_instances":          3,
			"allow_clone":            false,
			"max_snapshots_per_site": 2,
		},
	})
	if !savePkg.OK {
		t.Fatalf("save_package_policy failed: %+v", savePkg)
	}
	resolvedStarter, _ := pol.ResolvePackagePolicy("starter")
	if resolvedStarter.MaxInstances != 3 || resolvedStarter.AllowClone {
		t.Fatalf("unexpected saved starter policy: %+v", resolvedStarter)
	}

	delPkg := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "delete_package_policy",
		Params: map[string]any{"package_name": "starter"},
	})
	if !delPkg.OK {
		t.Fatalf("delete_package_policy failed: %+v", delPkg)
	}
	inheritedStarter, _ := pol.ResolvePackagePolicy("starter")
	if !inheritedStarter.AllowClone || inheritedStarter.MaxInstances != 0 {
		t.Fatalf("expected starter to inherit default policy after delete, got %+v", inheritedStarter)
	}

	// 3. delete_core_cache removes seeded 6.7.1-en_US release
	delCache := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "delete_core_cache",
		Params: map[string]any{"wp_version": "6.7.1", "locale": "en_US"},
	})
	if !delCache.OK || len(shield.Cache.Status().Releases) != 0 {
		t.Fatalf("delete_core_cache failed: %+v", delCache)
	}

	// 4. save_updater_config masks token & check_github_update detects v1.2.0
	saveUpd := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{
		Action: "save_updater_config",
		Params: map[string]any{
			"update_channel":   "stable",
			"backup_retention": 7,
			"github_token":     "ghp_TestMaskedSecret999",
		},
	})
	if !saveUpd.OK {
		t.Fatalf("save_updater_config failed: %+v", saveUpd)
	}
	getUpd := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{Action: "get_updater_config"})
	rawUpd, _ := json.Marshal(getUpd.Data)
	if strings.Contains(string(rawUpd), "ghp_TestMaskedSecret999") || !strings.Contains(string(rawUpd), `"has_github_token":true`) {
		t.Fatalf("updater config leaked secret or missed has_github_token: %s", string(rawUpd))
	}

	chkUpd := svc.HandleAdminRequest(ctx, rootCred, ipc.Request{Action: "check_github_update"})
	if !chkUpd.OK {
		t.Fatalf("check_github_update failed: %+v", chkUpd)
	}
	rawChk, _ := json.Marshal(chkUpd.Data)
	if !strings.Contains(string(rawChk), `"update_available":true`) || !strings.Contains(string(rawChk), `"latest_version":"v1.2.0"`) {
		t.Fatalf("unexpected check_github_update output: %s", string(rawChk))
	}
	if gotAuthHeader != "Bearer ghp_TestMaskedSecret999" {
		t.Fatalf("expected Bearer token header sent to GitHub API, got %q", gotAuthHeader)
	}
}
