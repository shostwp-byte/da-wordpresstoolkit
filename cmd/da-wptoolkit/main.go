package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
	"github.com/shostwp-byte/da-wptoolkits/internal/clonesync"
	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daemon"
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
	"github.com/shostwp-byte/da-wptoolkits/internal/updater"
	"github.com/shostwp-byte/da-wptoolkits/internal/version"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/webserver"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

const (
	DefaultPluginDataDir  = "/usr/local/directadmin/plugins/da_wp_toolkits/data"
	DefaultUpdaterCfgPath = "/etc/da-wptoolkit/updater.conf"
	DefaultDADataRoot     = "/usr/local/directadmin/data"
	DefaultPasswdPath     = "/etc/passwd"
	DefaultCoreCacheDir   = "/var/cache/da-wptoolkit/wp-core"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[da-wptoolkit] ")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "version", "-v", "--version":
		fmt.Println(version.Info())

	case "ping":
		err = runPing(os.Args[2:])

	case "serve":
		err = runServe(os.Args[2:])

	case "scan":
		err = runScan(os.Args[2:])

	case "list":
		err = runList(os.Args[2:])

	case "install":
		err = runInstall(os.Args[2:])

	case "uninstall":
		err = runUninstall(os.Args[2:])

	case "detach":
		err = runDetach(os.Args[2:])

	case "sso":
		err = runSSO(os.Args[2:])

	case "sync-vulndb":
		err = runSyncVulnDB(os.Args[2:])

	case "plugins":
		err = runExtensionsCLI(false, os.Args[2:])

	case "themes":
		err = runExtensionsCLI(true, os.Args[2:])

	case "smart-update":
		err = runSmartUpdateCLI(os.Args[2:])

	case "bulk-update":
		err = runBulkUpdateCLI(os.Args[2:])

	case "verify-core":
		err = runVerifyCoreCLI(os.Args[2:])

	case "lock-core":
		err = runCoreLockCLI(true, os.Args[2:])

	case "unlock-core":
		err = runCoreLockCLI(false, os.Args[2:])

	case "shield-mode":
		err = runShieldModeCLI(os.Args[2:])

	case "harden":
		err = runHardenCLI(os.Args[2:])

	case "quarantine":
		err = runQuarantineCLI(os.Args[2:])

	case "tools":
		err = runToolsCLI(os.Args[2:])

	case "search-replace":
		err = runSearchReplaceCLI(os.Args[2:])

	case "snapshot":
		err = runSnapshotCLI(os.Args[2:])

	case "clone":
		err = runCloneCLI(os.Args[2:])

	case "sync":
		err = runSyncCLI(os.Args[2:])

	case "backup-hook":
		err = runBackupHookCLI(os.Args[2:])

	case "cleanup-owner":
		err = runCleanupOwnerCLI(os.Args[2:])

	case "hook":
		err = runDAHookCLI(os.Args[2:])

	case "check-update":
		err = runCheckUpdateCLI(os.Args[2:])

	case "update":
		err = runSelfUpdateCLI(os.Args[2:])

	case "rollback":
		err = runRollbackCLI(os.Args[2:])

	case "apply-staged":
		err = runApplyStagedCLI(os.Args[2:])

	case "keygen":
		err = runKeygenCLI()

	case "sign-release":
		err = runSignReleaseCLI(os.Args[2:])

	case "verify-release":
		err = runVerifyReleaseCLI(os.Args[2:])

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		log.Fatalf("%s failed: %v", os.Args[1], err)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	adminSock := fs.String("admin-sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	userSock := fs.String("user-sock", getenvOr("DA_WPTK_USER_SOCK", ipc.DefaultUserSocketPath), "End-User Unix socket path")
	stateDir := fs.String("state-dir", getenvOr("DA_WPTK_STATE_DIR", store.DefaultStateDir), "Persistent state directory")
	workers := fs.Int("workers", store.DefaultWorkerCount, "Background job worker count")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := store.Open(*stateDir)
	if err != nil {
		return fmt.Errorf("open state store: %w", err)
	}
	jm, err := store.NewJobManager(*stateDir, *workers)
	if err != nil {
		return fmt.Errorf("init job manager: %w", err)
	}

	dataDir := getenvOr("DA_WPTK_DATA_DIR", DefaultPluginDataDir)
	updaterCfg := getenvOr("DA_WPTK_UPDATER_CONF", DefaultUpdaterCfgPath)
	daRoot := getenvOr("DA_WPTK_DA_DATA_ROOT", DefaultDADataRoot)
	passwdPath := getenvOr("DA_WPTK_PASSWD_PATH", DefaultPasswdPath)
	procRoot := getenvOr("DA_WPTK_PROC_ROOT", auth.DefaultProcRoot)
	sessDir := getenvOr("DA_WPTK_SESSIONS_DIR", auth.DefaultDASessionsDir)
	csrfKey := getenvOr("DA_WPTK_CSRF_KEY_PATH", auth.DefaultCSRFKeyPath)

	optionsConf := getenvOr("DA_WPTK_OPTIONS_CONF", daphp.DefaultOptionsConfPath)
	usrLocalRoot := getenvOr("DA_WPTK_USR_LOCAL", daphp.DefaultUsrLocalRoot)
	daMySQLConf := getenvOr("DA_WPTK_DA_MYSQL_CONF", database.DefaultDAMySQLConfPath)
	daAPIConf := getenvOr("DA_WPTK_DA_API_CONF", database.DefaultDAAPIConfPath)
	daHooksDir := getenvOr("DA_WPTK_DA_HOOKS_DIR", database.DefaultDAHooksDir)
	wpcliBin := getenvOr("DA_WPTK_WPCLI_BIN", wpcli.DefaultWPCLIBinPath)
	coreCacheDir := getenvOr("DA_WPTK_CORE_CACHE_DIR", DefaultCoreCacheDir)
	vulnFeedURL := getenvOr("DA_WPTK_VULN_FEED_URL", vulndb.DefaultWordfenceFeedURL)
	stagingBaseDir := getenvOr("DA_WPTK_STAGING_DIR", filepath.Join(filepath.Dir(*stateDir), "staging", "rollback"))
	nginxSnippetDir := getenvOr("DA_WPTK_NGINX_SNIPPET_DIR", webserver.DefaultNginxSnippetDir)
	quarantineDir := getenvOr("DA_WPTK_QUARANTINE_DIR", integrity.DefaultQuarantineDir)

	pol := config.NewPolicyStore(dataDir, updaterCfg)
	users := dausers.NewRegistry(daRoot, passwdPath)
	_ = users.Reload()

	vdb, err := vulndb.Open(*stateDir, vulnFeedURL)
	if err != nil {
		return fmt.Errorf("init vulndb: %w", err)
	}

	phpResolver := daphp.NewResolver(optionsConf, usrLocalRoot)
	domResolver := dadomains.NewResolver(daRoot, phpResolver)
	dbManager := database.NewManager(daMySQLConf, daAPIConf, daHooksDir)
	wpRunner := wpcli.NewRunner(wpcliBin, coreCacheDir)
	scanner := discovery.NewScanner(domResolver, st, pol)
	scanner.Vulns = vdb

	lifeManager := lifecycle.NewManager(domResolver, dbManager, wpRunner, st, pol, coreCacheDir)
	extManager := extensions.NewManager(domResolver, wpRunner, st, vdb)
	extManager.LiveUpdateCheck = getenvOr("DA_WPTK_LIVE_WPORG_CHECK", "1") != "0"
	smartEngine := smartupdate.NewEngine(domResolver, wpRunner, extManager, st, stagingBaseDir)

	wsAdapter := webserver.NewAdapter(optionsConf, nginxSnippetDir)
	shield, err := integrity.NewShield(st, users, pol, integrity.ShieldConfig{
		StateDir:      *stateDir,
		CoreCacheDir:  coreCacheDir,
		QuarantineDir: quarantineDir,
	})
	if err != nil {
		return fmt.Errorf("init core integrity shield: %w", err)
	}
	hardEngine := hardening.NewEngine(*stateDir, wsAdapter, domResolver, wpRunner, st)
	hardEngine.WithShieldSuppression = shield.WithUpdatingSuppression

	cronManager := quicktools.NewDACronManager(daRoot)
	qtManager := quicktools.NewManager(domResolver, wpRunner, wsAdapter, cronManager, st)
	qtManager.WithShieldSuppression = shield.WithUpdatingSuppression

	snapManager, err := snapshot.NewManager(*stateDir, domResolver, wpRunner, st, pol)
	if err != nil {
		return fmt.Errorf("init snapshot manager: %w", err)
	}
	snapManager.WithShieldSuppression = shield.WithUpdatingSuppression

	cloneEngine := clonesync.NewEngine(domResolver, dbManager, wpRunner, snapManager, st, pol)
	cloneEngine.DAAPIConfPath = daAPIConf
	cloneEngine.DAHooksDir = daHooksDir
	cloneEngine.WithShieldSuppression = shield.WithUpdatingSuppression

	guard := auth.NewGuard(users, st, procRoot, sessDir, csrfKey)
	svc := daemon.NewService(st, jm, pol, users, guard)
	svc.Domains = domResolver
	svc.Scanner = scanner
	svc.Lifecycle = lifeManager
	svc.Vulns = vdb
	svc.Extensions = extManager
	svc.SmartUpdate = smartEngine
	svc.WebServer = wsAdapter
	svc.Hardening = hardEngine
	svc.Shield = shield
	svc.QuickTools = qtManager
	svc.Snapshots = snapManager
	svc.CloneSync = cloneEngine

	updManager := updater.NewManager(*stateDir, st)
	updManager.AdminSockPath = *adminSock
	updManager.BinPath = getenvOr("DA_WPTK_BIN_PATH", updater.DefaultBinPath)
	updManager.PluginDir = getenvOr("DA_WPTK_PLUGIN_DIR", updater.DefaultPluginDir)
	updManager.HooksBaseDir = getenvOr("DA_WPTK_CUSTOM_HOOKS_DIR", updater.DefaultHooksBaseDir)
	updManager.ShareDir = getenvOr("DA_WPTK_SHARE_DIR", updater.DefaultShareDir)
	svc.Updater = updManager

	srv := ipc.NewServer(*adminSock, *userSock, svc)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	jm.Start(ctx)
	if err := shield.Start(ctx); err != nil {
		log.Printf("warning: core integrity shield watcher: %v", err)
	}
	if getenvOr("DA_WPTK_AUTO_VULNSYNC", "1") != "0" {
		vdb.StartAutoSync(ctx, vulndb.DefaultSyncInterval, func(s vulndb.Status) {
			log.Printf("synced Wordfence CVE feed: rules=%d plugins=%d themes=%d", s.TotalRules, s.IndexedPlugins, s.IndexedThemes)
		})
	}

	if err := srv.Start(ctx); err != nil {
		stop()
		jm.Wait()
		return err
	}

	log.Printf("started %s (admin=%s, user=%s, webserver=%s)", version.Info(), *adminSock, *userSock, wsAdapter.DetectKind())
	<-ctx.Done()
	log.Printf("shutting down gracefully...")

	srv.Wait()
	jm.Wait()
	return nil
}

func runPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{Action: "ping"})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	raw, _ := json.Marshal(resp.Data)
	fmt.Printf("OK: %s\n", string(raw))
	return nil
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	user := fs.String("user", "", "DirectAdmin username to scan")
	all := fs.Bool("all", false, "Scan all DirectAdmin hosting accounts on the server")
	reattach := fs.Bool("reattach", false, "Re-attach previously detached WordPress instances")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*user) == "" && !*all {
		return errors.New("specify either --user <username> or --all")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:   "scan_instances",
		Username: strings.TrimSpace(*user),
		Params:   map[string]any{"reattach": *reattach},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}

	var res discovery.ScanResult
	if err := remarshal(resp.Data, &res); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf(
		"Scan completed: targets=%d discovered=%d added=%d updated=%d\n",
		res.ScannedTargets,
		res.DiscoveredTotal,
		res.AddedCount,
		res.UpdatedCount,
	)
	for _, inst := range res.Instances {
		fmt.Printf("  - [%s] %-26s WP %-7s PHP %-4s vulns=%d (%s)\n", inst.ID, inst.Domain+inst.SubPath, inst.WPVersion, inst.PHPVersion, inst.VulnCount, inst.DocRoot)
	}
	return nil
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	user := fs.String("user", "", "Filter by DirectAdmin username")
	vulnOnly := fs.Bool("vuln", false, "Show only instances with active CVE vulnerabilities")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:   "list_instances",
		Username: strings.TrimSpace(*user),
		Params:   map[string]any{"vuln_only": *vulnOnly},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}

	var wrapper struct {
		Instances []store.InstanceRecord `json:"instances"`
	}
	if err := remarshal(resp.Data, &wrapper); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	if len(wrapper.Instances) == 0 {
		fmt.Println("No managed WordPress instances found.")
		return nil
	}
	fmt.Printf("Managed WordPress instances (%d):\n", len(wrapper.Instances))
	for _, inst := range wrapper.Instances {
		fmt.Printf(
			"  - [%s] owner=%-10s site=%-26s WP=%-7s PHP=%-4s shield=%-13s sec=%d/%d updates=%d vulns=%d\n",
			inst.ID,
			inst.Owner,
			inst.Domain+inst.SubPath,
			inst.WPVersion,
			inst.PHPVersion,
			inst.CoreShieldMode,
			inst.SecurityScore,
			inst.SecurityTotal,
			inst.UpdateCount,
			inst.VulnCount,
		)
	}
	return nil
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	user := fs.String("user", "", "Target DirectAdmin username (required)")
	domain := fs.String("domain", "", "Target domain or subdomain (required)")
	subPath := fs.String("subpath", "", "Optional subdirectory path (e.g. /blog)")
	siteTitle := fs.String("title", "", "WordPress site title")
	adminUser := fs.String("admin-user", "", "WordPress admin username (auto-generated if omitted)")
	adminEmail := fs.String("admin-email", "", "WordPress admin email")
	locale := fs.String("locale", "vi", "WordPress locale")
	wpVer := fs.String("wp-version", "", "Specific WordPress version (default: latest)")
	tablePrefix := fs.String("table-prefix", "", "Custom database table prefix (e.g. wp_a1_)")
	setID := fs.String("set", "", "Optional Plugin/Theme Set ID to apply after install")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*user) == "" || strings.TrimSpace(*domain) == "" {
		return errors.New("both --user and --domain are required")
	}

	envPass := os.Getenv("DA_WPTK_ADMIN_PASSWORD")

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:   "install_instance",
		Username: strings.TrimSpace(*user),
		Params: map[string]any{
			"sync":           true,
			"domain":         strings.TrimSpace(*domain),
			"sub_path":       strings.TrimSpace(*subPath),
			"site_title":     strings.TrimSpace(*siteTitle),
			"admin_user":     strings.TrimSpace(*adminUser),
			"admin_password": envPass,
			"admin_email":    strings.TrimSpace(*adminEmail),
			"locale":         strings.TrimSpace(*locale),
			"wp_version":     strings.TrimSpace(*wpVer),
			"table_prefix":   strings.TrimSpace(*tablePrefix),
			"set_id":         strings.TrimSpace(*setID),
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}

	var res lifecycle.InstallResult
	if err := remarshal(resp.Data, &res); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf("Installed WordPress successfully!\n")
	fmt.Printf("  Instance ID : %s\n", res.Instance.ID)
	fmt.Printf("  Site URL    : %s\n", res.Instance.SiteURL)
	fmt.Printf("  DocRoot     : %s\n", res.Instance.DocRoot)
	fmt.Printf("  Database    : %s (user: %s)\n", res.Instance.DBName, res.Instance.DBUser)
	fmt.Printf("  Admin User  : %s\n", res.AdminUser)
	if res.GeneratedPassword != "" {
		fmt.Printf("  Admin Pass  : %s (shown once — never stored on disk)\n", res.GeneratedPassword)
	}
	return nil
}

func runUninstall(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	dropDB := fs.Bool("drop-db", false, "Also drop the associated MariaDB database and user")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id <wp_id> is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 60 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "uninstall_instance",
		InstanceID: strings.TrimSpace(*id),
		Params:     map[string]any{"drop_db": *dropDB},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	fmt.Printf("Uninstalled WordPress instance %s (drop_db=%v)\n", strings.TrimSpace(*id), *dropDB)
	return nil
}

func runDetach(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("detach", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id <wp_id> is required")
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "detach_instance",
		InstanceID: strings.TrimSpace(*id),
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	fmt.Printf("Detached WordPress instance %s (files & database preserved)\n", strings.TrimSpace(*id))
	return nil
}

func runSSO(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("sso", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	adminUser := fs.String("admin-user", "", "Specific WordPress administrator login (optional)")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id <wp_id> is required")
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "sso_login",
		InstanceID: strings.TrimSpace(*id),
		Params:     map[string]any{"admin_user": strings.TrimSpace(*adminUser)},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}

	var sso lifecycle.SSOResult
	if err := remarshal(resp.Data, &sso); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf("One-Time SSO URL (expires in %ds):\n%s\n", sso.ExpiresIn, sso.LoginURL)
	return nil
}

func runSyncVulnDB(args []string) error {
	fs := flag.NewFlagSet("sync-vulndb", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	source := fs.String("source", "", "Optional custom Wordfence v2 feed URL or local .json/.json.gz path")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action: "sync_vulndb",
		Params: map[string]any{"source": strings.TrimSpace(*source)},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	var st vulndb.Status
	if err := remarshal(resp.Data, &st); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf(
		"Synced CVE Database: total_rules=%d plugins=%d themes=%d core=%d\n",
		st.TotalRules,
		st.IndexedPlugins,
		st.IndexedThemes,
		st.CoreRules,
	)
	return nil
}

func runExtensionsCLI(isTheme bool, args []string) error {
	label := "plugins"
	listAction := "list_plugins"
	mutAction := "manage_plugin"
	if isTheme {
		label = "themes"
		listAction = "list_themes"
		mutAction = "manage_theme"
	}

	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet(label, flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	op := fs.String("op", "list", "Operation: list | activate | deactivate | delete | autoupdate_on | autoupdate_off | install_slug | install_zip")
	slug := fs.String("slug", "", "Extension slug or comma-separated slugs")
	zipPath := fs.String("zip", "", "Local .zip package path (for install_zip)")
	activate := fs.Bool("activate", false, "Activate immediately after install")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id <wp_id> is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second

	cleanOp := strings.ToLower(strings.TrimSpace(*op))
	var req ipc.Request
	if cleanOp == "" || cleanOp == "list" {
		req = ipc.Request{
			Action:     listAction,
			InstanceID: strings.TrimSpace(*id),
		}
	} else {
		req = ipc.Request{
			Action:     mutAction,
			InstanceID: strings.TrimSpace(*id),
			Params: map[string]any{
				"operation": cleanOp,
				"slug":      strings.TrimSpace(*slug),
				"zip_path":  strings.TrimSpace(*zipPath),
				"activate":  *activate,
			},
		}
	}

	resp, err := cli.Send(context.Background(), req)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runSmartUpdateCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("smart-update", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	plugins := fs.String("plugins", "", "Comma-separated plugin slugs to update")
	allPlugins := fs.Bool("all-plugins", false, "Update all outdated plugins")
	themes := fs.String("themes", "", "Comma-separated theme slugs to update")
	allThemes := fs.Bool("all-themes", false, "Update all outdated themes")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("--id <wp_id> is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "smart_update",
		InstanceID: strings.TrimSpace(*id),
		Params: map[string]any{
			"sync":         true,
			"plugin_slugs": strings.TrimSpace(*plugins),
			"all_plugins":  *allPlugins,
			"theme_slugs":  strings.TrimSpace(*themes),
			"all_themes":   *allThemes,
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}

	var out smartupdate.Outcome
	if err := remarshal(resp.Data, &out); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	if out.RolledBack {
		fmt.Printf(
			"SMART AUTO-ROLLBACK TRIGGERED on %s (%dms): %s | culprits=%v | site_recovered=%v\n",
			out.Domain+out.SubPath,
			out.RollbackMillis,
			out.FaultReason,
			out.CulpritSlugs,
			out.RestoredHealthy,
		)
		return nil
	}
	fmt.Printf(
		"Smart Safe Update [%s] on %s (%dms): plugins=%v themes=%v\n",
		out.Status,
		out.Domain+out.SubPath,
		out.TotalElapsedMs,
		out.UpdatedPlugins,
		out.UpdatedThemes,
	)
	return nil
}

func runBulkUpdateCLI(args []string) error {
	fs := flag.NewFlagSet("bulk-update", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	ids := fs.String("ids", "", "Comma-separated WordPress Instance IDs")
	plugins := fs.String("plugins", "", "Comma-separated plugin slugs")
	allPlugins := fs.Bool("all-plugins", false, "Update all outdated plugins across selected instances")
	themes := fs.String("themes", "", "Comma-separated theme slugs")
	allThemes := fs.Bool("all-themes", false, "Update all outdated themes across selected instances")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*ids) == "" {
		return errors.New("--ids <wp_1,wp_2> is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action: "bulk_smart_update",
		Params: map[string]any{
			"sync":         true,
			"instance_ids": strings.TrimSpace(*ids),
			"plugin_slugs": strings.TrimSpace(*plugins),
			"all_plugins":  *allPlugins,
			"theme_slugs":  strings.TrimSpace(*themes),
			"all_themes":   *allThemes,
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runVerifyCoreCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("verify-core", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	all := fs.Bool("all", false, "Verify all managed WordPress instances across the server")
	checkOnly := fs.Bool("check-only", false, "Verify checksums only without triggering Auto-Heal")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" && !*all {
		return errors.New("specify either <wp_id> / --id <wp_id> or --all")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 180 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "verify_core",
		InstanceID: strings.TrimSpace(*id),
		Params: map[string]any{
			"all":  *all,
			"heal": !*checkOnly,
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	if *all {
		return emitPrettyJSON(resp.Data)
	}

	var rep integrity.VerifyReport
	if err := remarshal(resp.Data, &rep); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf(
		"Core Integrity [%s] clean=%v mode=%s checked=%d modified=%d missing=%d unknown_exec=%d healed=%d quarantined=%d (%dms)\n",
		rep.Domain,
		rep.Clean,
		rep.Mode,
		rep.CheckedFiles,
		len(rep.ModifiedFiles),
		len(rep.MissingFiles),
		len(rep.UnknownExecutables),
		len(rep.HealedFiles),
		len(rep.QuarantinedIDs),
		rep.ElapsedMillis,
	)
	return nil
}

func runCoreLockCLI(lock bool, args []string) error {
	name := "unlock-core"
	action := "unlock_core"
	if lock {
		name = "lock-core"
		action = "lock_core"
	}
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	mode := fs.String("mode", config.ShieldModeAutoHeal, "Target shield mode after unlock (auto_heal | monitor)")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("specify <wp_id> or --id <wp_id>")
	}

	params := map[string]any{}
	if !lock {
		params["mode"] = strings.TrimSpace(*mode)
	}
	cli := ipc.NewClient(*sock)
	cli.Timeout = 60 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     action,
		InstanceID: strings.TrimSpace(*id),
		Params:     params,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}

	var inst store.InstanceRecord
	if err := remarshal(resp.Data, &inst); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf("Updated Core Shield Mode for %s (%s): %s\n", inst.ID, inst.Domain+inst.SubPath, inst.CoreShieldMode)
	return nil
}

func runShieldModeCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("shield-mode", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	mode := fs.String("mode", "", "Shield mode: monitor | auto_heal | fortress_lock")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" || strings.TrimSpace(*mode) == "" {
		return errors.New("--id <wp_id> and --mode <monitor|auto_heal|fortress_lock> are required")
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "set_shield_mode",
		InstanceID: strings.TrimSpace(*id),
		Params:     map[string]any{"mode": strings.TrimSpace(*mode)},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runHardenCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("harden", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	preset := fs.String("preset", "", "Hardening preset: critical | recommended | all")
	rules := fs.String("rules", "", "Comma-separated hardening rule IDs")
	newAdmin := fs.String("new-admin", "", "Replacement admin username (for rename_default_admin)")
	newPrefix := fs.String("new-prefix", "", "Replacement DB table prefix (for change_db_prefix)")
	revert := fs.Bool("revert", false, "Revert specified toggleable hardening rules")
	statusOnly := fs.Bool("status", false, "Inspect current security hardening status without mutating")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" {
		return errors.New("specify <wp_id> or --id <wp_id>")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 120 * time.Second

	var req ipc.Request
	switch {
	case *statusOnly || (!*revert && strings.TrimSpace(*preset) == "" && strings.TrimSpace(*rules) == ""):
		req = ipc.Request{
			Action:     "get_security_status",
			InstanceID: strings.TrimSpace(*id),
		}
	case *revert:
		req = ipc.Request{
			Action:     "revert_hardening",
			InstanceID: strings.TrimSpace(*id),
			Params:     map[string]any{"rule_ids": strings.TrimSpace(*rules)},
		}
	default:
		req = ipc.Request{
			Action:     "apply_hardening",
			InstanceID: strings.TrimSpace(*id),
			Params: map[string]any{
				"preset":           strings.TrimSpace(*preset),
				"rule_ids":         strings.TrimSpace(*rules),
				"new_admin_user":   strings.TrimSpace(*newAdmin),
				"new_table_prefix": strings.TrimSpace(*newPrefix),
			},
		}
	}

	resp, err := cli.Send(context.Background(), req)
	if err != nil {
		return err
	}
	if *asJSON || req.Action == "get_security_status" {
		if *asJSON {
			return emitPrettyJSON(resp)
		}
		return emitPrettyJSON(resp.Data)
	}

	var rep hardening.Report
	if err := remarshal(resp.Data, &rep); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf("Security Hardening [%s] webserver=%s score=%d/%d\n", rep.Domain+rep.SubPath, rep.WebServer, rep.Score, rep.Total)
	for _, r := range rep.Rules {
		mark := "[ ]"
		if r.Applied {
			mark = "[x]"
		}
		fmt.Printf("  %s %-26s (%s)\n", mark, r.ID, r.Severity)
	}
	return nil
}

func runQuarantineCLI(args []string) error {
	sub := "list"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = strings.ToLower(strings.TrimSpace(args[0]))
		rest = args[1:]
	}

	fs := flag.NewFlagSet("quarantine", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", "", "Filter by WordPress Instance ID (wp_...)")
	user := fs.String("user", "", "Filter by DirectAdmin username")
	qid := fs.String("qid", "", "Quarantine item ID (q_...)")
	noWhitelist := fs.Bool("no-whitelist", false, "Restore quarantined file without adding path to Core Whitelist")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	cli := ipc.NewClient(*sock)
	var req ipc.Request
	switch sub {
	case "list":
		req = ipc.Request{
			Action:     "list_quarantine",
			Username:   strings.TrimSpace(*user),
			InstanceID: strings.TrimSpace(*id),
		}
	case "diff":
		if strings.TrimSpace(*qid) == "" {
			return errors.New("--qid <q_id> is required for quarantine diff")
		}
		req = ipc.Request{
			Action: "get_quarantine_diff",
			Params: map[string]any{"quarantine_id": strings.TrimSpace(*qid)},
		}
	case "restore":
		if strings.TrimSpace(*qid) == "" {
			return errors.New("--qid <q_id> is required for quarantine restore")
		}
		req = ipc.Request{
			Action: "restore_quarantine",
			Params: map[string]any{
				"quarantine_id": strings.TrimSpace(*qid),
				"whitelist":     !*noWhitelist,
			},
		}
	case "delete":
		if strings.TrimSpace(*qid) == "" {
			return errors.New("--qid <q_id> is required for quarantine delete")
		}
		req = ipc.Request{
			Action: "delete_quarantine",
			Params: map[string]any{"quarantine_id": strings.TrimSpace(*qid)},
		}
	default:
		return fmt.Errorf("unknown quarantine subcommand %q (expected list | diff | restore | delete)", sub)
	}

	resp, err := cli.Send(context.Background(), req)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runBackupHookCLI(args []string) error {
	stage := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		stage = strings.ToLower(strings.TrimSpace(args[0]))
		rest = args[1:]
	}

	fs := flag.NewFlagSet("backup-hook", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	user := fs.String("user", "", "DirectAdmin username being backed up")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*user) == "" {
		return errors.New("--user <username> is required")
	}

	var action string
	switch stage {
	case "pre":
		action = "backup_pre_unlock"
	case "post":
		action = "backup_post_relock"
	default:
		return errors.New("specify stage 'pre' or 'post' (e.g. da-wptoolkit backup-hook pre --user <username>)")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 60 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:   action,
		Username: strings.TrimSpace(*user),
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runCleanupOwnerCLI(args []string) error {
	fs := flag.NewFlagSet("cleanup-owner", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	user := fs.String("user", "", "Destroyed DirectAdmin username to purge")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*user) == "" {
		return errors.New("--user <username> is required")
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:   "cleanup_owner",
		Username: strings.TrimSpace(*user),
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runToolsCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("tools", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	indexing := fs.String("indexing", "", "Set search engine indexing (on|off)")
	maint := fs.String("maintenance", "", "Set 503 Maintenance Mode (on|off)")
	debug := fs.String("debug", "", "Set WP_DEBUG + WP_DEBUG_LOG (on|off)")
	cron := fs.String("cron", "", "Take over wp-cron.php with DirectAdmin system cron (on|off)")
	interval := fs.Int("interval", 15, "System cron interval in minutes (5, 10, 15, 30, 60)")
	cache := fs.String("cache", "", "Toggle WP_CACHE (on|off)")
	clearCache := fs.Bool("clear-cache", false, "Flush Object Cache, LSCache & wp-content/cache")
	tailLog := fs.Bool("tail-log", false, "Read last 32KB of wp-content/debug.log")
	dbOp := fs.String("db", "", "Database maintenance operation (optimize|repair)")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	instID := strings.TrimSpace(*id)
	if instID == "" {
		return errors.New("instance ID (<wp_id> or --id <wp_id>) is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 90 * time.Second

	sendAct := func(action string, params map[string]any) (ipc.Response, error) {
		return cli.Send(context.Background(), ipc.Request{
			Action:     action,
			InstanceID: instID,
			Params:     params,
		})
	}

	var resp ipc.Response
	var err error
	switch {
	case *tailLog:
		resp, err = sendAct("read_debug_log", map[string]any{"max_bytes": 32768})
	case *clearCache:
		resp, err = sendAct("clear_cache", nil)
	case strings.TrimSpace(*dbOp) != "":
		resp, err = sendAct("db_maintenance", map[string]any{"operation": strings.TrimSpace(*dbOp)})
	case strings.TrimSpace(*indexing) != "":
		on, pErr := parseOnOff(*indexing)
		if pErr != nil {
			return pErr
		}
		resp, err = sendAct("set_search_indexing", map[string]any{"enabled": on})
	case strings.TrimSpace(*maint) != "":
		on, pErr := parseOnOff(*maint)
		if pErr != nil {
			return pErr
		}
		resp, err = sendAct("set_maintenance_mode", map[string]any{"enabled": on})
	case strings.TrimSpace(*debug) != "":
		on, pErr := parseOnOff(*debug)
		if pErr != nil {
			return pErr
		}
		resp, err = sendAct("set_debug_config", map[string]any{"wp_debug": on, "wp_debug_log": on, "wp_debug_display": false})
	case strings.TrimSpace(*cron) != "":
		on, pErr := parseOnOff(*cron)
		if pErr != nil {
			return pErr
		}
		resp, err = sendAct("set_wp_cron", map[string]any{"disable_wp_cron": on, "interval_min": *interval})
	case strings.TrimSpace(*cache) != "":
		on, pErr := parseOnOff(*cache)
		if pErr != nil {
			return pErr
		}
		resp, err = sendAct("set_caching", map[string]any{"enabled": on})
	default:
		resp, err = sendAct("get_tools_status", nil)
	}
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runSearchReplaceCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("search-replace", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	search := fs.String("search", "", "Source string/URL to find (required)")
	replace := fs.String("replace", "", "Replacement string/URL (required)")
	live := fs.Bool("live", false, "Apply replacements to database (defaults to safe Dry-Run preview)")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" || *search == "" {
		return errors.New("<wp_id> and --search are required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 120 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "search_replace",
		InstanceID: strings.TrimSpace(*id),
		Params: map[string]any{
			"search":  *search,
			"replace": *replace,
			"dry_run": !*live,
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runSnapshotCLI(args []string) error {
	subCmd := "list"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subCmd = strings.ToLower(strings.TrimSpace(args[0]))
		rest = args[1:]
	}
	posID, rest := extractPositionalID(rest)

	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "WordPress Instance ID (wp_...)")
	snapID := fs.String("snap-id", "", "Snapshot ID (snap_...) for restore/delete")
	note := fs.String("note", "", "Optional snapshot note")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	instID := strings.TrimSpace(*id)
	if instID == "" {
		return errors.New("instance ID (<wp_id> or --id <wp_id>) is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 300 * time.Second

	var req ipc.Request
	req.InstanceID = instID
	switch subCmd {
	case "list":
		req.Action = "list_snapshots"
	case "create":
		req.Action = "create_snapshot"
		req.Params = map[string]any{"sync": true, "note": strings.TrimSpace(*note)}
	case "restore":
		if strings.TrimSpace(*snapID) == "" {
			return errors.New("--snap-id <snap_...> is required for snapshot restore")
		}
		req.Action = "restore_snapshot"
		req.Params = map[string]any{"sync": true, "snapshot_id": strings.TrimSpace(*snapID)}
	case "delete":
		if strings.TrimSpace(*snapID) == "" {
			return errors.New("--snap-id <snap_...> is required for snapshot delete")
		}
		req.Action = "delete_snapshot"
		req.Params = map[string]any{"snapshot_id": strings.TrimSpace(*snapID)}
	default:
		return fmt.Errorf("unknown snapshot subcommand %q (expected list|create|restore|delete)", subCmd)
	}

	resp, err := cli.Send(context.Background(), req)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func runCloneCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("clone", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "Source WordPress Instance ID (wp_...)")
	domain := fs.String("domain", "", "Target domain or subdomain, e.g. staging.example.com (required)")
	subPath := fs.String("subpath", "", "Optional target subdirectory, e.g. /staging")
	title := fs.String("title", "", "Optional site title for cloned instance")
	envTag := fs.String("env", "", "Environment tag (staging|production|development)")
	overwrite := fs.Bool("overwrite", false, "Allow overwriting unmanaged files in target path")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" || strings.TrimSpace(*domain) == "" {
		return errors.New("<source_wp_id> and --domain <target_domain> are required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 300 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "clone_instance",
		InstanceID: strings.TrimSpace(*id),
		Params: map[string]any{
			"sync":              true,
			"target_domain":     strings.TrimSpace(*domain),
			"target_sub_path":   strings.TrimSpace(*subPath),
			"target_site_title": strings.TrimSpace(*title),
			"environment_tag":   strings.TrimSpace(*envTag),
			"overwrite":         *overwrite,
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	var res clonesync.CloneResult
	if err := remarshal(resp.Data, &res); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf("Cloned WordPress instance successfully!\n")
	fmt.Printf("  New ID       : %s (%s)\n", res.Instance.ID, res.Instance.EnvironmentTag)
	fmt.Printf("  Target URL   : %s\n", res.Instance.SiteURL)
	fmt.Printf("  DocRoot      : %s\n", res.Instance.DocRoot)
	fmt.Printf("  Database     : %s\n", res.Instance.DBName)
	fmt.Printf("  Cache Salt   : %s\n", res.CacheKeySalt)
	fmt.Printf("  NoIndex      : %v\n", res.SearchEngineNoIdx)
	return nil
}

func runSyncCLI(args []string) error {
	posID, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	id := fs.String("id", posID, "Source WordPress Instance ID (wp_...)")
	toID := fs.String("to", "", "Target WordPress Instance ID (wp_...) (required)")
	mode := fs.String("mode", "both", "Sync mode: both | files | db")
	noSnap := fs.Bool("no-snapshot", false, "Skip automatic pre-sync Zstd snapshot of target")
	noWoo := fs.Bool("no-preserve-woo", false, "Overwrite WooCommerce order/customer tables on target")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*id) == "" || strings.TrimSpace(*toID) == "" {
		return errors.New("<source_wp_id> and --to <target_wp_id> are required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 300 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:     "sync_instance",
		InstanceID: strings.TrimSpace(*id),
		Params: map[string]any{
			"sync":                 true,
			"target_instance_id":   strings.TrimSpace(*toID),
			"mode":                 strings.TrimSpace(*mode),
			"auto_snapshot":        !*noSnap,
			"preserve_woocommerce": !*noWoo,
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	var res clonesync.SyncResult
	if err := remarshal(resp.Data, &res); err != nil {
		return emitPrettyJSON(resp.Data)
	}
	fmt.Printf("Synchronized %s -> %s (%s)\n", res.SourceInstance.Domain+res.SourceInstance.SubPath, res.TargetInstance.Domain+res.TargetInstance.SubPath, res.Mode)
	if res.PreSyncSnapshotID != "" {
		fmt.Printf("  Pre-Sync Snapshot : %s\n", res.PreSyncSnapshotID)
	}
	fmt.Printf("  Synced Files      : %d\n", res.SyncedFiles)
	fmt.Printf("  SQL Replacements  : %d\n", res.SQLReplacements)
	if len(res.PreservedWooTables) > 0 {
		fmt.Printf("  Preserved Woo     : %s\n", strings.Join(res.PreservedWooTables, ", "))
	}
	return nil
}

func parseOnOff(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true", "1", "yes", "enable", "enabled":
		return true, nil
	case "off", "false", "0", "no", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("expected on|off, got %q", raw)
	}
}

func extractPositionalID(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return strings.TrimSpace(args[0]), args[1:]
	}
	return "", args
}

func emitPrettyJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func remarshal(src any, dst any) error {
	raw, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dst)
}

func getenvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func printUsage() {
	fmt.Printf("%s\n\n", version.Info())
	fmt.Println("Usage:")
	fmt.Println("  da-wptoolkit serve          Start background daemon & Dual Unix Socket IPC server")
	fmt.Println("  da-wptoolkit ping           Check daemon health, web server & inotify watches")
	fmt.Println("  da-wptoolkit scan           Auto-discover WordPress instances (--user <u> | --all)")
	fmt.Println("  da-wptoolkit list           List managed WordPress instances ([--user <u>] [--vuln])")
	fmt.Println("  da-wptoolkit install        1-Click install WordPress (--user <u> --domain <d>)")
	fmt.Println("  da-wptoolkit uninstall      Uninstall WordPress instance (<wp_id> [--drop-db])")
	fmt.Println("  da-wptoolkit detach         Stop tracking an instance without deleting files (<wp_id>)")
	fmt.Println("  da-wptoolkit sso            Generate 45s self-destructing wp-admin SSO URL (<wp_id>)")
	fmt.Println("  da-wptoolkit sync-vulndb    Sync Wordfence Community CVE Feed into local index")
	fmt.Println("  da-wptoolkit plugins        List or manage plugins on an instance (<wp_id>)")
	fmt.Println("  da-wptoolkit themes         List or manage themes on an instance (<wp_id>)")
	fmt.Println("  da-wptoolkit smart-update   Run Smart Safe Update with HTTP 500 Auto-Rollback (<wp_id>)")
	fmt.Println("  da-wptoolkit bulk-update    Run multi-site Bulk Smart Safe Update (--ids <id1,id2>)")
	fmt.Println("  da-wptoolkit verify-core    Verify SHA-256 Core integrity & Auto-Heal (<wp_id> | --all)")
	fmt.Println("  da-wptoolkit lock-core      Enable Fortress Core Lock (root:<user>) on <wp_id>")
	fmt.Println("  da-wptoolkit unlock-core    Disable Fortress Core Lock & restore user ownership on <wp_id>")
	fmt.Println("  da-wptoolkit shield-mode    Set Core Shield mode (--id <wp_id> --mode monitor|auto_heal|fortress_lock)")
	fmt.Println("  da-wptoolkit harden         Check, apply, or revert 12 security hardening rules (<wp_id>)")
	fmt.Println("  da-wptoolkit quarantine     Manage Quarantine Vault (list | diff | restore | delete)")
	fmt.Println("  da-wptoolkit tools          Inspect or toggle Plesk Quick Tools, Cache, Cron & Debug Log (<wp_id>)")
	fmt.Println("  da-wptoolkit search-replace Serialized-safe DB Search & Replace with Dry-Run (<wp_id>)")
	fmt.Println("  da-wptoolkit snapshot       Zstd (.tar.zst) Snapshot manager (list | create | restore | delete)")
	fmt.Println("  da-wptoolkit clone          1-Click Clone / Staging with isolated WP_CACHE_KEY_SALT (<wp_id>)")
	fmt.Println("  da-wptoolkit sync           Bidirectional Staging Sync preserving WooCommerce orders (<wp_id>)")
	fmt.Println("  da-wptoolkit backup-hook    DirectAdmin backup pre/post Fortress Lock hook (pre|post --user <u>)")
	fmt.Println("  da-wptoolkit cleanup-owner  Purge destroyed DirectAdmin account data (--user <u>)")
	fmt.Println("  da-wptoolkit hook           Dispatch DirectAdmin lifecycle hook (<event> --user <u> [--domain <d>])")
	fmt.Println("  da-wptoolkit check-update   Check GitHub Releases for newer Ed25519-signed versions")
	fmt.Println("  da-wptoolkit update         Verify Ed25519 + SHA-256 & atomically update with Auto-Rollback")
	fmt.Println("  da-wptoolkit rollback       Instant rollback to previous snapshot backup")
	fmt.Println("  da-wptoolkit keygen         Generate Ed25519 release signing keypair (hex)")
	fmt.Println("  da-wptoolkit sign-release   Generate checksums.txt & Ed25519 checksums.txt.sig (--dir <path>)")
	fmt.Println("  da-wptoolkit verify-release Verify Ed25519 checksums.txt.sig & SHA-256 digests (--dir <path>)")
	fmt.Println("  da-wptoolkit version        Print build version information")
}

func runDAHookCLI(args []string) error {
	evName, rest := extractPositionalID(args)
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	event := fs.String("event", evName, "Hook event name (domain_create|domain_destroy|subdomain_create|subdomain_destroy|user_modify|user_backup_pre|user_backup_post|user_restore|user_destroy)")
	user := fs.String("user", "", "DirectAdmin username")
	domain := fs.String("domain", "", "Target domain name")
	subdomain := fs.String("subdomain", "", "Target subdomain label")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if strings.TrimSpace(*event) == "" {
		return errors.New("hook <event> is required")
	}

	cli := ipc.NewClient(*sock)
	cli.Timeout = 60 * time.Second
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action:   "handle_da_hook",
		Username: strings.TrimSpace(*user),
		Params: map[string]any{
			"event":     strings.TrimSpace(*event),
			"username":  strings.TrimSpace(*user),
			"domain":    strings.TrimSpace(*domain),
			"subdomain": strings.TrimSpace(*subdomain),
		},
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(resp)
	}
	return emitPrettyJSON(resp.Data)
}

func newStandaloneUpdater(stateDir, sockPath string) (*updater.Manager, config.UpdaterConfig) {
	st, _ := store.Open(stateDir)
	pol := config.NewPolicyStore(
		getenvOr("DA_WPTK_DATA_DIR", DefaultPluginDataDir),
		getenvOr("DA_WPTK_UPDATER_CONF", DefaultUpdaterCfgPath),
	)
	cfg, _ := pol.LoadUpdaterConfig(version.DefaultGitHubRepo)
	mgr := updater.NewManager(stateDir, st)
	mgr.AdminSockPath = sockPath
	mgr.BinPath = getenvOr("DA_WPTK_BIN_PATH", updater.DefaultBinPath)
	mgr.PluginDir = getenvOr("DA_WPTK_PLUGIN_DIR", updater.DefaultPluginDir)
	mgr.HooksBaseDir = getenvOr("DA_WPTK_CUSTOM_HOOKS_DIR", updater.DefaultHooksBaseDir)
	mgr.ShareDir = getenvOr("DA_WPTK_SHARE_DIR", updater.DefaultShareDir)
	if apiBase := strings.TrimSpace(os.Getenv("DA_WPTK_GITHUB_API_BASE")); apiBase != "" {
		mgr.APIBaseURL = apiBase
	}
	return mgr, cfg
}

func runCheckUpdateCLI(args []string) error {
	fs := flag.NewFlagSet("check-update", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	stateDir := fs.String("state-dir", getenvOr("DA_WPTK_STATE_DIR", store.DefaultStateDir), "Persistent state directory")
	tag := fs.String("tag", "", "Optional specific release tag to inspect")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cli := ipc.NewClient(*sock)
	resp, err := cli.Send(context.Background(), ipc.Request{
		Action: "check_github_update",
		Params: map[string]any{"tag": strings.TrimSpace(*tag)},
	})
	if err == nil && resp.OK {
		if *asJSON {
			return emitPrettyJSON(resp)
		}
		return emitPrettyJSON(resp.Data)
	}

	mgr, cfg := newStandaloneUpdater(*stateDir, *sock)
	rel, cErr := mgr.CheckLatest(context.Background(), cfg, strings.TrimSpace(*tag))
	if cErr != nil {
		return cErr
	}
	return emitPrettyJSON(rel)
}

func runSelfUpdateCLI(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	stateDir := fs.String("state-dir", getenvOr("DA_WPTK_STATE_DIR", store.DefaultStateDir), "Persistent state directory")
	tag := fs.String("tag", "", "Specific GitHub release tag (default: latest for channel)")
	force := fs.Bool("force", false, "Reinstall even if already on latest version")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr, cfg := newStandaloneUpdater(*stateDir, *sock)
	out, err := mgr.PerformUpdate(context.Background(), cfg, strings.TrimSpace(*tag), *force, false)
	if *asJSON {
		_ = emitPrettyJSON(out)
		return err
	}
	if err != nil {
		return err
	}
	fmt.Printf("Updated DA-WordPressToolkits %s -> %s in %dms (backup: %s)\n", out.PreviousVersion, out.TargetVersion, out.ElapsedMs, out.BackupPath)
	return nil
}

func runRollbackCLI(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	stateDir := fs.String("state-dir", getenvOr("DA_WPTK_STATE_DIR", store.DefaultStateDir), "Persistent state directory")
	backup := fs.String("backup", "", "Specific backup archive filename (default: latest)")
	listOnly := fs.Bool("list", false, "List available rollback snapshot backups")
	noRestart := fs.Bool("no-restart", false, "Restore files without calling systemctl restart")
	asJSON := fs.Bool("json", false, "Emit raw JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr, _ := newStandaloneUpdater(*stateDir, *sock)
	if *listOnly {
		items, err := mgr.ListBackups()
		if err != nil {
			return err
		}
		if *asJSON {
			return emitPrettyJSON(items)
		}
		if len(items) == 0 {
			fmt.Println("No rollback backups found.")
			return nil
		}
		for _, it := range items {
			fmt.Printf("  - %-40s version=%-10s size=%dB created=%s\n", it.FileName, it.Version, it.SizeBytes, it.CreatedAt.Format(time.RFC3339))
		}
		return nil
	}
	bkp, err := mgr.RestoreBackup(context.Background(), strings.TrimSpace(*backup), !*noRestart)
	if err != nil {
		return err
	}
	if *asJSON {
		return emitPrettyJSON(bkp)
	}
	fmt.Printf("Rolled back to %s (%s)\n", bkp.Version, bkp.FileName)
	return nil
}

func runApplyStagedCLI(args []string) error {
	fs := flag.NewFlagSet("apply-staged", flag.ContinueOnError)
	sock := fs.String("sock", getenvOr("DA_WPTK_ADMIN_SOCK", ipc.DefaultAdminSocketPath), "Admin Unix socket path")
	stateDir := fs.String("state-dir", getenvOr("DA_WPTK_STATE_DIR", store.DefaultStateDir), "Persistent state directory")
	staged := fs.String("staged", "", "Verified extracted payload directory (required)")
	backup := fs.String("backup", "", "Pre-update rollback archive path (required)")
	targetVer := fs.String("target-version", "", "Target release version tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*staged) == "" || strings.TrimSpace(*backup) == "" {
		return errors.New("--staged and --backup are required")
	}

	mgr, _ := newStandaloneUpdater(*stateDir, *sock)
	out, err := mgr.ApplyStagedWithAutoRollback(context.Background(), strings.TrimSpace(*staged), strings.TrimSpace(*backup), strings.TrimSpace(*targetVer))
	if err != nil {
		return err
	}
	fmt.Printf("Applied staged release %s (%dms)\n", out.TargetVersion, out.ElapsedMs)
	return nil
}

func runKeygenCLI() error {
	privHex, pubHex, err := updater.GenerateKeyPairHex()
	if err != nil {
		return err
	}
	fmt.Println("Generated Ed25519 Release Signing Keypair:")
	fmt.Printf("  PUBLIC_KEY_HEX  (embed in DefaultReleasePublicKeyHex)          : %s\n", pubHex)
	fmt.Printf("  PRIVATE_KEY_HEX (GitHub Secret RELEASE_ED25519_PRIVATE_KEY)    : %s\n", privHex)
	return nil
}

func runSignReleaseCLI(args []string) error {
	fs := flag.NewFlagSet("sign-release", flag.ContinueOnError)
	dir := fs.String("dir", "dist/release", "Directory containing release .tar.gz artifacts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rawKey := strings.TrimSpace(os.Getenv("DA_WPTK_RELEASE_PRIVATE_KEY"))
	if rawKey == "" {
		return errors.New("DA_WPTK_RELEASE_PRIVATE_KEY environment variable is required")
	}
	privKey, err := updater.ParsePrivateKey(rawKey)
	if err != nil {
		return err
	}
	csPath, sigPath, digests, err := updater.SignChecksumsDir(strings.TrimSpace(*dir), privKey)
	if err != nil {
		return err
	}
	fmt.Printf("Signed %d artifacts:\n  checksums : %s\n  signature : %s\n", len(digests), csPath, sigPath)
	return nil
}

func runVerifyReleaseCLI(args []string) error {
	fs := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	dir := fs.String("dir", "dist/release", "Directory containing checksums.txt, checksums.txt.sig, and artifacts")
	pubKey := fs.String("pub-key", version.DefaultReleasePublicKeyHex, "Hex-encoded 32-byte Ed25519 public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cleanDir := strings.TrimSpace(*dir)
	csBytes, err := os.ReadFile(filepath.Join(cleanDir, "checksums.txt"))
	if err != nil {
		return err
	}
	sigBytes, err := os.ReadFile(filepath.Join(cleanDir, "checksums.txt.sig"))
	if err != nil {
		return err
	}
	digests, err := updater.VerifyChecksumsSignature(csBytes, sigBytes, strings.TrimSpace(*pubKey))
	if err != nil {
		return err
	}
	fmt.Printf("Verified Ed25519 signature over %d release artifacts in %s\n", len(digests), cleanDir)
	return nil
}
