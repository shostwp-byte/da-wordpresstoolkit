package clonesync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/database"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/discovery"
	"github.com/shostwp-byte/da-wptoolkits/internal/hardening"
	"github.com/shostwp-byte/da-wptoolkits/internal/snapshot"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

type mockDBProvisioner struct {
	mu      sync.Mutex
	counter int
	dbs     map[string]string // dbName -> SQL dump state
}

func newMockDBProvisioner() *mockDBProvisioner {
	return &mockDBProvisioner{
		dbs: make(map[string]string),
	}
}

func (m *mockDBProvisioner) CreateDatabase(_ context.Context, acct dausers.Account, _ string) (database.Credentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	name := fmt.Sprintf("%s_clone%d", acct.Username, m.counter)
	m.dbs[name] = ""
	return database.Credentials{
		DBName:   name,
		DBUser:   name,
		Password: fmt.Sprintf("StrongPassClone%dX9", m.counter),
		Host:     "localhost",
	}, nil
}

func (m *mockDBProvisioner) DropDatabase(_ context.Context, _ dausers.Account, dbName, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.dbs, dbName)
	return nil
}

func TestReplacePHPSerializedSafeAndElementorSQL(t *testing.T) {
	pairs := [][2]string{
		{"https://renolabs-audio.com", "https://staging.renolabs-audio.com"},
		{"/home/reno26/domains/renolabs-audio.com/public_html", "/home/reno26/domains/renolabs-audio.com/public_html/staging"},
	}

	raw := `a:3:{s:3:"url";s:37:"https://renolabs-audio.com/banner.jpg";s:4:"path";s:51:"/home/reno26/domains/renolabs-audio.com/public_html";s:9:"elementor";s:58:"[{"bg":"https:\/\/renolabs-audio.com\/assets\/hero.webp"}]";}`
	got, hits := ReplacePHPSerializedSafe(raw, pairs)
	if hits < 3 {
		t.Fatalf("expected >= 3 replacements, got %d", hits)
	}

	wantURL := `s:45:"https://staging.renolabs-audio.com/banner.jpg";`
	wantPath := `s:59:"/home/reno26/domains/renolabs-audio.com/public_html/staging";`
	wantElem := `s:66:"[{"bg":"https:\/\/staging.renolabs-audio.com\/assets\/hero.webp"}]";`
	for _, want := range []string{wantURL, wantPath, wantElem} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing exact PHP serialized segment %s in:\n%s", want, got)
		}
	}

	sqlIn := "CREATE TABLE `wp_options` (`option_name` varchar(191), `option_value` longtext);\n" +
		"INSERT INTO `wp_options` VALUES ('wp_user_roles', 'a:1:{s:5:\"admin\";b:1;}'), ('theme_mods', 'a:1:{s:4:\"logo\";s:35:\"https://renolabs-audio.com/logo.png\";}');\n"
	sqlOut, sqlHits := ReplaceSQLDumpSafe(sqlIn, pairs, "wp_", "wp_stg_")
	if sqlHits == 0 {
		t.Fatal("expected SQL replacements > 0")
	}
	if !strings.Contains(sqlOut, "`wp_stg_options`") || !strings.Contains(sqlOut, "'wp_stg_user_roles'") {
		t.Fatalf("expected table prefix rename to wp_stg_, got:\n%s", sqlOut)
	}
	if !strings.Contains(sqlOut, `s:43:"https://staging.renolabs-audio.com/logo.png";`) {
		t.Fatalf("expected exact serialized length 43 inside SQL literal, got:\n%s", sqlOut)
	}
}

// TestTC09_CloneStagingIsolatesRedisCachePreservesElementorSerializedAndSetsNoIndex validates Acceptance Test Case TC-09
// and Phase 4 DoD: cloning a Production WordPress + Elementor + WooCommerce + Redis Object Cache site to `staging.domain.com`
// preserves 100% of serialized Elementor layout structures, isolates `WP_CACHE_KEY_SALT` (zero Redis cache cross-pollution),
// and automatically enforces `noindex` on Staging.
func TestTC09_CloneStagingIsolatesRedisCachePreservesElementorSerializedAndSetsNoIndex(t *testing.T) {
	tmp := t.TempDir()
	ctx := context.Background()

	homeDir := filepath.Join(tmp, "home", "reno26")
	prodDocRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	daDataRoot := filepath.Join(tmp, "da_data")
	userDir := filepath.Join(daDataRoot, "users", "reno26")
	domainsConfDir := filepath.Join(userDir, "domains")
	stateDir := filepath.Join(tmp, "state")
	policyDir := filepath.Join(tmp, "policies")

	for _, d := range []string{
		filepath.Join(prodDocRoot, "wp-content", "themes", "audib"),
		filepath.Join(prodDocRoot, "wp-content", "uploads"),
		filepath.Join(prodDocRoot, "wp-includes"),
		domainsConfDir,
		stateDir,
		policyDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=renolabs-audio.com\npackage=business\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domainsConfDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	prodWPConfig := `<?php
define( 'DB_NAME', 'reno26_prod' );
define( 'DB_USER', 'reno26_prod' );
define( 'DB_PASSWORD', 'ProdSecretPass123' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
define( 'WP_CACHE', true );
define( 'WP_CACHE_KEY_SALT', 'prod_salt_renolabs' );
define( 'AUTH_KEY', 'old-auth-key' );
require_once ABSPATH . 'wp-settings.php';
`
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-config.php"), []byte(prodWPConfig), 0o600)
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.7.1';\n"), 0o644)
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-content", "themes", "audib", "style.css"), []byte("/* Audib v1.0 */\n"), 0o644)
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-content", "uploads", "hero.webp"), []byte("WEBP-DATA"), 0o644)

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	policies := config.NewPolicyStore(policyDir, filepath.Join(policyDir, "updater.conf"))
	acct := dausers.Account{
		Username: "reno26",
		UID:      1026,
		GID:      1026,
		HomeDir:  homeDir,
		Package:  "business",
	}

	prodInst, err := st.UpsertInstance(store.InstanceRecord{
		ID:             "wp_prod0001",
		Owner:          acct.Username,
		OwnerUID:       acct.UID,
		Domain:         "renolabs-audio.com",
		DomainType:     dadomains.DomainTypeMain,
		DocRoot:        prodDocRoot,
		SiteURL:        "https://renolabs-audio.com",
		SiteTitle:      "RENOLABS OFFICIAL",
		AdminUser:      "radmin",
		AdminEmail:     "admin@renolabs-audio.com",
		WPVersion:      "6.7.1",
		DBName:         "reno26_prod",
		DBUser:         "reno26_prod",
		TablePrefix:    "wp_",
		ActiveTheme:    "audib",
		SSLActive:      true,
		SearchIndexing: true,
		CacheEnabled:   true,
		EnvironmentTag: "production",
	})
	if err != nil {
		t.Fatal(err)
	}

	dbProv := newMockDBProvisioner()
	dbProv.dbs["reno26_prod"] = "CREATE TABLE `wp_options` (`option_name` varchar(191), `option_value` longtext);\n" +
		"INSERT INTO `wp_options` VALUES ('siteurl','https://renolabs-audio.com'),('home','https://renolabs-audio.com'),('blogname','RENOLABS OFFICIAL'),('blog_public','1');\n" +
		"INSERT INTO `wp_postmeta` VALUES ('_elementor_css','a:1:{s:3:\"url\";s:37:\"https://renolabs-audio.com/banner.jpg\";}'),('_elementor_data','[{\"bg\":\"https:\\\\/\\\\/renolabs-audio.com\\\\/uploads\\\\/hero.webp\"}]');\n"

	// Simulated shared Redis Object Cache server keyed by `<WP_CACHE_KEY_SALT>:<key>`
	var redisMu sync.Mutex
	sharedRedis := map[string]string{
		"prod_salt_renolabs:blogname": "RENOLABS OFFICIAL",
		"prod_salt_renolabs:siteurl":  "https://renolabs-audio.com",
	}
	optionsByDB := map[string]map[string]string{
		"reno26_prod": {
			"blogname":    "RENOLABS OFFICIAL",
			"siteurl":     "https://renolabs-audio.com",
			"home":        "https://renolabs-audio.com",
			"blog_public": "1",
		},
	}

	readSiteConfig := func(docRoot string) (dbName, cacheSalt string) {
		raw, _ := os.ReadFile(filepath.Join(docRoot, "wp-config.php"))
		parsed := discovery.ParseWPConfig(raw)
		salt, _ := hardening.GetDefinedString(string(raw), "WP_CACHE_KEY_SALT")
		return parsed.DBName, salt
	}

	runner := wpcli.NewRunner("/usr/local/bin/wp", filepath.Join(tmp, "core-cache"))
	runner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		dbName, cacheSalt := readSiteConfig(spec.Dir)
		for i := 0; i < len(spec.Args); i++ {
			switch spec.Args[i] {
			case "db":
				if i+2 < len(spec.Args) && spec.Args[i+1] == "export" {
					sqlPath := spec.Args[i+2]
					dbProv.mu.Lock()
					dump := dbProv.dbs[dbName]
					dbProv.mu.Unlock()
					if err := os.WriteFile(sqlPath, []byte(dump), 0o600); err != nil {
						return "", err.Error(), err
					}
					return "Success", "", nil
				}
				if i+2 < len(spec.Args) && spec.Args[i+1] == "import" {
					sqlPath := spec.Args[i+2]
					raw, err := os.ReadFile(sqlPath)
					if err != nil {
						return "", err.Error(), err
					}
					dbProv.mu.Lock()
					dbProv.dbs[dbName] = dbProv.dbs[dbName] + "\n" + string(raw)
					dbProv.mu.Unlock()
					redisMu.Lock()
					if optionsByDB[dbName] == nil {
						optionsByDB[dbName] = make(map[string]string)
					}
					redisMu.Unlock()
					return "Success", "", nil
				}
			case "option":
				if i+3 < len(spec.Args) && spec.Args[i+1] == "update" {
					optKey := spec.Args[i+2]
					optVal := spec.Args[i+3]
					redisMu.Lock()
					if optionsByDB[dbName] == nil {
						optionsByDB[dbName] = make(map[string]string)
					}
					optionsByDB[dbName][optKey] = optVal
					if cacheSalt != "" {
						sharedRedis[cacheSalt+":"+optKey] = optVal
					}
					redisMu.Unlock()
					return "Success", "", nil
				}
			case "cache":
				if i+1 < len(spec.Args) && spec.Args[i+1] == "flush" {
					// Realistic Redis Object Cache flush scoped by WP_CACHE_KEY_SALT prefix
					redisMu.Lock()
					if cacheSalt != "" {
						prefix := cacheSalt + ":"
						for k := range sharedRedis {
							if strings.HasPrefix(k, prefix) {
								delete(sharedRedis, k)
							}
						}
					}
					redisMu.Unlock()
					return "Success", "", nil
				}
			}
		}
		return "Success", "", nil
	}

	domResolver := dadomains.NewResolver(daDataRoot, daphp.NewResolver("", ""))
	snapMgr, err := snapshot.NewManager(stateDir, domResolver, runner, st, policies)
	if err != nil {
		t.Fatal(err)
	}
	snapMgr.ZstdBin = filepath.Join(tmp, "no-zstd")

	eng := NewEngine(domResolver, dbProv, runner, snapMgr, st, policies)

	// 1. Clone `renolabs-audio.com` -> `staging.renolabs-audio.com`
	cloneRes, err := eng.Clone(ctx, acct, CloneRequest{
		SourceInstanceID: prodInst.ID,
		TargetDomain:     "staging.renolabs-audio.com",
	}, nil)
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}
	if !cloneRes.CreatedSubdomain {
		t.Fatal("expected staging.renolabs-audio.com subdomain to be auto-provisioned")
	}
	if !cloneRes.SearchEngineNoIdx || cloneRes.Instance.SearchIndexing {
		t.Fatalf("TC-09 FAILED: expected Staging instance to have noindex enabled, got SearchIndexing=%v", cloneRes.Instance.SearchIndexing)
	}
	if cloneRes.CacheKeySalt == "" || cloneRes.CacheKeySalt == "prod_salt_renolabs" {
		t.Fatalf("TC-09 FAILED: expected isolated WP_CACHE_KEY_SALT on Staging, got %q", cloneRes.CacheKeySalt)
	}

	// 2. Update Site Title on Staging (as required by TC-09) -> writes into sharedRedis under Staging's WP_CACHE_KEY_SALT
	_, err = runner.Run(ctx, wpcli.CallOptions{
		Account: acct,
		DocRoot: cloneRes.Instance.DocRoot,
		Args:    []string{"option", "update", "blogname", "RENOLABS STAGING SANDBOX"},
	})
	if err != nil {
		t.Fatalf("update staging blogname failed: %v", err)
	}

	// 3. Verify Production Redis keys and SiteURL/Title remain 100% untouched!
	redisMu.Lock()
	prodCachedTitle := sharedRedis["prod_salt_renolabs:blogname"]
	prodCachedURL := sharedRedis["prod_salt_renolabs:siteurl"]
	stgCachedTitle := sharedRedis[cloneRes.CacheKeySalt+":blogname"]
	stgPublicOpt := optionsByDB[cloneRes.Instance.DBName]["blog_public"]
	redisMu.Unlock()

	if prodCachedTitle != "RENOLABS OFFICIAL" || prodCachedURL != "https://renolabs-audio.com" {
		t.Fatalf("TC-09 FAILED: Production Redis cache polluted! title=%q url=%q", prodCachedTitle, prodCachedURL)
	}
	if stgCachedTitle != "RENOLABS STAGING SANDBOX" {
		t.Fatalf("expected Staging Redis cache to hold updated title, got %q", stgCachedTitle)
	}
	if stgPublicOpt != "0" {
		t.Fatalf("TC-09 FAILED: expected Staging blog_public=0, got %q", stgPublicOpt)
	}

	// 4. Verify Elementor serialized & JSON structures inside Staging DB have exact byte lengths
	dbProv.mu.Lock()
	stagingSQL := dbProv.dbs[cloneRes.Instance.DBName]
	dbProv.mu.Unlock()
	if !strings.Contains(stagingSQL, `s:45:"https://staging.renolabs-audio.com/banner.jpg";`) {
		t.Fatalf("expected Elementor serialized URL length s:45 on Staging DB, got:\n%s", stagingSQL)
	}
	if !strings.Contains(stagingSQL, `https:\\/\\/staging.renolabs-audio.com\\/uploads\\/hero.webp`) {
		t.Fatalf("expected Elementor JSON escaped URL on Staging DB, got:\n%s", stagingSQL)
	}
}

func TestBidirectionalSyncCreatesPreSyncSnapshotPreservesWooCommerceOrdersAndProdIndexing(t *testing.T) {
	tmp := t.TempDir()
	ctx := context.Background()

	homeDir := filepath.Join(tmp, "home", "reno26")
	prodDocRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	daDataRoot := filepath.Join(tmp, "da_data")
	userDir := filepath.Join(daDataRoot, "users", "reno26")
	domainsConfDir := filepath.Join(userDir, "domains")
	stateDir := filepath.Join(tmp, "state")
	policyDir := filepath.Join(tmp, "policies")

	for _, d := range []string{
		filepath.Join(prodDocRoot, "wp-content", "themes", "audib"),
		filepath.Join(prodDocRoot, "wp-includes"),
		domainsConfDir,
		stateDir,
		policyDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=renolabs-audio.com\npackage=business\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domainsConfDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=1\n"), 0o600)

	prodWPConfig := `<?php
define( 'DB_NAME', 'reno26_prod' );
define( 'DB_USER', 'reno26_prod' );
define( 'DB_PASSWORD', 'ProdSecretPass123' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
define( 'WP_CACHE_KEY_SALT', 'prod_salt_keep' );
require_once ABSPATH . 'wp-settings.php';
`
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-config.php"), []byte(prodWPConfig), 0o600)
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-includes", "version.php"), []byte("<?php $wp_version = '6.7.1';\n"), 0o644)
	_ = os.WriteFile(filepath.Join(prodDocRoot, "wp-content", "themes", "audib", "style.css"), []byte("/* Theme v1.0 */\n"), 0o644)

	st, err := store.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	policies := config.NewPolicyStore(policyDir, filepath.Join(policyDir, "updater.conf"))
	acct := dausers.Account{
		Username: "reno26",
		UID:      1026,
		GID:      1026,
		HomeDir:  homeDir,
		Package:  "business",
	}

	prodInst, err := st.UpsertInstance(store.InstanceRecord{
		ID:             "wp_prodsync01",
		Owner:          acct.Username,
		OwnerUID:       acct.UID,
		Domain:         "renolabs-audio.com",
		DomainType:     dadomains.DomainTypeMain,
		DocRoot:        prodDocRoot,
		SiteURL:        "https://renolabs-audio.com",
		SiteTitle:      "RENOLABS",
		WPVersion:      "6.7.1",
		DBName:         "reno26_prod",
		DBUser:         "reno26_prod",
		TablePrefix:    "wp_",
		ActiveTheme:    "audib",
		SSLActive:      true,
		SearchIndexing: true,
		EnvironmentTag: "production",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Simulate per-DB table SQL map (`dbTables[dbName][tableName] = sql`)
	var dbMu sync.Mutex
	dbTables := map[string]map[string]string{
		"reno26_prod": {
			"wp_options":                 "INSERT INTO `wp_options` VALUES ('siteurl','https://renolabs-audio.com'),('blog_public','1');\n",
			"wp_posts":                   "INSERT INTO `wp_posts` VALUES (1,'a:1:{s:4:\"hero\";s:34:\"https://renolabs-audio.com/v1.webp\";}');\n",
			"wp_wc_orders":               "INSERT INTO `wp_wc_orders` VALUES (9001,'completed',299.00,'customer@vip.vn');\n",
			"wp_woocommerce_order_items": "INSERT INTO `wp_woocommerce_order_items` VALUES (501,'Tube Amplifier Pro',9001);\n",
		},
	}
	blogPublicByDB := map[string]string{"reno26_prod": "1"}

	dbProv := newMockDBProvisioner()

	readDBName := func(docRoot string) string {
		raw, _ := os.ReadFile(filepath.Join(docRoot, "wp-config.php"))
		return discovery.ParseWPConfig(raw).DBName
	}

	runner := wpcli.NewRunner("/usr/local/bin/wp", filepath.Join(tmp, "core-cache"))
	runner.ExecCommand = func(_ context.Context, spec wpcli.ExecSpec) (string, string, error) {
		dbName := readDBName(spec.Dir)
		for i := 0; i < len(spec.Args); i++ {
			if spec.Args[i] == "db" && i+1 < len(spec.Args) {
				switch spec.Args[i+1] {
				case "tables":
					dbMu.Lock()
					var names []string
					for tbl := range dbTables[dbName] {
						names = append(names, tbl)
					}
					dbMu.Unlock()
					return strings.Join(names, "\n"), "", nil

				case "export":
					if i+2 >= len(spec.Args) {
						break
					}
					sqlPath := spec.Args[i+2]
					var filter map[string]struct{}
					for _, a := range spec.Args[i+3:] {
						if strings.HasPrefix(a, "--tables=") {
							filter = make(map[string]struct{})
							for _, tName := range strings.Split(strings.TrimPrefix(a, "--tables="), ",") {
								filter[strings.TrimSpace(tName)] = struct{}{}
							}
						}
					}
					dbMu.Lock()
					var b strings.Builder
					for tbl, rowSQL := range dbTables[dbName] {
						if filter != nil {
							if _, ok := filter[tbl]; !ok {
								continue
							}
						}
						fmt.Fprintf(&b, "-- TABLE:%s\n%s", tbl, rowSQL)
					}
					dbMu.Unlock()
					if err := os.WriteFile(sqlPath, []byte(b.String()), 0o600); err != nil {
						return "", err.Error(), err
					}
					return "Success", "", nil

				case "import":
					if i+2 >= len(spec.Args) {
						break
					}
					raw, err := os.ReadFile(spec.Args[i+2])
					if err != nil {
						return "", err.Error(), err
					}
					blocks := strings.Split(string(raw), "-- TABLE:")
					dbMu.Lock()
					if dbTables[dbName] == nil {
						dbTables[dbName] = make(map[string]string)
					}
					// If full DB import (contains wp_options), reset non-imported tables just like DROP/CREATE TABLE
					if strings.Contains(string(raw), "-- TABLE:wp_options") {
						dbTables[dbName] = make(map[string]string)
					}
					for _, blk := range blocks[1:] {
						nl := strings.IndexByte(blk, '\n')
						if nl > 0 {
							tbl := strings.TrimSpace(blk[:nl])
							dbTables[dbName][tbl] = blk[nl+1:]
						}
					}
					dbMu.Unlock()
					return "Success", "", nil
				}
			}
			if spec.Args[i] == "option" && i+3 < len(spec.Args) && spec.Args[i+1] == "update" && spec.Args[i+2] == "blog_public" {
				dbMu.Lock()
				blogPublicByDB[dbName] = spec.Args[i+3]
				dbMu.Unlock()
				return "Success", "", nil
			}
		}
		return "Success", "", nil
	}

	domResolver := dadomains.NewResolver(daDataRoot, daphp.NewResolver("", ""))
	snapMgr, err := snapshot.NewManager(stateDir, domResolver, runner, st, policies)
	if err != nil {
		t.Fatal(err)
	}
	snapMgr.ZstdBin = filepath.Join(tmp, "no-zstd")

	eng := NewEngine(domResolver, dbProv, runner, snapMgr, st, policies)

	// 1. Clone Production -> Staging
	cloneRes, err := eng.Clone(ctx, acct, CloneRequest{
		SourceInstanceID: prodInst.ID,
		TargetDomain:     "staging.renolabs-audio.com",
	}, nil)
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}
	stagingInst := cloneRes.Instance

	// 2. Simulate new live WooCommerce order #9002 arriving on Production WHILE designer edits Staging!
	dbMu.Lock()
	dbTables["reno26_prod"]["wp_wc_orders"] += "INSERT INTO `wp_wc_orders` VALUES (9002,'processing',599.00,'newbuyer@vip.vn');\n"
	// Designer updates page hero on Staging + removes test order on Staging
	dbTables[stagingInst.DBName]["wp_posts"] = "INSERT INTO `wp_posts` VALUES (1,'a:1:{s:4:\"hero\";s:42:\"https://staging.renolabs-audio.com/v2.webp\";}');\n"
	dbTables[stagingInst.DBName]["wp_wc_orders"] = ""
	dbMu.Unlock()

	if err := os.WriteFile(filepath.Join(stagingInst.DocRoot, "wp-content", "themes", "audib", "style.css"), []byte("/* Theme v2.0 Redesigned */\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Push Staging -> Production (`Mode: "both"`)
	syncRes, err := eng.Sync(ctx, acct, SyncRequest{
		SourceInstanceID: stagingInst.ID,
		TargetInstanceID: prodInst.ID,
		Mode:             SyncModeBoth,
	}, nil)
	if err != nil {
		t.Fatalf("Sync Staging -> Production failed: %v", err)
	}

	if syncRes.PreSyncSnapshotID == "" {
		t.Fatal("expected automatic pre_sync Zstd snapshot to be created before overwriting Production")
	}
	if len(syncRes.PreservedWooTables) < 2 {
		t.Fatalf("expected WooCommerce tables to be detected and preserved, got %v", syncRes.PreservedWooTables)
	}
	if !syncRes.TargetSearchIndexingKept {
		t.Fatal("expected Production SearchIndexing=true to be preserved")
	}

	// Verify theme v2.0 arrived on Production while Production's wp-config.php kept `prod_salt_keep`
	prodStyle, _ := os.ReadFile(filepath.Join(prodDocRoot, "wp-content", "themes", "audib", "style.css"))
	if !strings.Contains(string(prodStyle), "Theme v2.0 Redesigned") {
		t.Fatalf("expected updated theme CSS on Production, got %q", string(prodStyle))
	}
	prodCfgAfter, _ := os.ReadFile(filepath.Join(prodDocRoot, "wp-config.php"))
	saltAfter, _ := hardening.GetDefinedString(string(prodCfgAfter), "WP_CACHE_KEY_SALT")
	if saltAfter != "prod_salt_keep" {
		t.Fatalf("Production wp-config.php WP_CACHE_KEY_SALT was overwritten: got %q", saltAfter)
	}

	// Verify Staging v2 content arrived on Production WITH URL rewritten back to `https://renolabs-audio.com/v2.webp` (s:35)
	// AND live WooCommerce order #9002 on Production was 100% preserved!
	dbMu.Lock()
	prodPosts := dbTables["reno26_prod"]["wp_posts"]
	prodWooOrders := dbTables["reno26_prod"]["wp_wc_orders"]
	prodBlogPublic := blogPublicByDB["reno26_prod"]
	dbMu.Unlock()

	if !strings.Contains(prodPosts, `s:34:"https://renolabs-audio.com/v2.webp";`) {
		t.Fatalf("expected Staging post URL to rewrite cleanly back to Production s:34, got:\n%s", prodPosts)
	}
	if !strings.Contains(prodWooOrders, "9002") || !strings.Contains(prodWooOrders, "newbuyer@vip.vn") {
		t.Fatalf("LIVE WOOCOMMERCE ORDER LOST during Staging->Prod sync! orders:\n%s", prodWooOrders)
	}
	if prodBlogPublic != "1" {
		t.Fatalf("Production blog_public must remain '1' (indexed), got %q", prodBlogPublic)
	}
}
