package clonesync

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/database"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/hardening"
	"github.com/shostwp-byte/da-wptoolkits/internal/snapshot"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

const (
	SyncModeBoth  = "both"
	SyncModeFiles = "files"
	SyncModeDB    = "db"
)

var wooCommerceProtectedSuffixes = []string{
	"wc_orders",
	"wc_order_addresses",
	"wc_order_operational_data",
	"wc_order_stats",
	"wc_orders_meta",
	"wc_order_product_lookup",
	"wc_order_tax_lookup",
	"wc_order_coupon_lookup",
	"wc_customer_lookup",
	"wc_download_log",
	"woocommerce_order_items",
	"woocommerce_order_itemmeta",
	"woocommerce_sessions",
	"woocommerce_payment_tokens",
	"woocommerce_payment_tokenmeta",
}

// CloneRequest defines parameters for 1-Click Clone / Staging creation (TC-09).
type CloneRequest struct {
	SourceInstanceID  string `json:"source_instance_id"`
	TargetDomain      string `json:"target_domain"`
	TargetSubPath     string `json:"target_sub_path,omitempty"`
	CreateSubdomain   *bool  `json:"create_subdomain,omitempty"` // default true
	EnvironmentTag    string `json:"environment_tag,omitempty"`  // staging | production | development
	SetNoIndex        *bool  `json:"set_noindex,omitempty"`      // default true when staging/development
	TargetSiteTitle   string `json:"target_site_title,omitempty"`
	TargetTablePrefix string `json:"target_table_prefix,omitempty"`
	Overwrite         bool   `json:"overwrite,omitempty"`
	AdminBypass       bool   `json:"-"`
}

// CloneResult summarizes the newly cloned WordPress instance.
type CloneResult struct {
	Instance          store.InstanceRecord `json:"instance"`
	CreatedSubdomain  bool                 `json:"created_subdomain"`
	CopiedFiles       int                  `json:"copied_files"`
	SQLReplacements   int                  `json:"sql_replacements"`
	CacheKeySalt      string               `json:"cache_key_salt"`
	SearchEngineNoIdx bool                 `json:"search_engine_noindex"`
}

// SyncRequest defines parameters for Bidirectional Staging <-> Production Sync.
type SyncRequest struct {
	SourceInstanceID    string `json:"source_instance_id"`
	TargetInstanceID    string `json:"target_instance_id"`
	Mode                string `json:"mode"`                 // both | files | db (default "both")
	AutoSnapshot        *bool  `json:"auto_snapshot"`        // default true
	PreserveWooCommerce *bool  `json:"preserve_woocommerce"` // default true
	OverwriteUploads    *bool  `json:"overwrite_uploads"`    // default true
	AdminBypass         bool   `json:"-"`
}

// SyncResult summarizes a completed Bidirectional Sync run.
type SyncResult struct {
	SourceInstance           store.InstanceRecord `json:"source_instance"`
	TargetInstance           store.InstanceRecord `json:"target_instance"`
	Mode                     string               `json:"mode"`
	PreSyncSnapshotID        string               `json:"pre_sync_snapshot_id,omitempty"`
	SyncedFiles              int                  `json:"synced_files"`
	SQLReplacements          int                  `json:"sql_replacements"`
	PreservedWooTables       []string             `json:"preserved_woo_tables,omitempty"`
	TargetSearchIndexingKept bool                 `json:"target_search_indexing_kept"`
}

// Engine orchestrates 1-Click Clone/Staging (with Redis WP_CACHE_KEY_SALT isolation & serialized-safe URL replacement)
// and Bidirectional Sync (with Pre-Sync Zstd Snapshot & WooCommerce order preservation).
type Engine struct {
	Domains               *dadomains.Resolver
	DB                    database.Provisioner
	WPCLI                 *wpcli.Runner
	Snapshots             *snapshot.Manager
	Store                 *store.Store
	Policies              *config.PolicyStore
	DAAPIConfPath         string
	DAHooksDir            string
	WithShieldSuppression func(acct dausers.Account, inst store.InstanceRecord, fn func() error) error
}

func NewEngine(
	domains *dadomains.Resolver,
	db database.Provisioner,
	wp *wpcli.Runner,
	snaps *snapshot.Manager,
	st *store.Store,
	policies *config.PolicyStore,
) *Engine {
	return &Engine{
		Domains:   domains,
		DB:        db,
		WPCLI:     wp,
		Snapshots: snaps,
		Store:     st,
		Policies:  policies,
	}
}

// Clone creates an isolated copy of a WordPress instance on a target Domain/Subdomain/SubPath (TC-09).
func (e *Engine) Clone(
	ctx context.Context,
	acct dausers.Account,
	req CloneRequest,
	report store.ProgressReporter,
) (CloneResult, error) {
	if report == nil {
		report = func(int, string) {}
	}
	if e.Store == nil || e.Domains == nil || e.DB == nil || e.WPCLI == nil {
		return CloneResult{}, errors.New("clone engine dependencies are not fully configured")
	}

	pol := e.resolvePolicy(acct.Package)
	if !req.AdminBypass {
		if !pol.Enabled {
			return CloneResult{}, errors.New("WordPress Toolkit is disabled for your hosting package")
		}
		if !pol.AllowClone {
			return CloneResult{}, errors.New("WordPress Clone/Staging is disabled for your hosting package")
		}
		if pol.MaxInstances > 0 && len(e.Store.ListInstancesByOwner(acct.Username)) >= pol.MaxInstances {
			return CloneResult{}, fmt.Errorf("hosting package limit reached (%d WordPress instances maximum)", pol.MaxInstances)
		}
	}

	source, err := e.Store.GetInstanceForOwner(strings.TrimSpace(req.SourceInstanceID), acct.Username)
	if err != nil {
		return CloneResult{}, fmt.Errorf("source instance: %w", err)
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, func(targetPath, reason string) {
		e.recordSymlinkViolation(acct, source.ID, targetPath, reason)
	})
	if err != nil {
		return CloneResult{}, err
	}
	verifiedSrcDocRoot, err := guard.VerifyExistingPath(source.DocRoot)
	if err != nil {
		return CloneResult{}, err
	}

	allowCreateSub := true
	if req.CreateSubdomain != nil {
		allowCreateSub = *req.CreateSubdomain
	}

	report(10, "Resolving target domain/subdomain topology")
	targetDom, createdSub, err := e.EnsureTargetSubdomain(ctx, acct, req.TargetDomain, allowCreateSub)
	if err != nil {
		return CloneResult{}, err
	}

	subPath, err := normalizeCloneSubPath(req.TargetSubPath)
	if err != nil {
		return CloneResult{}, err
	}
	if subPath != "" {
		relCheck := strings.TrimPrefix(subPath, "/")
		if owningSub, conflict := targetDom.ExcludedRelPaths[relCheck]; conflict {
			return CloneResult{}, fmt.Errorf("path %s belongs to subdomain %s; please clone directly to %s", subPath, owningSub, owningSub)
		}
	}

	rawTargetDocRoot := targetDom.DocRoot
	if subPath != "" {
		rawTargetDocRoot = filepath.Join(targetDom.DocRoot, filepath.FromSlash(strings.TrimPrefix(subPath, "/")))
	}
	verifiedDstDocRoot, err := guard.VerifyProspectivePath(rawTargetDocRoot)
	if err != nil {
		return CloneResult{}, err
	}
	if verifiedDstDocRoot == verifiedSrcDocRoot {
		return CloneResult{}, errors.New("target document root cannot be identical to source document root")
	}

	for _, existing := range e.Store.ListAllInstances(false) {
		if filepath.Clean(existing.DocRoot) == verifiedDstDocRoot {
			return CloneResult{}, fmt.Errorf("target path already hosts registered WordPress instance %s (%s%s)", existing.ID, existing.Domain, existing.SubPath)
		}
	}
	if !req.Overwrite && hasWPFiles(verifiedDstDocRoot) {
		return CloneResult{}, fmt.Errorf("a WordPress installation already exists at %s%s (enable overwrite to replace unmanaged files)", targetDom.Domain, subPath)
	}

	envTag := normalizeEnvTag(req.EnvironmentTag, targetDom.Domain, subPath)
	setNoIndex := envTag != "production"
	if req.SetNoIndex != nil {
		setNoIndex = *req.SetNoIndex
	}

	targetPrefix := strings.TrimSpace(req.TargetTablePrefix)
	if targetPrefix == "" {
		targetPrefix = source.TablePrefix
	}
	if targetPrefix == "" {
		targetPrefix = "wp_"
	}
	if !isValidSQLPrefix(targetPrefix) {
		return CloneResult{}, errors.New("invalid target_table_prefix: must match [a-zA-Z0-9_]+ and end with '_'")
	}

	scheme := "http://"
	if targetDom.SSLActive || strings.HasPrefix(strings.ToLower(source.SiteURL), "https://") && targetDom.Domain == source.Domain {
		scheme = "https://"
	}
	targetURL := scheme + targetDom.Domain + subPath
	sourceURL := strings.TrimRight(source.SiteURL, "/")
	if sourceURL == "" {
		srcScheme := "http://"
		if source.SSLActive {
			srcScheme = "https://"
		}
		sourceURL = srcScheme + source.Domain + source.SubPath
	}

	srcExclusions, srcPHP := e.resolveExclusionsAndPHP(acct, source.Domain, verifiedSrcDocRoot)
	// Always exclude verifiedDstDocRoot if it sits inside verifiedSrcDocRoot (e.g. classic subdomain `public_html/staging`)
	if relDst, rErr := filepath.Rel(verifiedSrcDocRoot, verifiedDstDocRoot); rErr == nil && relDst != "." && relDst != ".." && !strings.HasPrefix(relDst, ".."+string(filepath.Separator)) {
		srcExclusions[filepath.ToSlash(relDst)] = struct{}{}
	}
	dstExclusions, _ := e.resolveExclusionsAndPHP(acct, targetDom.Domain, verifiedDstDocRoot)

	// Step 1: Provision dedicated MariaDB database for cloned site
	report(22, "Provisioning isolated MariaDB database for cloned site")
	dbCreds, err := e.DB.CreateDatabase(ctx, acct, targetDom.Domain)
	if err != nil {
		return CloneResult{}, fmt.Errorf("database provisioning failed: %w", err)
	}
	rollbackDB := true
	defer func() {
		if rollbackDB {
			_ = e.DB.DropDatabase(context.Background(), acct, dbCreds.DBName, dbCreds.DBUser)
		}
	}()

	if err := ensureOwnedDirHierarchy(domainsRoot, verifiedDstDocRoot, acct.UID, acct.GID); err != nil {
		return CloneResult{}, err
	}

	// Step 2: Copy WordPress files Source -> Target (blocking symlinks & skipping sibling subdomains + transient artifacts)
	report(42, "Copying WordPress Core, Plugins, Themes, and Media files")
	copiedFiles, err := e.copyInstanceTree(ctx, acct, source.ID, verifiedSrcDocRoot, verifiedDstDocRoot, srcExclusions, dstExclusions)
	if err != nil {
		return CloneResult{}, err
	}

	// Step 3: Rewrite Target wp-config.php with new DB credentials, fresh 8 auth salts, and isolated WP_CACHE_KEY_SALT (TC-09)
	report(58, "Isolating wp-config.php credentials, auth salts, and Redis WP_CACHE_KEY_SALT")
	srcConfigBytes, err := guard.ReadRegularFileUnderVerifiedRoot(verifiedSrcDocRoot, 256*1024, "wp-config.php")
	if err != nil {
		return CloneResult{}, fmt.Errorf("read source wp-config.php: %w", err)
	}
	oldCacheSalt, _ := hardening.GetDefinedString(string(srcConfigBytes), "WP_CACHE_KEY_SALT")
	newCacheSalt, err := generateUniqueCacheKeySalt(targetDom.Domain+subPath, oldCacheSalt)
	if err != nil {
		return CloneResult{}, err
	}
	rewrittenWPConfig, err := rewriteClonedWPConfig(string(srcConfigBytes), dbCreds, targetPrefix, newCacheSalt)
	if err != nil {
		return CloneResult{}, err
	}
	if err := writeAtomicOwnedFile(filepath.Join(verifiedDstDocRoot, "wp-config.php"), []byte(rewrittenWPConfig), acct.UID, acct.GID, 0o600); err != nil {
		return CloneResult{}, fmt.Errorf("write target wp-config.php: %w", err)
	}

	// Remove copied `.htaccess` password protection blocks if any existed on source
	e.stripCopiedPasswordProtectBlock(verifiedDstDocRoot, acct.UID, acct.GID)

	// Step 4: Export Source DB -> PHP-Serialized-Safe URL & Path Replacement -> Import into Target DB
	report(75, "Exporting database and running serialized-safe URL & path replacement")
	sqlReplacements, err := e.transferAndTransformDatabase(
		ctx,
		acct,
		verifiedSrcDocRoot, srcPHP,
		verifiedDstDocRoot, targetDom.PHP,
		sourceURL, targetURL,
		source.TablePrefix, targetPrefix,
		nil,
	)
	if err != nil {
		return CloneResult{}, err
	}

	// Step 5: Configure Target indexing (`noindex` on Staging), optional Site Title, and isolated cache flush
	report(90, "Applying search engine indexing policy and flushing isolated object cache")
	blogPublicVal := "1"
	if setNoIndex {
		blogPublicVal = "0"
	}
	_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDstDocRoot,
		PHP:         targetDom.PHP,
		Args:        []string{"option", "update", "blog_public", blogPublicVal},
		SkipPlugins: true,
		SkipThemes:  true,
	})

	finalTitle := source.SiteTitle
	if cleanTitle := strings.TrimSpace(req.TargetSiteTitle); cleanTitle != "" {
		finalTitle = cleanTitle
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDstDocRoot,
			PHP:         targetDom.PHP,
			Args:        []string{"option", "update", "blogname", finalTitle},
			SkipPlugins: true,
			SkipThemes:  true,
		})
	}

	// Flush cache strictly on Target (Target's wp-config.php already carries the new WP_CACHE_KEY_SALT!)
	_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedDstDocRoot,
		PHP:         targetDom.PHP,
		Args:        []string{"cache", "flush"},
		SkipPlugins: true,
		SkipThemes:  true,
	})

	// Step 6: Register cloned instance in Store
	newInst := store.InstanceRecord{
		Owner:              acct.Username,
		OwnerUID:           acct.UID,
		Domain:             targetDom.Domain,
		DomainType:         targetDom.DomainType,
		SubPath:            subPath,
		DocRoot:            verifiedDstDocRoot,
		SiteURL:            targetURL,
		SiteTitle:          finalTitle,
		AdminUser:          source.AdminUser,
		AdminEmail:         source.AdminEmail,
		WPVersion:          source.WPVersion,
		Locale:             source.Locale,
		PHPVersion:         targetDom.PHP.Version,
		MemoryLimit:        source.MemoryLimit,
		DBName:             dbCreds.DBName,
		DBUser:             dbCreds.DBUser,
		TablePrefix:        targetPrefix,
		ActiveTheme:        source.ActiveTheme,
		SSLActive:          targetDom.SSLActive,
		SearchIndexing:     !setNoIndex,
		CacheEnabled:       source.CacheEnabled,
		CoreShieldMode:     pol.DefaultCoreShieldMode,
		CoreIntegrityClean: true,
		SecurityScore:      source.SecurityScore,
		SecurityTotal:      12,
		PluginCount:        source.PluginCount,
		ThemeCount:         source.ThemeCount,
		EnvironmentTag:     envTag,
		ParentInstanceID:   source.ID,
		LastScannedAt:      time.Now().UTC(),
	}
	saved, err := e.Store.UpsertInstance(newInst)
	if err != nil {
		return CloneResult{}, err
	}

	rollbackDB = false
	report(100, "Clone completed successfully")
	return CloneResult{
		Instance:          saved,
		CreatedSubdomain:  createdSub,
		CopiedFiles:       copiedFiles,
		SQLReplacements:   sqlReplacements,
		CacheKeySalt:      newCacheSalt,
		SearchEngineNoIdx: setNoIndex,
	}, nil
}

// Sync synchronizes Files, Database, or Both between two WordPress instances owned by the same DirectAdmin user,
// automatically creating a Pre-Sync Zstd Snapshot of the Target and preserving live WooCommerce orders/customers.
func (e *Engine) Sync(
	ctx context.Context,
	acct dausers.Account,
	req SyncRequest,
	report store.ProgressReporter,
) (SyncResult, error) {
	if report == nil {
		report = func(int, string) {}
	}
	if e.Store == nil || e.Domains == nil || e.WPCLI == nil {
		return SyncResult{}, errors.New("sync engine dependencies are not fully configured")
	}

	pol := e.resolvePolicy(acct.Package)
	if !req.AdminBypass {
		if !pol.Enabled {
			return SyncResult{}, errors.New("WordPress Toolkit is disabled for your hosting package")
		}
		if !pol.AllowStagingSync {
			return SyncResult{}, errors.New("Staging Sync is disabled for your hosting package")
		}
	}

	mode := normalizeSyncMode(req.Mode)
	autoSnap := true
	if req.AutoSnapshot != nil {
		autoSnap = *req.AutoSnapshot
	}
	preserveWoo := true
	if req.PreserveWooCommerce != nil {
		preserveWoo = *req.PreserveWooCommerce
	}
	overwriteUploads := true
	if req.OverwriteUploads != nil {
		overwriteUploads = *req.OverwriteUploads
	}

	srcID := strings.TrimSpace(req.SourceInstanceID)
	dstID := strings.TrimSpace(req.TargetInstanceID)
	if srcID == "" || dstID == "" || srcID == dstID {
		return SyncResult{}, errors.New("distinct source_instance_id and target_instance_id are required")
	}

	source, err := e.Store.GetInstanceForOwner(srcID, acct.Username)
	if err != nil {
		return SyncResult{}, fmt.Errorf("source instance: %w", err)
	}
	target, err := e.Store.GetInstanceForOwner(dstID, acct.Username)
	if err != nil {
		return SyncResult{}, fmt.Errorf("target instance: %w", err)
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, func(targetPath, reason string) {
		e.recordSymlinkViolation(acct, target.ID, targetPath, reason)
	})
	if err != nil {
		return SyncResult{}, err
	}
	verifiedSrcDocRoot, err := guard.VerifyExistingPath(source.DocRoot)
	if err != nil {
		return SyncResult{}, err
	}
	verifiedDstDocRoot, err := guard.VerifyExistingPath(target.DocRoot)
	if err != nil {
		return SyncResult{}, err
	}

	srcExclusions, srcPHP := e.resolveExclusionsAndPHP(acct, source.Domain, verifiedSrcDocRoot)
	dstExclusions, dstPHP := e.resolveExclusionsAndPHP(acct, target.Domain, verifiedDstDocRoot)
	if relDst, rErr := filepath.Rel(verifiedSrcDocRoot, verifiedDstDocRoot); rErr == nil && relDst != "." && relDst != ".." && !strings.HasPrefix(relDst, ".."+string(filepath.Separator)) {
		srcExclusions[filepath.ToSlash(relDst)] = struct{}{}
	}
	if relSrc, rErr := filepath.Rel(verifiedDstDocRoot, verifiedSrcDocRoot); rErr == nil && relSrc != "." && relSrc != ".." && !strings.HasPrefix(relSrc, ".."+string(filepath.Separator)) {
		dstExclusions[filepath.ToSlash(relSrc)] = struct{}{}
	}

	// Step 1: Automatic Pre-Sync Zstandard Snapshot on Target before any destructive change
	var preSyncSnapID string
	if autoSnap && e.Snapshots != nil && (pol.MaxSnapshotsPerSite > 0 || req.AdminBypass) {
		report(15, "Creating automatic pre-sync Zstandard (.tar.zst) snapshot of target site")
		snapRec, sErr := e.Snapshots.CreateSnapshot(ctx, acct, snapshot.CreateRequest{
			InstanceID:  target.ID,
			Kind:        snapshot.KindPreSync,
			Note:        fmt.Sprintf("Auto backup before sync from %s%s", source.Domain, source.SubPath),
			AdminBypass: req.AdminBypass,
		}, nil)
		if sErr != nil {
			return SyncResult{}, fmt.Errorf("pre-sync safety snapshot failed: %w", sErr)
		}
		preSyncSnapID = snapRec.ID
		if refreshed, gErr := e.Store.GetInstanceForOwner(target.ID, acct.Username); gErr == nil {
			target = refreshed
		}
	}

	var syncedFiles int
	var sqlReplacements int
	var preservedWoo []string

	syncExec := func() error {
		if mode == SyncModeFiles || mode == SyncModeBoth {
			report(45, "Synchronizing WordPress files to target while preserving wp-config.php & .htaccess")
			var fErr error
			syncedFiles, fErr = e.syncSelectedDirectories(ctx, acct, source.ID, verifiedSrcDocRoot, verifiedDstDocRoot, srcExclusions, dstExclusions, overwriteUploads)
			if fErr != nil {
				return fErr
			}
		}

		if mode == SyncModeDB || mode == SyncModeBoth {
			var wooTables []string
			if preserveWoo {
				wooTables = e.detectExistingWooCommerceTables(ctx, acct, verifiedDstDocRoot, dstPHP, target.TablePrefix)
			}
			preservedWoo = wooTables

			report(72, "Synchronizing database with PHP-serialized URL rewrite and WooCommerce order protection")
			var dbErr error
			sqlReplacements, dbErr = e.transferAndTransformDatabase(
				ctx,
				acct,
				verifiedSrcDocRoot, srcPHP,
				verifiedDstDocRoot, dstPHP,
				strings.TrimRight(source.SiteURL, "/"),
				strings.TrimRight(target.SiteURL, "/"),
				source.TablePrefix,
				target.TablePrefix,
				wooTables,
			)
			if dbErr != nil {
				return dbErr
			}

			// Restore Target's own Search Engine Indexing policy (`blog_public`) so Staging -> Prod never leaves Prod on `noindex`!
			blogPub := "0"
			if target.SearchIndexing {
				blogPub = "1"
			}
			_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedDstDocRoot,
				PHP:         dstPHP,
				Args:        []string{"option", "update", "blog_public", blogPub},
				SkipPlugins: true,
				SkipThemes:  true,
			})
		}

		report(92, "Flushing target WordPress object cache")
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDstDocRoot,
			PHP:         dstPHP,
			Args:        []string{"cache", "flush"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		return nil
	}

	if e.WithShieldSuppression != nil {
		err = e.WithShieldSuppression(acct, target, syncExec)
	} else {
		err = syncExec()
	}
	if err != nil {
		return SyncResult{}, err
	}

	if mode == SyncModeFiles || mode == SyncModeBoth {
		target.WPVersion = source.WPVersion
		target.ActiveTheme = source.ActiveTheme
		target.PluginCount = source.PluginCount
		target.ThemeCount = source.ThemeCount
	}
	target.LastScannedAt = time.Now().UTC()
	if savedTarget, uErr := e.Store.UpsertInstance(target); uErr == nil {
		target = savedTarget
	}

	report(100, "Synchronization completed successfully")
	return SyncResult{
		SourceInstance:           source,
		TargetInstance:           target,
		Mode:                     mode,
		PreSyncSnapshotID:        preSyncSnapID,
		SyncedFiles:              syncedFiles,
		SQLReplacements:          sqlReplacements,
		PreservedWooTables:       preservedWoo,
		TargetSearchIndexingKept: target.SearchIndexing,
	}, nil
}

func (e *Engine) transferAndTransformDatabase(
	ctx context.Context,
	acct dausers.Account,
	srcDocRoot string, srcPHP daphp.Selection,
	dstDocRoot string, dstPHP daphp.Selection,
	sourceURL, targetURL string,
	srcTablePrefix, dstTablePrefix string,
	preserveTargetTables []string,
) (int, error) {
	randStr, _ := randomHex(6)
	srcDumpPath := filepath.Join(srcDocRoot, ".da-wptk-sync-src-"+randStr+".sql")
	dstDumpPath := filepath.Join(dstDocRoot, ".da-wptk-sync-dst-"+randStr+".sql")
	wooDumpPath := filepath.Join(dstDocRoot, ".da-wptk-sync-woo-"+randStr+".sql")
	defer func() {
		_ = os.Remove(srcDumpPath)
		_ = os.Remove(dstDumpPath)
		_ = os.Remove(wooDumpPath)
	}()

	// 1. If preserving WooCommerce live tables on Target, export them BEFORE overwriting Target DB
	hasWooBackup := false
	if len(preserveTargetTables) > 0 {
		tablesCSV := strings.Join(preserveTargetTables, ",")
		out, wErr := e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     dstDocRoot,
			PHP:         dstPHP,
			Args:        []string{"db", "export", wooDumpPath, "--tables=" + tablesCSV, "--add-drop-table"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		if wErr != nil {
			return 0, fmt.Errorf("backup target WooCommerce tables failed: %w", wErr)
		}
		if st, sErr := os.Lstat(wooDumpPath); sErr == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return 0, fsguard.ErrSymlinkBlocked
			}
			hasWooBackup = st.Size() > 0
		} else if strings.TrimSpace(out) != "" && (strings.Contains(out, "CREATE TABLE") || strings.Contains(out, "INSERT INTO")) {
			if err := writeAtomicOwnedFile(wooDumpPath, []byte(out), acct.UID, acct.GID, 0o600); err == nil {
				hasWooBackup = true
			}
		}
	}

	// 2. Export Source DB
	srcStdout, err := e.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     srcDocRoot,
		PHP:         srcPHP,
		Args:        []string{"db", "export", srcDumpPath, "--add-drop-table"},
		SkipPlugins: true,
		SkipThemes:  true,
	})
	if err != nil {
		return 0, fmt.Errorf("export source database failed: %w", err)
	}

	var rawSQLBytes []byte
	if st, sErr := os.Lstat(srcDumpPath); sErr == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return 0, fsguard.ErrSymlinkBlocked
		}
		rawSQLBytes, err = os.ReadFile(srcDumpPath)
		if err != nil {
			return 0, err
		}
	} else {
		rawSQLBytes = []byte(srcStdout)
	}

	// 3. Transform SQL dump using Pure-Go PHP Serialized-Safe & Elementor JSON-Safe Replacer
	pairs := buildURLAndPathPairs(sourceURL, targetURL, srcDocRoot, dstDocRoot)
	transformedSQL, replacements := ReplaceSQLDumpSafe(string(rawSQLBytes), pairs, srcTablePrefix, dstTablePrefix)

	if err := writeAtomicOwnedFile(dstDumpPath, []byte(transformedSQL), acct.UID, acct.GID, 0o600); err != nil {
		return 0, err
	}

	// 4. Import transformed SQL into Target DB
	if _, err := e.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     dstDocRoot,
		PHP:         dstPHP,
		Args:        []string{"db", "import", dstDumpPath},
		SkipPlugins: true,
		SkipThemes:  true,
	}); err != nil {
		return 0, fmt.Errorf("import target database failed: %w", err)
	}

	// 5. Re-import preserved Target WooCommerce order/customer tables
	if hasWooBackup {
		if _, err := e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     dstDocRoot,
			PHP:         dstPHP,
			Args:        []string{"db", "import", wooDumpPath},
			SkipPlugins: true,
			SkipThemes:  true,
		}); err != nil {
			return 0, fmt.Errorf("restore preserved WooCommerce tables failed: %w", err)
		}
	}

	// 6. Run WP-CLI `--precise` search-replace & explicit home/siteurl updates as defense-in-depth
	if sourceURL != "" && targetURL != "" && sourceURL != targetURL {
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     dstDocRoot,
			PHP:         dstPHP,
			Args:        []string{"search-replace", sourceURL, targetURL, "--all-tables-with-prefix", "--precise"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
	}
	if targetURL != "" {
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     dstDocRoot,
			PHP:         dstPHP,
			Args:        []string{"option", "update", "home", targetURL},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     dstDocRoot,
			PHP:         dstPHP,
			Args:        []string{"option", "update", "siteurl", targetURL},
			SkipPlugins: true,
			SkipThemes:  true,
		})
	}

	return replacements, nil
}

func (e *Engine) detectExistingWooCommerceTables(ctx context.Context, acct dausers.Account, dstDocRoot string, dstPHP daphp.Selection, tablePrefix string) []string {
	if tablePrefix == "" {
		tablePrefix = "wp_"
	}
	wantSet := make(map[string]struct{}, len(wooCommerceProtectedSuffixes))
	for _, suf := range wooCommerceProtectedSuffixes {
		wantSet[strings.ToLower(tablePrefix+suf)] = struct{}{}
	}

	out, err := e.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     dstDocRoot,
		PHP:         dstPHP,
		Args:        []string{"db", "tables", "--all-tables-with-prefix", "--format=csv"},
		SkipPlugins: true,
		SkipThemes:  true,
	})
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}

	var matched []string
	seen := make(map[string]struct{})
	for _, token := range strings.FieldsFunc(out, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	}) {
		clean := strings.TrimSpace(token)
		lower := strings.ToLower(clean)
		if _, ok := wantSet[lower]; ok {
			if _, dup := seen[lower]; !dup {
				seen[lower] = struct{}{}
				matched = append(matched, clean)
			}
		}
	}
	return matched
}

func (e *Engine) copyInstanceTree(
	ctx context.Context,
	acct dausers.Account,
	sourceInstanceID string,
	srcRoot, dstRoot string,
	srcExclusions, dstExclusions map[string]struct{},
) (int, error) {
	copied := 0
	var walk func(absSrc, absDst, relSlash string) error
	walk = func(absSrc, absDst, relSlash string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(absSrc)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			name := ent.Name()
			childRel := name
			if relSlash != "" {
				childRel = relSlash + "/" + name
			}
			if isCloneSkippedPath(name, childRel, srcExclusions, dstExclusions) {
				continue
			}

			srcChild := filepath.Join(absSrc, name)
			dstChild := filepath.Join(absDst, name)
			lstat, err := os.Lstat(srcChild)
			if err != nil {
				return err
			}
			if lstat.Mode()&os.ModeSymlink != 0 {
				e.recordSymlinkViolation(acct, sourceInstanceID, srcChild, "symlink inside source DocRoot blocked during clone")
				return fmt.Errorf("%w: %s", fsguard.ErrSymlinkBlocked, srcChild)
			}
			if lstat.IsDir() {
				if dStat, dErr := os.Lstat(dstChild); dErr == nil && dStat.Mode()&os.ModeSymlink != 0 {
					return fsguard.ErrSymlinkBlocked
				}
				if err := os.MkdirAll(dstChild, 0o755); err != nil {
					return err
				}
				chownCustomerIfRoot(dstChild, acct.UID, acct.GID)
				if childRel == "wp-content/cache" || childRel == "wp-content/litespeed/cache" {
					continue
				}
				if err := walk(srcChild, dstChild, childRel); err != nil {
					return err
				}
				continue
			}
			if !lstat.Mode().IsRegular() {
				continue
			}
			mode := os.FileMode(0o644)
			if childRel == "wp-config.php" {
				mode = 0o600
			}
			if err := copyVerifiedRegularFile(srcChild, dstChild, lstat, acct.UID, acct.GID, mode); err != nil {
				return err
			}
			copied++
		}
		return nil
	}
	return copied, walk(srcRoot, dstRoot, "")
}

func (e *Engine) syncSelectedDirectories(
	ctx context.Context,
	acct dausers.Account,
	sourceInstanceID string,
	srcRoot, dstRoot string,
	srcExclusions, dstExclusions map[string]struct{},
	overwriteUploads bool,
) (int, error) {
	// Sync Core (`wp-admin`, `wp-includes` & root WP files except `wp-config.php`, `.htaccess`, `.user.ini`, `.maintenance`)
	// and `wp-content/{plugins,themes,mu-plugins,languages,uploads}`.
	synced := 0

	// 1. Root regular PHP/Core files (preserving Target's wp-config.php, .htaccess, .user.ini, .maintenance, .well-known)
	preservedRootFiles := map[string]struct{}{
		"wp-config.php": {},
		".htaccess":     {},
		".user.ini":     {},
		"php.ini":       {},
		".maintenance":  {},
	}
	rootEntries, err := os.ReadDir(srcRoot)
	if err != nil {
		return 0, err
	}
	for _, ent := range rootEntries {
		name := ent.Name()
		if _, keep := preservedRootFiles[name]; keep {
			continue
		}
		if isCloneSkippedPath(name, name, srcExclusions, dstExclusions) {
			continue
		}
		srcPath := filepath.Join(srcRoot, name)
		lstat, lErr := os.Lstat(srcPath)
		if lErr != nil {
			continue
		}
		if lstat.Mode()&os.ModeSymlink != 0 {
			e.recordSymlinkViolation(acct, sourceInstanceID, srcPath, "symlink inside source DocRoot blocked during sync")
			return synced, fmt.Errorf("%w: %s", fsguard.ErrSymlinkBlocked, srcPath)
		}
		if lstat.Mode().IsRegular() {
			if err := copyVerifiedRegularFile(srcPath, filepath.Join(dstRoot, name), lstat, acct.UID, acct.GID, 0o644); err != nil {
				return synced, err
			}
			synced++
		}
	}

	// 2. Managed subdirectories (`plugins`, `themes`, `mu-plugins`, `languages`, `wp-admin`, `wp-includes` mirrored cleanly; `uploads` merged/updated)
	mirrorSubdirs := []string{
		"wp-admin",
		"wp-includes",
		"wp-content/plugins",
		"wp-content/themes",
		"wp-content/mu-plugins",
		"wp-content/languages",
	}
	for _, rel := range mirrorSubdirs {
		if isRelExcluded(rel, srcExclusions) || isRelExcluded(rel, dstExclusions) {
			continue
		}
		srcSub := filepath.Join(srcRoot, filepath.FromSlash(rel))
		dstSub := filepath.Join(dstRoot, filepath.FromSlash(rel))
		if st, sErr := os.Lstat(srcSub); sErr != nil {
			if errors.Is(sErr, os.ErrNotExist) {
				continue
			}
			return synced, sErr
		} else if st.Mode()&os.ModeSymlink != 0 {
			return synced, fsguard.ErrSymlinkBlocked
		}

		// Clean existing target subdir before mirroring so removed plugin/theme files don't linger
		if dStat, dErr := os.Lstat(dstSub); dErr == nil {
			if dStat.Mode()&os.ModeSymlink != 0 {
				return synced, fsguard.ErrSymlinkBlocked
			}
			_ = os.RemoveAll(dstSub)
		}
		if err := os.MkdirAll(dstSub, 0o755); err != nil {
			return synced, err
		}
		chownCustomerIfRoot(dstSub, acct.UID, acct.GID)
		n, cErr := e.copyInstanceTree(ctx, acct, sourceInstanceID, srcSub, dstSub, nil, nil)
		synced += n
		if cErr != nil {
			return synced, cErr
		}
	}

	if overwriteUploads && !isRelExcluded("wp-content/uploads", srcExclusions) && !isRelExcluded("wp-content/uploads", dstExclusions) {
		srcUploads := filepath.Join(srcRoot, "wp-content", "uploads")
		dstUploads := filepath.Join(dstRoot, "wp-content", "uploads")
		if st, sErr := os.Lstat(srcUploads); sErr == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			if err := os.MkdirAll(dstUploads, 0o755); err != nil {
				return synced, err
			}
			chownCustomerIfRoot(dstUploads, acct.UID, acct.GID)
			n, cErr := e.copyInstanceTree(ctx, acct, sourceInstanceID, srcUploads, dstUploads, nil, nil)
			synced += n
			if cErr != nil {
				return synced, cErr
			}
		}
	}

	return synced, nil
}

func (e *Engine) stripCopiedPasswordProtectBlock(dstDocRoot string, uid, gid uint32) {
	htaPath := filepath.Join(dstDocRoot, ".htaccess")
	st, err := os.Lstat(htaPath)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return
	}
	raw, err := os.ReadFile(htaPath)
	if err != nil {
		return
	}
	s := string(raw)
	const beginMarker = "# BEGIN DA-WPTOOLKIT password_protect"
	const endMarker = "# END DA-WPTOOLKIT password_protect"
	bIdx := strings.Index(s, beginMarker)
	eIdx := strings.Index(s, endMarker)
	if bIdx >= 0 && eIdx > bIdx {
		after := eIdx + len(endMarker)
		if after < len(s) && s[after] == '\n' {
			after++
		}
		cleaned := s[:bIdx] + s[after:]
		_ = writeAtomicOwnedFile(htaPath, []byte(cleaned), uid, gid, 0o644)
	}
}

func (e *Engine) resolvePolicy(pkg string) config.PackagePolicy {
	pol := config.DefaultPackagePolicy()
	if e.Policies != nil {
		if resolved, err := e.Policies.ResolvePackagePolicy(pkg); err == nil {
			pol = resolved
		}
	}
	return pol
}

func (e *Engine) resolveExclusionsAndPHP(acct dausers.Account, domain, verifiedDocRoot string) (map[string]struct{}, daphp.Selection) {
	excl := make(map[string]struct{})
	var phpSel daphp.Selection
	if e.Domains == nil {
		return excl, phpSel
	}
	targets, err := e.Domains.ListTargets(acct)
	if err != nil {
		return excl, phpSel
	}
	for _, t := range targets {
		if t.Domain == domain {
			phpSel = t.PHP
		}
		cleanOther := filepath.Clean(t.DocRoot)
		if cleanOther == verifiedDocRoot {
			continue
		}
		rel, rErr := filepath.Rel(verifiedDocRoot, cleanOther)
		if rErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			excl[filepath.ToSlash(rel)] = struct{}{}
		}
	}
	return excl, phpSel
}

func (e *Engine) recordSymlinkViolation(acct dausers.Account, instanceID, targetPath, reason string) {
	if e.Store == nil {
		return
	}
	e.Store.RecordSecurityEvent(store.SecurityAuditEvent{
		Severity:   "critical",
		Category:   "symlink_guard",
		Owner:      acct.Username,
		InstanceID: instanceID,
		Message:    fmt.Sprintf("Clone/Sync symlink guard blocked %s: %s", targetPath, reason),
	})
}

func rewriteClonedWPConfig(srcContent string, creds database.Credentials, tablePrefix, newCacheSalt string) (string, error) {
	cur := srcContent
	var err error
	for _, kv := range [][2]string{
		{"DB_NAME", creds.DBName},
		{"DB_USER", creds.DBUser},
		{"DB_PASSWORD", creds.Password},
		{"DB_HOST", defaultIfBlank(creds.Host, "localhost")},
		{"WP_CACHE_KEY_SALT", newCacheSalt},
	} {
		cur, err = hardening.SetDefinedString(cur, kv[0], kv[1])
		if err != nil {
			return "", err
		}
	}
	// Remove hardcoded WP_HOME / WP_SITEURL if source wp-config.php pinned them, or else cloned site would redirect back to Production!
	cur, _ = hardening.RemoveDefinedConstant(cur, "WP_HOME")
	cur, _ = hardening.RemoveDefinedConstant(cur, "WP_SITEURL")

	if tablePrefix != "" {
		cur, _ = hardening.SetTablePrefix(cur, tablePrefix)
	}
	cur, err = hardening.RegenerateSalts(cur)
	if err != nil {
		return "", err
	}
	return cur, nil
}

func buildURLAndPathPairs(sourceURL, targetURL, srcDocRoot, dstDocRoot string) [][2]string {
	var pairs [][2]string
	cleanSrcURL := strings.TrimRight(strings.TrimSpace(sourceURL), "/")
	cleanDstURL := strings.TrimRight(strings.TrimSpace(targetURL), "/")

	if cleanSrcURL != "" && cleanDstURL != "" && cleanSrcURL != cleanDstURL {
		pairs = append(pairs, [2]string{cleanSrcURL, cleanDstURL})
		// Also map opposite scheme (`http://` <-> `https://`) of source host+subpath -> canonical targetURL
		if strings.HasPrefix(cleanSrcURL, "https://") {
			pairs = append(pairs, [2]string{"http://" + strings.TrimPrefix(cleanSrcURL, "https://"), cleanDstURL})
		} else if strings.HasPrefix(cleanSrcURL, "http://") {
			pairs = append(pairs, [2]string{"https://" + strings.TrimPrefix(cleanSrcURL, "http://"), cleanDstURL})
		}
	}

	cleanSrcRoot := filepath.Clean(srcDocRoot)
	cleanDstRoot := filepath.Clean(dstDocRoot)
	if cleanSrcRoot != cleanDstRoot {
		pairs = append(pairs, [2]string{cleanSrcRoot, cleanDstRoot})
		srcSlash := filepath.ToSlash(cleanSrcRoot)
		dstSlash := filepath.ToSlash(cleanDstRoot)
		if srcSlash != dstSlash {
			pairs = append(pairs, [2]string{srcSlash, dstSlash})
		}
	}
	return pairs
}

func generateUniqueCacheKeySalt(scope, avoidSalt string) (string, error) {
	safeScope := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, scope)
	if len(safeScope) > 36 {
		safeScope = safeScope[:36]
	}
	for attempt := 0; attempt < 4; attempt++ {
		rnd, err := randomHex(6)
		if err != nil {
			return "", err
		}
		cand := "dawptk_" + safeScope + "_" + rnd
		if cand != avoidSalt {
			return cand, nil
		}
	}
	return "dawptk_isolated_" + scope, nil
}

func normalizeCloneSubPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "/" {
		return "", nil
	}
	trimmed = "/" + strings.Trim(filepath.ToSlash(trimmed), "/")
	segs := strings.Split(strings.TrimPrefix(trimmed, "/"), "/")
	if len(segs) > 2 {
		return "", errors.New("target_sub_path depth cannot exceed 2 levels")
	}
	blocked := map[string]struct{}{
		"wp-admin": {}, "wp-content": {}, "wp-includes": {}, "cgi-bin": {}, ".well-known": {},
	}
	for _, seg := range segs {
		if err := config.ValidateIdentifier(seg); err != nil {
			return "", fmt.Errorf("invalid target_sub_path segment %q: %w", seg, err)
		}
		if _, bad := blocked[strings.ToLower(seg)]; bad {
			return "", fmt.Errorf("reserved directory %q cannot be used as target_sub_path", seg)
		}
	}
	return trimmed, nil
}

func normalizeEnvTag(explicit, domain, subPath string) string {
	switch strings.ToLower(strings.TrimSpace(explicit)) {
	case "staging", "production", "development":
		return strings.ToLower(strings.TrimSpace(explicit))
	}
	d := strings.ToLower(domain)
	sp := strings.ToLower(subPath)
	if strings.HasPrefix(d, "staging.") || strings.HasPrefix(d, "stage.") || strings.HasPrefix(d, "test.") || sp == "/staging" || sp == "/stage" {
		return "staging"
	}
	if strings.HasPrefix(d, "dev.") || sp == "/dev" {
		return "development"
	}
	return "staging"
}

func normalizeSyncMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case SyncModeFiles:
		return SyncModeFiles
	case SyncModeDB:
		return SyncModeDB
	default:
		return SyncModeBoth
	}
}

func isCloneSkippedPath(name, relSlash string, srcExcl, dstExcl map[string]struct{}) bool {
	if name == ".maintenance" || strings.HasPrefix(name, ".da-wptk-") || strings.HasPrefix(name, ".wptk-") {
		return true
	}
	if relSlash == ".well-known" || relSlash == "cgi-bin" || strings.HasPrefix(relSlash, ".well-known/") || strings.HasPrefix(relSlash, "cgi-bin/") {
		return true
	}
	if strings.HasPrefix(relSlash, "wp-content/mu-plugins/da-wptk-sso-") || relSlash == "wp-content/maintenance.php" || relSlash == "wp-content/debug.log" {
		return true
	}
	return isRelExcluded(relSlash, srcExcl) || isRelExcluded(relSlash, dstExcl)
}

func isRelExcluded(relSlash string, excl map[string]struct{}) bool {
	for ex := range excl {
		if relSlash == ex || strings.HasPrefix(relSlash, ex+"/") {
			return true
		}
	}
	return false
}

func hasWPFiles(docRoot string) bool {
	if _, err := os.Lstat(filepath.Join(docRoot, "wp-config.php")); err == nil {
		return true
	}
	if _, err := os.Lstat(filepath.Join(docRoot, "wp-includes", "version.php")); err == nil {
		return true
	}
	return false
}

func isValidSQLPrefix(p string) bool {
	if len(p) < 2 || len(p) > 24 || !strings.HasSuffix(p, "_") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func ensureOwnedDirHierarchy(domainsRoot, targetDir string, uid, gid uint32) error {
	rel, err := filepath.Rel(domainsRoot, targetDir)
	if err != nil {
		return err
	}
	cur := domainsRoot
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		if st, err := os.Lstat(cur); err == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				return fsguard.ErrSymlinkBlocked
			}
			continue
		}
		if err := os.MkdirAll(cur, 0o755); err != nil {
			return err
		}
		chownCustomerIfRoot(cur, uid, gid)
	}
	return nil
}

func copyVerifiedRegularFile(srcPath, dstPath string, srcLstat os.FileInfo, uid, gid uint32, mode os.FileMode) error {
	if dstStat, err := os.Lstat(dstPath); err == nil && dstStat.Mode()&os.ModeSymlink != 0 {
		return fsguard.ErrSymlinkBlocked
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	fstat, err := in.Stat()
	if err != nil {
		return err
	}
	if !fstat.Mode().IsRegular() || !os.SameFile(srcLstat, fstat) {
		return fsguard.ErrSymlinkBlocked
	}

	dir := filepath.Dir(dstPath)
	tmp, err := os.CreateTemp(dir, ".da-wptk-c-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	chownCustomerIfRoot(tmpPath, uid, gid)
	if err := os.Rename(tmpPath, dstPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func writeAtomicOwnedFile(path string, content []byte, uid, gid uint32, mode os.FileMode) error {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fsguard.ErrSymlinkBlocked
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".da-wptk-w-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	chownCustomerIfRoot(tmpPath, uid, gid)
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func chownCustomerIfRoot(path string, uid, gid uint32) {
	if os.Geteuid() == 0 && uid >= 1000 {
		_ = chownNoFollow(path, uid, gid)
	}
}

func randomHex(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func defaultIfBlank(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
