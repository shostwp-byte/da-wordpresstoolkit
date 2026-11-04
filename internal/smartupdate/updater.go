package smartupdate

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
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/extensions"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

const DefaultBulkConcurrency = 3

// Request specifies plugins and/or themes to update safely on a single WordPress instance.
type Request struct {
	InstanceID  string   `json:"instance_id"`
	PluginSlugs []string `json:"plugin_slugs,omitempty"`
	AllPlugins  bool     `json:"all_plugins"`
	ThemeSlugs  []string `json:"theme_slugs,omitempty"`
	AllThemes   bool     `json:"all_themes"`
}

// BulkRequest specifies a multi-site Smart Safe Update batch across multiple instances of an account (or server).
type BulkRequest struct {
	InstanceIDs []string `json:"instance_ids"`
	PluginSlugs []string `json:"plugin_slugs,omitempty"`
	AllPlugins  bool     `json:"all_plugins"`
	ThemeSlugs  []string `json:"theme_slugs,omitempty"`
	AllThemes   bool     `json:"all_themes"`
}

// Outcome reports the exact result of a Smart Safe Update on one WordPress instance (TC-08).
type Outcome struct {
	InstanceID      string   `json:"instance_id"`
	Domain          string   `json:"domain"`
	SubPath         string   `json:"sub_path,omitempty"`
	Status          string   `json:"status"` // succeeded | rolled_back | noop | failed
	UpdatedPlugins  []string `json:"updated_plugins,omitempty"`
	UpdatedThemes   []string `json:"updated_themes,omitempty"`
	RolledBack      bool     `json:"rolled_back"`
	RestoredHealthy bool     `json:"restored_healthy"`
	FaultReason     string   `json:"fault_reason,omitempty"`
	CulpritSlugs    []string `json:"culprit_slugs,omitempty"`
	RollbackMillis  int64    `json:"rollback_millis,omitempty"`
	TotalElapsedMs  int64    `json:"total_elapsed_ms"`
}

// BulkOutcome summarizes a completed multi-site Smart Safe Update batch.
type BulkOutcome struct {
	TotalInstances  int       `json:"total_instances"`
	SucceededCount  int       `json:"succeeded_count"`
	RolledBackCount int       `json:"rolled_back_count"`
	FailedCount     int       `json:"failed_count"`
	Results         []Outcome `json:"results"`
}

type stagedBackupItem struct {
	kind       string // "plugin" | "theme"
	slug       string
	livePath   string
	backupPath string
	isDir      bool
	existed    bool
}

// Engine executes Smart Safe Updates with pre-flight directory staging, live HTTP/log health checks,
// and sub-3-second automatic directory rollback on HTTP 500 / PHP Fatal error (TC-08).
type Engine struct {
	Domains        *dadomains.Resolver
	WPCLI          *wpcli.Runner
	Extensions     *extensions.Manager
	Store          *store.Store
	StagingBaseDir string
	ProbeHealth    ProberFunc
	MaxBulkWorkers int
}

func NewEngine(
	domains *dadomains.Resolver,
	wp *wpcli.Runner,
	ext *extensions.Manager,
	st *store.Store,
	stagingBaseDir string,
) *Engine {
	if strings.TrimSpace(stagingBaseDir) == "" {
		stagingBaseDir = "/var/lib/da-wptoolkit/staging/rollback"
	}
	return &Engine{
		Domains:        domains,
		WPCLI:          wp,
		Extensions:     ext,
		Store:          st,
		StagingBaseDir: stagingBaseDir,
		ProbeHealth:    DefaultLoopbackProber,
		MaxBulkWorkers: DefaultBulkConcurrency,
	}
}

// UpdateInstance runs the 3-step Smart Safe Update pipeline on a single WordPress instance.
func (e *Engine) UpdateInstance(
	ctx context.Context,
	acct dausers.Account,
	req Request,
	report store.ProgressReporter,
) (Outcome, error) {
	if report == nil {
		report = func(int, string) {}
	}
	started := time.Now()

	inst, err := e.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), acct.Username)
	if err != nil {
		return Outcome{}, err
	}

	out := Outcome{
		InstanceID: inst.ID,
		Domain:     inst.Domain,
		SubPath:    inst.SubPath,
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return out, err
	}
	verifiedRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return out, err
	}

	var phpSel daphp.Selection
	if e.Domains != nil {
		if tgt, fErr := e.Domains.FindTarget(acct, inst.Domain); fErr == nil {
			phpSel = tgt.PHP
		}
	}

	pluginTargets, err := e.resolveTargetSlugs(ctx, acct, inst.ID, verifiedRoot, "plugin", req.PluginSlugs, req.AllPlugins)
	if err != nil {
		return out, err
	}
	themeTargets, err := e.resolveTargetSlugs(ctx, acct, inst.ID, verifiedRoot, "theme", req.ThemeSlugs, req.AllThemes)
	if err != nil {
		return out, err
	}

	if len(pluginTargets) == 0 && len(themeTargets) == 0 {
		out.Status = "noop"
		out.TotalElapsedMs = time.Since(started).Milliseconds()
		report(100, "All plugins and themes are already up to date")
		return out, nil
	}

	// Mark instance UpdatingFlag = true so Phase 3 Core Shield pauses false-positive alerts during update
	e.setUpdatingFlag(inst.ID, true)
	defer e.setUpdatingFlag(inst.ID, false)

	prober := e.ProbeHealth
	if prober == nil {
		prober = DefaultLoopbackProber
	}

	// STEP 1: Pre-Flight Health Probe + Instant Directory Backup
	report(15, "Running pre-flight HTTP health check & backing up extension directories")
	preHealth := prober(ctx, inst)
	preLogs := capturePreUpdateLogOffsets(guard, verifiedRoot)

	txDir, err := e.createStagingDir(inst.ID)
	if err != nil {
		out.Status = "failed"
		return out, err
	}
	defer func() {
		_ = os.RemoveAll(txDir)
	}()

	var backups []stagedBackupItem
	for _, slug := range pluginTargets {
		bItem, bErr := stageExtensionBackup(guard, verifiedRoot, txDir, "plugin", slug)
		if bErr != nil {
			out.Status = "failed"
			return out, bErr
		}
		backups = append(backups, bItem)
	}
	for _, slug := range themeTargets {
		bItem, bErr := stageExtensionBackup(guard, verifiedRoot, txDir, "theme", slug)
		if bErr != nil {
			out.Status = "failed"
			return out, bErr
		}
		backups = append(backups, bItem)
	}

	// STEP 2: Execute Sandboxed WP-CLI Update + Flush Object/OPcache
	report(50, fmt.Sprintf("Updating %d plugin(s) and %d theme(s) via sandboxed WP-CLI", len(pluginTargets), len(themeTargets)))
	var updateExecErr error
	if len(pluginTargets) > 0 {
		args := append([]string{"plugin", "update"}, pluginTargets...)
		if _, rErr := e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			updateExecErr = fmt.Errorf("wp plugin update failed: %w", rErr)
		} else {
			out.UpdatedPlugins = pluginTargets
		}
	}

	if updateExecErr == nil && len(themeTargets) > 0 {
		args := append([]string{"theme", "update"}, themeTargets...)
		if _, rErr := e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			updateExecErr = fmt.Errorf("wp theme update failed: %w", rErr)
		} else {
			out.UpdatedThemes = themeTargets
		}
	}

	// Best-effort cache flush so new PHP code is evaluated immediately on healthcheck
	_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedRoot,
		PHP:         phpSel,
		Args:        []string{"cache", "flush"},
		SkipPlugins: true,
		SkipThemes:  true,
	})

	// STEP 3: Post-Update Healthcheck & Sub-3s Atomic Auto-Rollback (TC-08)
	report(80, "Verifying live HTTP health & PHP error logs after update")
	faultReason := ""
	var culprits []string

	if updateExecErr != nil {
		faultReason = updateExecErr.Error()
	} else {
		postHealth := prober(ctx, inst)
		logFault, logSlug := inspectNewFatalLogs(guard, verifiedRoot, preLogs)

		if preHealth.Healthy && !postHealth.Healthy {
			faultReason = postHealth.FaultReason
			if postHealth.DetectedSlug != "" {
				culprits = appendUnique(culprits, postHealth.DetectedSlug)
			}
		}
		if logFault != "" {
			if faultReason == "" {
				faultReason = logFault
			} else {
				faultReason = faultReason + "; " + logFault
			}
			if logSlug != "" {
				culprits = appendUnique(culprits, logSlug)
			}
		}
	}

	if faultReason != "" {
		rbStart := time.Now()
		report(90, "Fault detected ("+faultReason+") — executing Smart Auto-Rollback")
		rbErr := restoreStagedBackups(backups, acct.UID, acct.GID)
		out.RollbackMillis = time.Since(rbStart).Milliseconds()
		out.RolledBack = true
		out.Status = "rolled_back"
		out.FaultReason = faultReason

		if len(culprits) == 0 {
			culprits = append(append([]string(nil), pluginTargets...), themeTargets...)
		}
		out.CulpritSlugs = culprits

		if rbErr == nil {
			verifyRecovery := prober(ctx, inst)
			out.RestoredHealthy = verifyRecovery.Healthy
		}

		if e.Store != nil {
			e.Store.RecordSecurityEvent(store.SecurityAuditEvent{
				Severity:   "warning",
				Category:   "smart_rollback",
				Owner:      acct.Username,
				InstanceID: inst.ID,
				Message: fmt.Sprintf(
					"Smart Safe Update auto-rolled back %v on %s in %dms due to: %s",
					out.CulpritSlugs,
					inst.Domain+inst.SubPath,
					out.RollbackMillis,
					faultReason,
				),
			})
		}

		if e.Extensions != nil {
			_, _ = e.Extensions.ScanInstanceVulnerabilities(ctx, acct, inst.ID)
		}
		out.TotalElapsedMs = time.Since(started).Milliseconds()
		report(100, fmt.Sprintf("Auto-rolled back to working version in %dms (%s)", out.RollbackMillis, faultReason))
		return out, nil
	}

	// Healthy update! Refresh extension & CVE counters on InstanceRecord
	if e.Extensions != nil {
		_, _ = e.Extensions.ScanInstanceVulnerabilities(ctx, acct, inst.ID)
	}
	out.Status = "succeeded"
	out.TotalElapsedMs = time.Since(started).Milliseconds()
	report(100, "Smart Safe Update completed and verified healthy (200 OK)")
	return out, nil
}

// RunBulkUpdate executes Smart Safe Update across multiple WordPress instances using bounded concurrency.
func (e *Engine) RunBulkUpdate(
	ctx context.Context,
	resolveOwner func(instanceID string) (dausers.Account, error),
	req BulkRequest,
	report store.ProgressReporter,
) (BulkOutcome, error) {
	if report == nil {
		report = func(int, string) {}
	}

	var ids []string
	seen := make(map[string]struct{}, len(req.InstanceIDs))
	for _, raw := range req.InstanceIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return BulkOutcome{}, errors.New("at least one instance_id is required for bulk update")
	}

	workers := e.MaxBulkWorkers
	if workers <= 0 {
		workers = DefaultBulkConcurrency
	}
	if len(ids) < workers {
		workers = len(ids)
	}

	results := make([]Outcome, len(ids))
	ch := make(chan int, len(ids))
	for i := range ids {
		ch <- i
	}
	close(ch)

	var doneMu sync.Mutex
	completed := 0

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range ch {
				instID := ids[idx]
				acct, oErr := resolveOwner(instID)
				if oErr != nil {
					results[idx] = Outcome{
						InstanceID:  instID,
						Status:      "failed",
						FaultReason: oErr.Error(),
					}
				} else {
					res, uErr := e.UpdateInstance(ctx, acct, Request{
						InstanceID:  instID,
						PluginSlugs: req.PluginSlugs,
						AllPlugins:  req.AllPlugins,
						ThemeSlugs:  req.ThemeSlugs,
						AllThemes:   req.AllThemes,
					}, nil)
					if uErr != nil && res.Status == "" {
						res = Outcome{
							InstanceID:  instID,
							Status:      "failed",
							FaultReason: uErr.Error(),
						}
					}
					results[idx] = res
				}

				doneMu.Lock()
				completed++
				pct := (completed * 100) / len(ids)
				report(pct, fmt.Sprintf("Processed %d/%d WordPress instances", completed, len(ids)))
				doneMu.Unlock()
			}
		}()
	}
	wg.Wait()

	summary := BulkOutcome{
		TotalInstances: len(ids),
		Results:        results,
	}
	for _, r := range results {
		switch r.Status {
		case "succeeded", "noop":
			summary.SucceededCount++
		case "rolled_back":
			summary.RolledBackCount++
		default:
			summary.FailedCount++
		}
	}
	return summary, nil
}

func (e *Engine) resolveTargetSlugs(
	ctx context.Context,
	acct dausers.Account,
	instanceID string,
	verifiedRoot string,
	kind string,
	explicit []string,
	updateAll bool,
) ([]string, error) {
	if !updateAll {
		var cleaned []string
		seen := make(map[string]struct{})
		for _, raw := range explicit {
			for _, part := range strings.Split(raw, ",") {
				s := strings.ToLower(strings.TrimSpace(part))
				if s == "" {
					continue
				}
				if err := config.ValidateIdentifier(s); err != nil {
					return nil, fmt.Errorf("invalid %s slug %q: %w", kind, s, err)
				}
				if _, dup := seen[s]; !dup {
					seen[s] = struct{}{}
					cleaned = append(cleaned, s)
				}
			}
		}
		return cleaned, nil
	}

	// When updateAll is true, query current extensions and select only those with UpdateAvailable == true
	if e.Extensions != nil {
		var items []extensions.ExtensionItem
		var err error
		if kind == "theme" {
			items, err = e.Extensions.ListThemes(ctx, acct, instanceID)
		} else {
			items, err = e.Extensions.ListPlugins(ctx, acct, instanceID)
		}
		if err == nil {
			var outdated []string
			for _, it := range items {
				if it.UpdateAvailable && config.ValidateIdentifier(it.Slug) == nil {
					outdated = append(outdated, it.Slug)
				}
			}
			return outdated, nil
		}
	}

	// Filesystem fallback if extension listing wasn't available
	subFolder := "plugins"
	if kind == "theme" {
		subFolder = "themes"
	}
	entries, _ := os.ReadDir(filepath.Join(verifiedRoot, "wp-content", subFolder))
	var slugs []string
	for _, ent := range entries {
		name := ent.Name()
		if strings.HasPrefix(name, ".") || name == "index.php" {
			continue
		}
		slug := strings.TrimSuffix(name, ".php")
		if config.ValidateIdentifier(slug) == nil {
			slugs = append(slugs, slug)
		}
	}
	return slugs, nil
}

func (e *Engine) createStagingDir(instanceID string) (string, error) {
	if err := os.MkdirAll(e.StagingBaseDir, 0o700); err != nil {
		return "", err
	}
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	dir := filepath.Join(e.StagingBaseDir, instanceID+"_"+hex.EncodeToString(nonce[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func stageExtensionBackup(guard *fsguard.Guard, verifiedRoot, txDir, kind, slug string) (stagedBackupItem, error) {
	subFolder := "plugins"
	if kind == "theme" {
		subFolder = "themes"
	}

	dirCandidate := filepath.Join(verifiedRoot, "wp-content", subFolder, slug)
	if _, err := guard.VerifyChildUnderVerifiedRoot(verifiedRoot, false, "wp-content", subFolder, slug); err == nil {
		if st, sErr := os.Lstat(dirCandidate); sErr == nil && st.IsDir() {
			dst := filepath.Join(txDir, kind, slug)
			if cErr := copyTreeNoSymlinks(dirCandidate, dst); cErr != nil {
				return stagedBackupItem{}, cErr
			}
			return stagedBackupItem{
				kind:       kind,
				slug:       slug,
				livePath:   dirCandidate,
				backupPath: dst,
				isDir:      true,
				existed:    true,
			}, nil
		}
	}

	if kind == "plugin" {
		fileCandidate := filepath.Join(verifiedRoot, "wp-content", "plugins", slug+".php")
		if raw, err := guard.ReadRegularFileUnderVerifiedRoot(verifiedRoot, 16*1024*1024, "wp-content", "plugins", slug+".php"); err == nil {
			dst := filepath.Join(txDir, kind, slug+".php")
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return stagedBackupItem{}, err
			}
			if err := os.WriteFile(dst, raw, 0o644); err != nil {
				return stagedBackupItem{}, err
			}
			return stagedBackupItem{
				kind:       kind,
				slug:       slug,
				livePath:   fileCandidate,
				backupPath: dst,
				isDir:      false,
				existed:    true,
			}, nil
		}
	}

	return stagedBackupItem{
		kind:     kind,
		slug:     slug,
		livePath: dirCandidate,
		existed:  false,
	}, nil
}

func restoreStagedBackups(backups []stagedBackupItem, uid, gid uint32) error {
	var firstErr error
	for _, item := range backups {
		_ = os.RemoveAll(item.livePath)
		if !item.existed {
			continue
		}
		if item.isDir {
			if err := restoreTreeOwned(item.backupPath, item.livePath, uid, gid); err != nil && firstErr == nil {
				firstErr = err
			}
		} else {
			raw, err := os.ReadFile(item.backupPath)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if err := os.WriteFile(item.livePath, raw, 0o644); err != nil && firstErr == nil {
				firstErr = err
			}
			_ = chownItem(item.livePath, uid, gid)
		}
	}
	return firstErr
}

func copyTreeNoSymlinks(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		info, err := in.Stat()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, cErr := io.Copy(out, in)
		_ = out.Close()
		return cErr
	})
}

func restoreTreeOwned(srcDir, dstDir string, uid, gid uint32) error {
	return filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			return chownItem(target, uid, gid)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, _ := d.Info()
		mode := os.FileMode(0o644)
		if info != nil && info.Mode().Perm() != 0 {
			mode = info.Mode().Perm()
		}
		if err := os.WriteFile(target, raw, mode); err != nil {
			return err
		}
		return chownItem(target, uid, gid)
	})
}

func (e *Engine) setUpdatingFlag(instanceID string, flag bool) {
	if e.Store == nil {
		return
	}
	inst, err := e.Store.GetInstance(instanceID)
	if err != nil {
		return
	}
	inst.UpdatingFlag = flag
	_, _ = e.Store.UpsertInstance(inst)
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
