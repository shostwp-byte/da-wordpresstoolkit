package smartupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/discovery"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

const (
	defaultCoreVersionCacheTTL = 15 * time.Minute
	coreUpdateCmdTimeout       = 5 * time.Minute
)

var reStrictWPVersion = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}(-[A-Za-z0-9._-]+)?$`)

// CoreCheckItem describes the WordPress Core update readiness of a single instance.
type CoreCheckItem struct {
	InstanceID     string `json:"instance_id"`
	Owner          string `json:"owner"`
	Domain         string `json:"domain"`
	SubPath        string `json:"sub_path,omitempty"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	PHPVersion     string `json:"php_version,omitempty"`
	CoreShieldMode string `json:"core_shield_mode,omitempty"`
	UpToDate       bool   `json:"up_to_date"`
	Action         string `json:"action"` // upgrade | skip | incompatible_php | error
	Reason         string `json:"reason"`
}

// CoreCheckSummary aggregates pre-flight WordPress Core version checks across multiple instances.
type CoreCheckSummary struct {
	LatestVersion     string          `json:"latest_version"`
	MinPHPVersion     string          `json:"min_php_version,omitempty"`
	TotalInstances    int             `json:"total_instances"`
	OutdatedCount     int             `json:"outdated_count"`
	UpToDateCount     int             `json:"up_to_date_count"`
	IncompatibleCount int             `json:"incompatible_count"`
	Items             []CoreCheckItem `json:"items"`
}

// BulkCoreUpdateRequest specifies a sequential WordPress Core update batch.
type BulkCoreUpdateRequest struct {
	InstanceIDs   []string `json:"instance_ids"`
	TargetVersion string   `json:"target_version,omitempty"`
}

// CoreUpdateItemOutcome reports the result of a sequential WordPress Core update on one instance.
type CoreUpdateItemOutcome struct {
	InstanceID string `json:"instance_id"`
	Domain     string `json:"domain"`
	SubPath    string `json:"sub_path,omitempty"`
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	Status     string `json:"status"` // succeeded | skipped | failed
	Detail     string `json:"detail,omitempty"`
	ElapsedMs  int64  `json:"elapsed_ms"`
}

// BulkCoreOutcome summarizes a completed sequential WordPress Core update batch.
type BulkCoreOutcome struct {
	TargetVersion  string                  `json:"target_version"`
	TotalInstances int                     `json:"total_instances"`
	UpdatedCount   int                     `json:"updated_count"`
	SkippedCount   int                     `json:"skipped_count"`
	FailedCount    int                     `json:"failed_count"`
	Results        []CoreUpdateItemOutcome `json:"results"`
}

type wpOrgCoreVersionCheckResp struct {
	Offers []struct {
		Response   string `json:"response"`
		Current    string `json:"current"`
		Version    string `json:"version"`
		PHPVersion string `json:"php_version"`
	} `json:"offers"`
}

// ResolveLatestWPCoreVersion queries WordPress.org for the latest stable WordPress release (cached for 15m).
func (e *Engine) ResolveLatestWPCoreVersion(ctx context.Context, forceRefresh bool) (string, string, error) {
	now := time.Now()
	if !forceRefresh {
		e.coreVerMu.Lock()
		if e.cachedLatestWP != "" && now.Before(e.coreVerExpires) {
			ver, minPHP := e.cachedLatestWP, e.cachedMinPHP
			e.coreVerMu.Unlock()
			return ver, minPHP, nil
		}
		e.coreVerMu.Unlock()
	}

	base := strings.TrimRight(strings.TrimSpace(e.WPOrgAPIBase), "/")
	if base == "" {
		base = "https://api.wordpress.org"
	}
	client := e.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, base+"/core/version-check/1.7/", nil)
	if err != nil {
		return "", "", fmt.Errorf("build wp.org version-check request: %w", err)
	}
	httpReq.Header.Set("User-Agent", "DA-WordPressToolkits/1.0")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", "", fmt.Errorf("query wp.org core version-check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("wp.org core version-check returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", "", fmt.Errorf("read wp.org core version-check body: %w", err)
	}

	var parsed wpOrgCoreVersionCheckResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", "", fmt.Errorf("decode wp.org core version-check json: %w", err)
	}
	if len(parsed.Offers) == 0 {
		return "", "", errors.New("wp.org core version-check returned zero offers")
	}

	chosen := parsed.Offers[0]
	for _, of := range parsed.Offers {
		if of.Response == "upgrade" || of.Response == "latest" {
			chosen = of
			break
		}
	}

	latestVer := strings.TrimSpace(chosen.Current)
	if latestVer == "" {
		latestVer = strings.TrimSpace(chosen.Version)
	}
	if !reStrictWPVersion.MatchString(latestVer) {
		return "", "", fmt.Errorf("invalid latest WordPress version %q from wp.org", latestVer)
	}
	minPHP := strings.TrimSpace(chosen.PHPVersion)

	e.coreVerMu.Lock()
	e.cachedLatestWP = latestVer
	e.cachedMinPHP = minPHP
	e.coreVerExpires = time.Now().Add(defaultCoreVersionCacheTTL)
	e.coreVerMu.Unlock()

	return latestVer, minPHP, nil
}

func (e *Engine) readLiveInstanceWPVersion(acct dausers.Account, inst store.InstanceRecord) (string, string, string, error) {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return inst.WPVersion, inst.Locale, "", err
	}
	verifiedRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return inst.WPVersion, inst.Locale, "", err
	}
	verPath, err := guard.VerifyExistingPath(filepath.Join(verifiedRoot, "wp-includes", "version.php"))
	if err != nil {
		return inst.WPVersion, inst.Locale, verifiedRoot, nil
	}
	raw, err := os.ReadFile(verPath)
	if err != nil {
		return inst.WPVersion, inst.Locale, verifiedRoot, nil
	}
	ver, loc := discovery.ParseVersionPHP(raw)
	if ver == "" {
		ver = inst.WPVersion
	}
	if loc == "" {
		loc = inst.Locale
	}
	if e.Store != nil && ver != "" && (ver != inst.WPVersion || (loc != "" && loc != inst.Locale)) {
		if cur, gErr := e.Store.GetInstance(inst.ID); gErr == nil {
			cur.WPVersion = ver
			if loc != "" && config.ValidateIdentifier(loc) == nil {
				cur.Locale = loc
			}
			_, _ = e.Store.UpsertInstance(cur)
		}
	}
	return ver, loc, verifiedRoot, nil
}

// CheckCoreUpdates inspects the live WordPress Core version of each target instance against WordPress.org.
func (e *Engine) CheckCoreUpdates(
	ctx context.Context,
	resolveOwner func(instanceID string) (dausers.Account, error),
	instanceIDs []string,
	targetVersion string,
	forceRefresh bool,
) (CoreCheckSummary, error) {
	explicitVer := strings.TrimSpace(targetVersion)
	var latestVer, minPHP string
	if explicitVer != "" {
		if !reStrictWPVersion.MatchString(explicitVer) {
			return CoreCheckSummary{}, fmt.Errorf("invalid target_version %q", explicitVer)
		}
		latestVer = explicitVer
	} else {
		var err error
		latestVer, minPHP, err = e.ResolveLatestWPCoreVersion(ctx, forceRefresh)
		if err != nil {
			return CoreCheckSummary{}, err
		}
	}

	ids := dedupeInstanceIDs(instanceIDs)
	summary := CoreCheckSummary{
		LatestVersion:  latestVer,
		MinPHPVersion:  minPHP,
		TotalInstances: len(ids),
		Items:          make([]CoreCheckItem, 0, len(ids)),
	}

	for _, id := range ids {
		acct, err := resolveOwner(id)
		if err != nil {
			summary.Items = append(summary.Items, CoreCheckItem{
				InstanceID:    id,
				LatestVersion: latestVer,
				Action:        "error",
				Reason:        err.Error(),
			})
			continue
		}
		inst, err := e.Store.GetInstanceForOwner(id, acct.Username)
		if err != nil {
			summary.Items = append(summary.Items, CoreCheckItem{
				InstanceID:    id,
				Owner:         acct.Username,
				LatestVersion: latestVer,
				Action:        "error",
				Reason:        err.Error(),
			})
			continue
		}

		curVer, _, _, _ := e.readLiveInstanceWPVersion(acct, inst)
		item := CoreCheckItem{
			InstanceID:     inst.ID,
			Owner:          inst.Owner,
			Domain:         inst.Domain,
			SubPath:        inst.SubPath,
			CurrentVersion: curVer,
			LatestVersion:  latestVer,
			PHPVersion:     inst.PHPVersion,
			CoreShieldMode: inst.CoreShieldMode,
		}

		if curVer != "" && vulndb.CompareVersions(curVer, latestVer) >= 0 {
			item.UpToDate = true
			item.Action = "skip"
			item.Reason = fmt.Sprintf("Đã ở phiên bản mới nhất (WP %s) — Sẽ bỏ qua", curVer)
			summary.UpToDateCount++
		} else if minPHP != "" && inst.PHPVersion != "" && vulndb.CompareVersions(inst.PHPVersion, minPHP) < 0 {
			item.UpToDate = false
			item.Action = "incompatible_php"
			item.Reason = fmt.Sprintf("Cần PHP >= %s (hiện tại PHP %s) — Sẽ bỏ qua", minPHP, inst.PHPVersion)
			summary.IncompatibleCount++
		} else {
			item.UpToDate = false
			item.Action = "upgrade"
			if curVer != "" {
				item.Reason = fmt.Sprintf("Cần nâng cấp WP %s → %s", curVer, latestVer)
			} else {
				item.Reason = fmt.Sprintf("Cần nâng cấp lên WP %s", latestVer)
			}
			summary.OutdatedCount++
		}
		summary.Items = append(summary.Items, item)
	}

	return summary, nil
}

// RunSequentialBulkCoreUpdate updates WordPress Core across multiple instances strictly one-by-one (sequential queue),
// automatically skipping instances that are already on the latest version.
func (e *Engine) RunSequentialBulkCoreUpdate(
	ctx context.Context,
	jobID string,
	resolveOwner func(instanceID string) (dausers.Account, error),
	req BulkCoreUpdateRequest,
	ctrl *store.JobController,
) (BulkCoreOutcome, error) {
	ids := dedupeInstanceIDs(req.InstanceIDs)
	if len(ids) == 0 {
		return BulkCoreOutcome{}, errors.New("at least one instance_id is required")
	}

	explicitVer := strings.TrimSpace(req.TargetVersion)
	var targetVer, minPHP string
	if explicitVer != "" {
		if !reStrictWPVersion.MatchString(explicitVer) {
			return BulkCoreOutcome{}, fmt.Errorf("invalid target_version %q", explicitVer)
		}
		targetVer = explicitVer
	} else {
		var err error
		targetVer, minPHP, err = e.ResolveLatestWPCoreVersion(ctx, true)
		if err != nil {
			return BulkCoreOutcome{}, err
		}
	}

	queueItems := make([]store.JobItemResult, len(ids))
	for i, id := range ids {
		dom := id
		if e.Store != nil {
			if inst, gErr := e.Store.GetInstance(id); gErr == nil {
				dom = inst.Domain + inst.SubPath
			}
		}
		queueItems[i] = store.JobItemResult{
			InstanceID: id,
			Domain:     dom,
			Status:     store.JobStatusQueued,
			Detail:     "Đang chờ đến lượt trong hàng đợi tuần tự",
		}
	}
	if ctrl != nil {
		ctrl.SetItems(queueItems)
		ctrl.Report(2, fmt.Sprintf("Bắt đầu hàng đợi tuần tự %d site (mục tiêu WP %s)...", len(ids), targetVer))
	}

	outcome := BulkCoreOutcome{
		TargetVersion:  targetVer,
		TotalInstances: len(ids),
		Results:        make([]CoreUpdateItemOutcome, 0, len(ids)),
	}

	for idx, instID := range ids {
		if err := ctx.Err(); err != nil {
			return outcome, err
		}

		res := e.runSingleSequentialCoreStep(ctx, jobID, idx, len(ids), instID, targetVer, explicitVer, minPHP, resolveOwner, ctrl)
		outcome.Results = append(outcome.Results, res)
		switch res.Status {
		case "succeeded":
			outcome.UpdatedCount++
		case "skipped":
			outcome.SkippedCount++
		default:
			outcome.FailedCount++
		}

		doneCount := idx + 1
		pct := (doneCount * 100) / len(ids)
		if pct < 5 && doneCount < len(ids) {
			pct = 5
		}
		if ctrl != nil {
			ctrl.SetSummary(fmt.Sprintf(
				"Đã xử lý %d/%d site (WP %s): nâng cấp %d, bỏ qua %d (đã mới nhất), lỗi %d",
				doneCount, len(ids), targetVer, outcome.UpdatedCount, outcome.SkippedCount, outcome.FailedCount,
			))
			if doneCount < len(ids) {
				ctrl.Report(pct, fmt.Sprintf("Đã xong [%d/%d] %s — chuẩn bị site tiếp theo...", doneCount, len(ids), res.Domain+res.SubPath))
			} else {
				ctrl.Report(100, fmt.Sprintf(
					"Hoàn tất hàng đợi cập nhật WP %s (%d nâng cấp, %d bỏ qua, %d lỗi)",
					targetVer, outcome.UpdatedCount, outcome.SkippedCount, outcome.FailedCount,
				))
			}
		}

		// Brief breather only after an actual WP-CLI upgrade so disk/CPU stays calm on large servers
		if res.Status == "succeeded" && doneCount < len(ids) {
			select {
			case <-ctx.Done():
				return outcome, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	return outcome, nil
}

func (e *Engine) runSingleSequentialCoreStep(
	ctx context.Context,
	jobID string,
	idx int,
	total int,
	instID string,
	targetVer string,
	explicitVer string,
	minPHP string,
	resolveOwner func(instanceID string) (dausers.Account, error),
	ctrl *store.JobController,
) CoreUpdateItemOutcome {
	started := time.Now()

	// Enforce server-wide sequential execution (concurrency = 1) across all core update batches
	if ctrl != nil {
		ctrl.UpdateItem(idx, store.JobStatusRunning, "Đang kiểm tra phiên bản hiện tại...")
	}
	e.coreUpdateSeqMu.Lock()
	defer e.coreUpdateSeqMu.Unlock()

	acct, err := resolveOwner(instID)
	if err != nil {
		detail := "Không xác thực được chủ sở hữu: " + err.Error()
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusFailed, detail)
		}
		return CoreUpdateItemOutcome{
			InstanceID: instID,
			Domain:     instID,
			Status:     "failed",
			Detail:     detail,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	inst, err := e.Store.GetInstanceForOwner(instID, acct.Username)
	if err != nil {
		detail := "Không tìm thấy instance: " + err.Error()
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusFailed, detail)
		}
		return CoreUpdateItemOutcome{
			InstanceID: instID,
			Domain:     instID,
			Status:     "failed",
			Detail:     detail,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	fullDom := inst.Domain + inst.SubPath
	beforeVer, beforeLoc, verifiedRoot, vErr := e.readLiveInstanceWPVersion(acct, inst)
	if vErr != nil || verifiedRoot == "" {
		msg := "Đường dẫn mã nguồn không hợp lệ"
		if vErr != nil {
			msg += ": " + vErr.Error()
		}
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusFailed, msg)
		}
		return CoreUpdateItemOutcome{
			InstanceID: inst.ID,
			Domain:     inst.Domain,
			SubPath:    inst.SubPath,
			OldVersion: beforeVer,
			Status:     "failed",
			Detail:     msg,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	// Fast-skip without spawning PHP/WP-CLI when already at or above latest version
	if beforeVer != "" && vulndb.CompareVersions(beforeVer, targetVer) >= 0 {
		detail := fmt.Sprintf("Đã ở bản mới nhất (WP %s) — Bỏ qua", beforeVer)
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusSkipped, detail)
		}
		return CoreUpdateItemOutcome{
			InstanceID: inst.ID,
			Domain:     inst.Domain,
			SubPath:    inst.SubPath,
			OldVersion: beforeVer,
			NewVersion: beforeVer,
			Status:     "skipped",
			Detail:     detail,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	// Guard against incompatible PHP version before touching core files
	if minPHP != "" && inst.PHPVersion != "" && vulndb.CompareVersions(inst.PHPVersion, minPHP) < 0 {
		detail := fmt.Sprintf("Bỏ qua: PHP %s thấp hơn yêu cầu tối thiểu PHP %s của WP %s", inst.PHPVersion, minPHP, targetVer)
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusSkipped, detail)
		}
		return CoreUpdateItemOutcome{
			InstanceID: inst.ID,
			Domain:     inst.Domain,
			SubPath:    inst.SubPath,
			OldVersion: beforeVer,
			NewVersion: beforeVer,
			Status:     "skipped",
			Detail:     detail,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	if e.TryLockInstance != nil && jobID != "" {
		if !e.TryLockInstance(inst.ID, jobID) {
			detail := "Site đang bận bởi một tác vụ khác — Bỏ qua"
			if ctrl != nil {
				ctrl.UpdateItem(idx, store.JobStatusFailed, detail)
			}
			return CoreUpdateItemOutcome{
				InstanceID: inst.ID,
				Domain:     inst.Domain,
				SubPath:    inst.SubPath,
				OldVersion: beforeVer,
				NewVersion: beforeVer,
				Status:     "failed",
				Detail:     detail,
				ElapsedMs:  time.Since(started).Milliseconds(),
			}
		}
		if e.UnlockInstance != nil {
			defer e.UnlockInstance(inst.ID, jobID)
		}
	}

	stepPct := (idx * 100) / total
	if stepPct < 5 {
		stepPct = 5
	}
	if ctrl != nil {
		ctrl.Report(stepPct, fmt.Sprintf("Đang cập nhật [%d/%d] %s (WP %s → %s)...", idx+1, total, fullDom, beforeVer, targetVer))
		ctrl.UpdateItem(idx, store.JobStatusRunning, fmt.Sprintf("Đang nâng cấp WP %s → %s...", beforeVer, targetVer))
	}

	var phpSel daphp.Selection
	if e.Domains != nil {
		if tgt, fErr := e.Domains.FindTarget(acct, inst.Domain); fErr == nil {
			phpSel = tgt.PHP
		}
	}

	e.setUpdatingFlag(inst.ID, true)
	defer e.setUpdatingFlag(inst.ID, false)

	var afterVer, afterLoc string
	var wasNoopUpToDate bool

	execErr := e.runWithShield(acct, inst, func() error {
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"transient", "delete", "update_core"},
			SkipPlugins: true,
			SkipThemes:  true,
			Timeout:     15 * time.Second,
		})

		updateArgs := []string{"core", "update"}
		if explicitVer != "" {
			updateArgs = append(updateArgs, "--version="+explicitVer)
		}
		res, uErr := e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        updateArgs,
			SkipPlugins: true,
			SkipThemes:  true,
			Timeout:     coreUpdateCmdTimeout,
		})
		if uErr != nil {
			return fmt.Errorf("wp core update failed: %w", uErr)
		}

		afterVer, afterLoc, _, _ = e.readLiveInstanceWPVersion(acct, inst)
		if afterVer == "" {
			afterVer = targetVer
		}
		if afterLoc == "" {
			afterLoc = beforeLoc
		}

		if afterVer == beforeVer && strings.Contains(strings.ToLower(res), "up to date") {
			wasNoopUpToDate = true
			return nil
		}

		// Apply WordPress database schema migrations & flush object cache
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"core", "update-db"},
			SkipPlugins: true,
			SkipThemes:  true,
			Timeout:     60 * time.Second,
		})
		_, _ = e.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"cache", "flush"},
			SkipPlugins: true,
			SkipThemes:  true,
			Timeout:     15 * time.Second,
		})

		updatedInst := inst
		if e.Store != nil {
			if latest, gErr := e.Store.GetInstance(inst.ID); gErr == nil {
				latest.WPVersion = afterVer
				if afterLoc != "" && config.ValidateIdentifier(afterLoc) == nil {
					latest.Locale = afterLoc
				}
				latest.CoreIntegrityClean = true
				latest.UpdatingFlag = false
				if saved, sErr := e.Store.UpsertInstance(latest); sErr == nil {
					updatedInst = saved
				}
			}
		}
		if e.OnCoreUpdated != nil {
			e.OnCoreUpdated(ctx, acct, updatedInst)
		}
		return nil
	})

	if execErr != nil {
		detail := execErr.Error()
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusFailed, detail)
		}
		return CoreUpdateItemOutcome{
			InstanceID: inst.ID,
			Domain:     inst.Domain,
			SubPath:    inst.SubPath,
			OldVersion: beforeVer,
			NewVersion: beforeVer,
			Status:     "failed",
			Detail:     detail,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	if wasNoopUpToDate {
		detail := fmt.Sprintf("Đã ở bản mới nhất (WP %s) — Bỏ qua", afterVer)
		if ctrl != nil {
			ctrl.UpdateItem(idx, store.JobStatusSkipped, detail)
		}
		return CoreUpdateItemOutcome{
			InstanceID: inst.ID,
			Domain:     inst.Domain,
			SubPath:    inst.SubPath,
			OldVersion: beforeVer,
			NewVersion: afterVer,
			Status:     "skipped",
			Detail:     detail,
			ElapsedMs:  time.Since(started).Milliseconds(),
		}
	}

	if e.Store != nil {
		e.Store.RecordSecurityEvent(store.SecurityAuditEvent{
			Severity:   "info",
			Category:   "core_update",
			Owner:      acct.Username,
			InstanceID: inst.ID,
			Message:    fmt.Sprintf("WordPress Core updated from %s to %s on %s", beforeVer, afterVer, fullDom),
		})
	}

	detail := fmt.Sprintf("Đã nâng cấp WP %s → %s", beforeVer, afterVer)
	if ctrl != nil {
		ctrl.UpdateItem(idx, store.JobStatusSucceeded, detail)
	}
	return CoreUpdateItemOutcome{
		InstanceID: inst.ID,
		Domain:     inst.Domain,
		SubPath:    inst.SubPath,
		OldVersion: beforeVer,
		NewVersion: afterVer,
		Status:     "succeeded",
		Detail:     detail,
		ElapsedMs:  time.Since(started).Milliseconds(),
	}
}

func dedupeInstanceIDs(rawIDs []string) []string {
	var ids []string
	seen := make(map[string]struct{}, len(rawIDs))
	for _, raw := range rawIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}
