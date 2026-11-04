package daemon

import (
	"context"
	"errors"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/clonesync"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/ipc"
	"github.com/shostwp-byte/da-wptoolkits/internal/quicktools"
	"github.com/shostwp-byte/da-wptoolkits/internal/snapshot"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

func (s *Service) handlePhase4Action(
	ctx context.Context,
	action string,
	req ipc.Request,
	userAcct dausers.Account,
	isAdmin bool,
	issuedCSRF string,
) ipc.Response {
	resolveTarget := func(instID string) (store.InstanceRecord, dausers.Account, error) {
		if isAdmin {
			return s.resolveAdminInstanceAndOwner(instID)
		}
		inst, gErr := s.Store.GetInstanceForOwner(strings.TrimSpace(instID), userAcct.Username)
		if gErr != nil {
			return store.InstanceRecord{}, dausers.Account{}, errors.New("WordPress instance not found")
		}
		return inst, userAcct, nil
	}

	switch action {
	case "get_tools_status":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		st, tErr := s.QuickTools.GetStatus(acct, inst.ID)
		if tErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: tErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: st}

	case "set_search_indexing":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		allow := paramBool(req.Params, "enabled", paramBool(req.Params, "search_indexing", true))
		updated, uErr := s.QuickTools.SetSearchIndexing(ctx, acct, inst.ID, allow)
		if uErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: updated}

	case "set_maintenance_mode":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		cfg, mErr := s.QuickTools.SetMaintenanceMode(ctx, acct, inst.ID, quicktools.MaintenanceConfig{
			Enabled:       paramBool(req.Params, "enabled", false),
			Headline:      paramString(req.Params, "headline"),
			Message:       paramString(req.Params, "message"),
			RetryAfterSec: paramInt(req.Params, "retry_after_sec", 0),
		})
		if mErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: mErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: cfg}

	case "set_debug_config":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		wpDebug := paramBool(req.Params, "wp_debug", paramBool(req.Params, "enabled", false))
		wpDebugLog := paramBool(req.Params, "wp_debug_log", wpDebug)
		wpDebugDisplay := paramBool(req.Params, "wp_debug_display", false)
		dbg, dErr := s.QuickTools.SetDebugConfig(ctx, acct, inst.ID, quicktools.DebugConfig{
			WPDebug:        wpDebug,
			WPDebugLog:     wpDebugLog,
			WPDebugDisplay: wpDebugDisplay,
		})
		if dErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: dbg}

	case "read_debug_log":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		maxBytes := int64(paramInt(req.Params, "max_bytes", 32*1024))
		tail, rErr := s.QuickTools.ReadDebugLog(acct, inst.ID, maxBytes)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: rErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: tail}

	case "clear_debug_log":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		if cErr := s.QuickTools.ClearDebugLog(acct, inst.ID); cErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: cErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"cleared": true}}

	case "set_password_protection":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		pwStatus, pErr := s.QuickTools.SetPasswordProtection(ctx, acct, inst.ID, quicktools.PasswordProtectionRequest{
			Enabled:  paramBool(req.Params, "enabled", false),
			Username: paramString(req.Params, "username"),
			Password: paramString(req.Params, "password"),
			Realm:    paramString(req.Params, "realm"),
		})
		if pErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: pErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: pwStatus}

	case "set_wp_cron":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		disable := paramBool(req.Params, "disable_wp_cron", paramBool(req.Params, "enabled", false))
		interval := paramInt(req.Params, "interval_min", 15)
		updated, cronCmd, cErr := s.QuickTools.SetWPCronTakeover(ctx, acct, inst.ID, disable, interval)
		if cErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: cErr.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"instance":     updated,
				"cron_command": cronCmd,
			},
		}

	case "set_caching":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		updated, cErr := s.QuickTools.SetCaching(ctx, acct, inst.ID, paramBool(req.Params, "enabled", false))
		if cErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: cErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: updated}

	case "clear_cache":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		out, cErr := s.QuickTools.ClearCache(ctx, acct, inst.ID)
		if cErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: cErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: out}

	case "update_site_title":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		updated, tErr := s.QuickTools.UpdateSiteTitle(ctx, acct, inst.ID, paramString(req.Params, "site_title"))
		if tErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: tErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: updated}

	case "manage_admin_account":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		updated, aErr := s.QuickTools.ManageAdminAccount(ctx, acct, inst.ID, quicktools.AdminAccountRequest{
			Operation:   paramString(req.Params, "operation"),
			Username:    paramString(req.Params, "admin_user"),
			Email:       paramString(req.Params, "email"),
			NewPassword: paramString(req.Params, "new_password"),
		})
		if aErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: aErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: updated}

	case "search_replace":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		res, srErr := s.QuickTools.SearchReplace(ctx, acct, inst.ID, quicktools.SearchReplaceRequest{
			Search:  paramString(req.Params, "search"),
			Replace: paramString(req.Params, "replace"),
			DryRun:  paramBool(req.Params, "dry_run", true),
		})
		if srErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: srErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}

	case "db_maintenance":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		op := paramString(req.Params, "operation")
		out, dbErr := s.QuickTools.RunDBMaintenance(ctx, acct, inst.ID, op)
		if dbErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: dbErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"operation": op, "output": out}}

	case "get_safe_wpconfig":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		view, gErr := s.QuickTools.GetSafeWPConfig(acct, inst.ID)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: gErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: view}

	case "update_safe_wpconfig":
		if s.QuickTools == nil {
			return ipc.Response{OK: false, Code: 503, Error: "quick tools manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		view, uErr := s.QuickTools.UpdateSafeWPConfig(acct, inst.ID, quicktools.SafeWPConfigUpdate{
			WPMemoryLimit:      paramOptionalString(req.Params, "wp_memory_limit"),
			WPMaxMemoryLimit:   paramOptionalString(req.Params, "wp_max_memory_limit"),
			WPPostRevisions:    paramOptionalInt(req.Params, "wp_post_revisions"),
			AutosaveInterval:   paramOptionalInt(req.Params, "autosave_interval"),
			EmptyTrashDays:     paramOptionalInt(req.Params, "empty_trash_days"),
			ConcatenateScripts: paramOptionalBool(req.Params, "concatenate_scripts"),
		})
		if uErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: view}

	case "list_snapshots":
		if s.Snapshots == nil {
			return ipc.Response{OK: false, Code: 503, Error: "snapshot manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		list, lErr := s.Snapshots.ListSnapshots(acct, inst.ID)
		if lErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: lErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"snapshots": list}}

	case "create_snapshot":
		if s.Snapshots == nil {
			return ipc.Response{OK: false, Code: 503, Error: "snapshot manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		snapReq := snapshot.CreateRequest{
			InstanceID:  inst.ID,
			Note:        paramString(req.Params, "note"),
			Kind:        paramString(req.Params, "kind"),
			IncludeDB:   paramOptionalBool(req.Params, "include_db"),
			AdminBypass: isAdmin,
		}
		if paramBool(req.Params, "sync", false) || s.Jobs == nil {
			rec, cErr := s.Snapshots.CreateSnapshot(ctx, acct, snapReq, nil)
			if cErr != nil {
				return ipc.Response{OK: false, Code: 400, Error: cErr.Error()}
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rec}
		}
		jobRec, jErr := s.Jobs.Enqueue(
			"snapshot_create",
			acct.Username,
			inst.ID,
			"Creating Zstandard (.tar.zst) snapshot of "+inst.Domain+inst.SubPath,
			func(jobCtx context.Context, report store.ProgressReporter) error {
				_, cErr := s.Snapshots.CreateSnapshot(jobCtx, acct, snapReq, report)
				return cErr
			},
		)
		if jErr != nil {
			return ipc.Response{OK: false, Code: 429, Error: jErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, JobID: jobRec.ID, Data: jobRec}

	case "restore_snapshot":
		if s.Snapshots == nil {
			return ipc.Response{OK: false, Code: 503, Error: "snapshot manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		snapID := paramString(req.Params, "snapshot_id")
		if snapID == "" {
			return ipc.Response{OK: false, Code: 400, Error: "snapshot_id is required"}
		}
		if paramBool(req.Params, "sync", false) || s.Jobs == nil {
			res, rErr := s.Snapshots.RestoreSnapshot(ctx, acct, inst.ID, snapID, nil)
			if rErr != nil {
				return ipc.Response{OK: false, Code: 400, Error: rErr.Error()}
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}
		}
		jobRec, jErr := s.Jobs.Enqueue(
			"snapshot_restore",
			acct.Username,
			inst.ID,
			"Restoring snapshot "+snapID+" on "+inst.Domain+inst.SubPath,
			func(jobCtx context.Context, report store.ProgressReporter) error {
				_, rErr := s.Snapshots.RestoreSnapshot(jobCtx, acct, inst.ID, snapID, report)
				return rErr
			},
		)
		if jErr != nil {
			return ipc.Response{OK: false, Code: 429, Error: jErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, JobID: jobRec.ID, Data: jobRec}

	case "delete_snapshot":
		if s.Snapshots == nil {
			return ipc.Response{OK: false, Code: 503, Error: "snapshot manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		snapID := paramString(req.Params, "snapshot_id")
		if dErr := s.Snapshots.DeleteSnapshot(acct, inst.ID, snapID); dErr != nil {
			if errors.Is(dErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "snapshot not found"}
			}
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"deleted": true}}

	case "get_snapshot_download":
		if s.Snapshots == nil {
			return ipc.Response{OK: false, Code: 503, Error: "snapshot manager is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		snapID := paramString(req.Params, "snapshot_id")
		archivePath, rec, rErr := s.Snapshots.ResolveDownloadPath(acct, inst.ID, snapID)
		if rErr != nil {
			if errors.Is(rErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "snapshot not found"}
			}
			return ipc.Response{OK: false, Code: 400, Error: rErr.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"snapshot":     rec,
				"archive_path": archivePath,
				"file_name":    rec.FileName,
			},
		}

	case "clone_instance":
		if s.CloneSync == nil {
			return ipc.Response{OK: false, Code: 503, Error: "clone/sync engine is not configured"}
		}
		srcID := strings.TrimSpace(req.InstanceID)
		if srcID == "" {
			srcID = paramString(req.Params, "source_instance_id")
		}
		srcInst, acct, err := resolveTarget(srcID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		cloneReq := clonesync.CloneRequest{
			SourceInstanceID:  srcInst.ID,
			TargetDomain:      paramString(req.Params, "target_domain"),
			TargetSubPath:     paramString(req.Params, "target_sub_path"),
			CreateSubdomain:   paramOptionalBool(req.Params, "create_subdomain"),
			EnvironmentTag:    paramString(req.Params, "environment_tag"),
			SetNoIndex:        paramOptionalBool(req.Params, "set_noindex"),
			TargetSiteTitle:   paramString(req.Params, "target_site_title"),
			TargetTablePrefix: paramString(req.Params, "target_table_prefix"),
			Overwrite:         paramBool(req.Params, "overwrite", false),
			AdminBypass:       isAdmin,
		}
		if cloneReq.TargetDomain == "" {
			return ipc.Response{OK: false, Code: 400, Error: "target_domain is required"}
		}
		if paramBool(req.Params, "sync", false) || s.Jobs == nil {
			res, cErr := s.CloneSync.Clone(ctx, acct, cloneReq, nil)
			if cErr != nil {
				return ipc.Response{OK: false, Code: 400, Error: cErr.Error()}
			}
			s.postInstallSecurityHook(ctx, acct, res.Instance.ID)
			if refreshed, gErr := s.Store.GetInstance(res.Instance.ID); gErr == nil {
				res.Instance = refreshed
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}
		}
		jobRec, jErr := s.Jobs.Enqueue(
			"clone",
			acct.Username,
			srcInst.ID,
			"Cloning "+srcInst.Domain+srcInst.SubPath+" -> "+cloneReq.TargetDomain+cloneReq.TargetSubPath,
			func(jobCtx context.Context, report store.ProgressReporter) error {
				res, cErr := s.CloneSync.Clone(jobCtx, acct, cloneReq, report)
				if cErr != nil {
					return cErr
				}
				s.postInstallSecurityHook(jobCtx, acct, res.Instance.ID)
				return nil
			},
		)
		if jErr != nil {
			return ipc.Response{OK: false, Code: 429, Error: jErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, JobID: jobRec.ID, Data: jobRec}

	case "sync_instance":
		if s.CloneSync == nil {
			return ipc.Response{OK: false, Code: 503, Error: "clone/sync engine is not configured"}
		}
		srcID := strings.TrimSpace(req.InstanceID)
		if srcID == "" {
			srcID = paramString(req.Params, "source_instance_id")
		}
		srcInst, acct, err := resolveTarget(srcID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		dstID := paramString(req.Params, "target_instance_id")
		if dstID == "" {
			return ipc.Response{OK: false, Code: 400, Error: "target_instance_id is required"}
		}
		dstInst, _, dstErr := resolveTarget(dstID)
		if dstErr != nil || dstInst.Owner != acct.Username {
			return ipc.Response{OK: false, Code: 404, Error: "target WordPress instance not found on the same account"}
		}
		syncReq := clonesync.SyncRequest{
			SourceInstanceID:    srcInst.ID,
			TargetInstanceID:    dstInst.ID,
			Mode:                paramString(req.Params, "mode"),
			AutoSnapshot:        paramOptionalBool(req.Params, "auto_snapshot"),
			PreserveWooCommerce: paramOptionalBool(req.Params, "preserve_woocommerce"),
			OverwriteUploads:    paramOptionalBool(req.Params, "overwrite_uploads"),
			AdminBypass:         isAdmin,
		}
		if paramBool(req.Params, "sync", false) || s.Jobs == nil {
			res, sErr := s.CloneSync.Sync(ctx, acct, syncReq, nil)
			if sErr != nil {
				return ipc.Response{OK: false, Code: 400, Error: sErr.Error()}
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}
		}
		jobRec, jErr := s.Jobs.Enqueue(
			"staging_sync",
			acct.Username,
			dstInst.ID,
			"Syncing "+srcInst.Domain+srcInst.SubPath+" -> "+dstInst.Domain+dstInst.SubPath,
			func(jobCtx context.Context, report store.ProgressReporter) error {
				_, sErr := s.CloneSync.Sync(jobCtx, acct, syncReq, report)
				return sErr
			},
		)
		if jErr != nil {
			return ipc.Response{OK: false, Code: 429, Error: jErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, JobID: jobRec.ID, Data: jobRec}
	}

	return ipc.Response{OK: false, Code: 501, Error: "unsupported Phase 4 action: " + action}
}

func paramOptionalString(params map[string]any, key string) *string {
	if params == nil {
		return nil
	}
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil
	}
	v := paramString(params, key)
	return &v
}

func paramOptionalInt(params map[string]any, key string) *int {
	if params == nil {
		return nil
	}
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil
	}
	v := paramInt(params, key, 0)
	return &v
}

func paramOptionalBool(params map[string]any, key string) *bool {
	if params == nil {
		return nil
	}
	raw, ok := params[key]
	if !ok || raw == nil {
		return nil
	}
	v := paramBool(params, key, false)
	return &v
}
