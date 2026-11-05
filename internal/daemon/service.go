package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/auth"
	"github.com/shostwp-byte/da-wptoolkits/internal/clonesync"
	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
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
)

// Service coordinates authentication, domain discovery, WP-CLI lifecycle, extensions, Smart Safe Update, CVE scanning, WebServer hardening, Core Integrity Shield, Quick Tools, Snapshots, Clone/Sync, Self-Updater, and IPC routing.
type Service struct {
	StartedAt     time.Time
	Store         *store.Store
	Jobs          *store.JobManager
	Policies      *config.PolicyStore
	Users         *dausers.Registry
	Guard         *auth.Guard
	Domains       *dadomains.Resolver
	Scanner       *discovery.Scanner
	Lifecycle     *lifecycle.Manager
	Vulns         *vulndb.DB
	Extensions    *extensions.Manager
	SmartUpdate   *smartupdate.Engine
	WebServer     *webserver.Adapter
	Hardening     *hardening.Engine
	Shield        *integrity.Shield
	QuickTools    *quicktools.Manager
	Snapshots     *snapshot.Manager
	CloneSync     *clonesync.Engine
	Updater       *updater.Manager
	GitHubAPIBase string
}

func NewService(
	st *store.Store,
	jm *store.JobManager,
	pol *config.PolicyStore,
	users *dausers.Registry,
	guard *auth.Guard,
) *Service {
	return &Service{
		StartedAt: time.Now(),
		Store:     st,
		Jobs:      jm,
		Policies:  pol,
		Users:     users,
		Guard:     guard,
	}
}

// AuthorizeSocketPeer implements ipc.PeerAuthorizer to block web-shells and unauthorized UIDs pre-decode.
func (s *Service) AuthorizeSocketPeer(cred auth.PeerCred, isAdminSocket bool) error {
	return s.Guard.AuthorizeSocketPeer(cred, isAdminSocket)
}

// HandleAdminRequest processes Admin Socket commands (CLI root commands, DA Hooks, and Admin Evolution UI).
func (s *Service) HandleAdminRequest(ctx context.Context, cred auth.PeerCred, req ipc.Request) ipc.Response {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		return ipc.Response{OK: false, Code: 400, Error: "missing action parameter"}
	}

	if action == "ping" && cred.UID == 0 {
		return ipc.Response{
			OK:   true,
			Data: s.buildPingData(),
		}
	}

	mutating := auth.IsMutatingAction(action)
	caller, err := s.Guard.AuthenticateAdminRequest(cred, req.SessionID, req.CSRFToken, mutating)
	if err != nil {
		return ipc.Response{OK: false, Code: 403, Error: err.Error()}
	}

	var issuedCSRF string
	if !caller.IsRootCLI && caller.SessionIDHash != "" {
		issuedCSRF, _ = s.Guard.IssueCSRFToken(cred.UID, caller.Username, caller.SessionIDHash)
	}

	switch action {
	case "ping":
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: s.buildPingData()}

	case "get_overview":
		allSites := s.Store.ListAllInstances(false)
		vulnSites := 0
		uncleanSites := 0
		for _, inst := range allSites {
			if inst.VulnCount > 0 {
				vulnSites++
			}
			if !inst.CoreIntegrityClean {
				uncleanSites++
			}
		}
		defPol, _ := s.Policies.LoadDefaultPolicy()
		var vStatus any
		if s.Vulns != nil {
			vStatus = s.Vulns.Status()
		}
		var cacheStatus any
		var activeWatches, maxWatches int
		if s.Shield != nil {
			cacheStatus = s.Shield.Cache.Status()
			activeWatches, maxWatches = s.Shield.WatchStats()
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"ping":                   s.buildPingData(),
				"hosting_accounts":       len(s.Users.ListAccounts()),
				"managed_sites":          len(allSites),
				"vulnerable_sites":       vulnSites,
				"core_attention_sites":   uncleanSites,
				"inotify_watches":        activeWatches,
				"inotify_max_budget":     maxWatches,
				"default_policy":         defPol,
				"vulndb":                 vStatus,
				"core_cache":             cacheStatus,
				"recent_security_events": s.Store.RecentSecurityEvents(20),
			},
		}

	case "list_instances":
		var list []store.InstanceRecord
		if strings.TrimSpace(req.Username) != "" {
			list = s.Store.ListInstancesByOwner(strings.TrimSpace(req.Username))
		} else {
			list = s.Store.ListAllInstances(false)
		}
		if paramBool(req.Params, "vuln_only", false) {
			filtered := make([]store.InstanceRecord, 0, len(list))
			for _, it := range list {
				if it.VulnCount > 0 {
					filtered = append(filtered, it)
				}
			}
			list = filtered
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"instances": list}}

	case "scan_instances":
		if s.Scanner == nil {
			return ipc.Response{OK: false, Code: 503, Error: "discovery scanner is not configured"}
		}
		if s.Users != nil {
			_ = s.Users.Reload()
		}
		reattach := paramBool(req.Params, "reattach", false)
		targetUser := strings.TrimSpace(req.Username)
		if targetUser != "" {
			acct, ok := s.Users.LookupByUsername(targetUser)
			if !ok {
				return ipc.Response{OK: false, Code: 404, Error: fmt.Sprintf("DirectAdmin user %q not found", targetUser)}
			}
			res, sErr := s.Scanner.ScanAccount(acct, reattach)
			if sErr != nil {
				return ipc.Response{OK: false, Code: 500, Error: sErr.Error()}
			}
			if s.Shield != nil {
				s.Shield.ReconcileAllOwnership()
				s.Shield.SyncAllWatches()
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}
		}

		var combined discovery.ScanResult
		for _, acct := range s.Users.ListAccounts() {
			r, sErr := s.Scanner.ScanAccount(acct, reattach)
			if sErr != nil {
				continue
			}
			combined.ScannedTargets += r.ScannedTargets
			combined.DiscoveredTotal += r.DiscoveredTotal
			combined.AddedCount += r.AddedCount
			combined.UpdatedCount += r.UpdatedCount
			combined.Instances = append(combined.Instances, r.Instances...)
		}
		if s.Shield != nil {
			s.Shield.ReconcileAllOwnership()
			s.Shield.SyncAllWatches()
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: combined}

	case "install_instance":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		targetUser := strings.TrimSpace(req.Username)
		acct, ok := s.Users.LookupByUsername(targetUser)
		if !ok {
			return ipc.Response{OK: false, Code: 404, Error: fmt.Sprintf("DirectAdmin user %q not found", targetUser)}
		}
		return s.dispatchInstall(ctx, acct, req.Params, issuedCSRF)

	case "uninstall_instance":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		inst, acct, rErr := s.resolveAdminInstanceAndOwner(req.InstanceID)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: rErr.Error()}
		}
		s.cleanupInstanceSecurityArtifacts(ctx, acct, inst)
		if s.Snapshots != nil && paramBool(req.Params, "purge_snapshots", true) {
			s.Snapshots.PurgeInstance(acct, inst.ID)
		}
		dropDB := paramBool(req.Params, "drop_db", false)
		if uErr := s.Lifecycle.Uninstall(ctx, acct, inst.ID, dropDB); uErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"uninstalled_id": inst.ID}}

	case "detach_instance":
		inst, gErr := s.Store.GetInstance(strings.TrimSpace(req.InstanceID))
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		if acct, ok := s.Users.LookupByUsername(inst.Owner); ok {
			s.cleanupInstanceSecurityArtifacts(ctx, acct, inst)
		}
		inst.Detached = true
		if _, uErr := s.Store.UpsertInstance(inst); uErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"detached_id": inst.ID}}

	case "sso_login":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		inst, acct, rErr := s.resolveAdminInstanceAndOwner(req.InstanceID)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: rErr.Error()}
		}
		if s.Shield != nil {
			s.Shield.ReconcileInstanceOwnership(acct, inst)
		}
		ssoRes, sErr := s.Lifecycle.CreateEphemeralSSO(acct, inst, paramString(req.Params, "admin_user"))
		if sErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: sErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: ssoRes}

	case "get_vulndb_status":
		if s.Vulns == nil {
			return ipc.Response{OK: false, Code: 503, Error: "vulnerability intelligence DB is not configured"}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: s.Vulns.Status()}

	case "sync_vulndb":
		if s.Vulns == nil {
			return ipc.Response{OK: false, Code: 503, Error: "vulnerability intelligence DB is not configured"}
		}
		st, sErr := s.Vulns.Sync(ctx, paramString(req.Params, "source"))
		if sErr != nil {
			return ipc.Response{OK: false, Code: 502, Error: sErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: st}

	case "list_plugins", "list_themes":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		inst, acct, rErr := s.resolveAdminInstanceAndOwner(req.InstanceID)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: rErr.Error()}
		}
		forceRefresh := paramBool(req.Params, "force_refresh", false)
		if action == "list_themes" {
			items, lErr := s.Extensions.ListThemesWithOptions(ctx, acct, inst.ID, forceRefresh)
			if lErr != nil {
				return ipc.Response{OK: false, Code: 500, Error: lErr.Error()}
			}
			updatedInst, _ := s.Store.GetInstance(inst.ID)
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"themes": items, "instance": updatedInst}}
		}
		items, lErr := s.Extensions.ListPluginsWithOptions(ctx, acct, inst.ID, forceRefresh)
		if lErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: lErr.Error()}
		}
		updatedInst, _ := s.Store.GetInstance(inst.ID)
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"plugins": items, "instance": updatedInst}}

	case "manage_plugin", "manage_theme":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		inst, acct, rErr := s.resolveAdminInstanceAndOwner(req.InstanceID)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: rErr.Error()}
		}
		return s.dispatchExtensionAction(ctx, acct, inst.ID, action == "manage_theme", req.Params, issuedCSRF)

	case "get_vulns":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		inst, acct, rErr := s.resolveAdminInstanceAndOwner(req.InstanceID)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: rErr.Error()}
		}
		rep, vErr := s.Extensions.ScanInstanceVulnerabilities(ctx, acct, inst.ID)
		if vErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: vErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rep}

	case "smart_update":
		if s.SmartUpdate == nil {
			return ipc.Response{OK: false, Code: 503, Error: "smart update engine is not configured"}
		}
		inst, acct, rErr := s.resolveAdminInstanceAndOwner(req.InstanceID)
		if rErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: rErr.Error()}
		}
		return s.dispatchSmartUpdate(ctx, acct, inst, req.Params, issuedCSRF)

	case "bulk_smart_update":
		if s.SmartUpdate == nil {
			return ipc.Response{OK: false, Code: 503, Error: "smart update engine is not configured"}
		}
		ownerName := strings.TrimSpace(req.Username)
		if ownerName == "" {
			ownerName = "admin"
		}
		return s.dispatchBulkSmartUpdate(
			ctx,
			ownerName,
			func(instID string) (dausers.Account, error) {
				_, acct, rErr := s.resolveAdminInstanceAndOwner(instID)
				return acct, rErr
			},
			req.Params,
			issuedCSRF,
		)

	case "list_sets":
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"sets": s.Store.ListSetsForOwner(strings.TrimSpace(req.Username))}}

	case "save_set":
		ps, uErr := s.Store.UpsertSet(parsePluginSetParams(req.Params), "", true)
		if uErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: ps}

	case "delete_set":
		if dErr := s.Store.DeleteSet(paramString(req.Params, "set_id"), "", true); dErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"deleted": true}}

	case "list_jobs":
		jobs := s.Jobs.ListJobs(strings.TrimSpace(req.Username), true, req.Limit)
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"jobs": jobs}}

	case "get_job":
		job, jErr := s.Jobs.GetJobForOwner(strings.TrimSpace(req.JobID), "", true)
		if jErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: jErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: job}

	case "get_security_events":
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data:      map[string]any{"events": s.Store.RecentSecurityEvents(req.Limit)},
		}

	case "get_core_cache_status":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		activeW, maxW := s.Shield.WatchStats()
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"cache":              s.Shield.Cache.Status(),
				"inotify_watches":    activeW,
				"inotify_max_budget": maxW,
			},
		}

	case "seed_core_cache":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		wpVer := paramString(req.Params, "wp_version")
		locale := paramString(req.Params, "locale")
		m, cErr := s.Shield.Cache.EnsureVerifiedCore(ctx, wpVer, locale)
		if cErr != nil {
			return ipc.Response{OK: false, Code: 502, Error: cErr.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"version":    m.Version,
				"locale":     m.Locale,
				"file_count": len(m.Files),
			},
		}

	case "get_security_status",
		"verify_core",
		"set_shield_mode",
		"lock_core",
		"unlock_core",
		"apply_hardening",
		"revert_hardening",
		"list_quarantine",
		"get_quarantine_diff",
		"restore_quarantine",
		"delete_quarantine",
		"list_whitelist",
		"manage_whitelist":
		return s.handleSecurityAction(ctx, action, req, dausers.Account{}, true, issuedCSRF)

	case "backup_pre_unlock":
		if s.Shield == nil {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"unlocked_ids": []string{}}}
		}
		ids, bErr := s.Shield.PrepareUserBackup(strings.TrimSpace(req.Username))
		if bErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: bErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"unlocked_ids": ids}}

	case "backup_post_relock":
		if s.Shield == nil {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"relocked_ids": []string{}}}
		}
		ids, bErr := s.Shield.FinishUserBackup(strings.TrimSpace(req.Username))
		if bErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: bErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"relocked_ids": ids}}

	case "cleanup_owner":
		owner := strings.TrimSpace(req.Username)
		if s.Shield != nil {
			s.Shield.CleanupOwner(owner)
		}
		if s.WebServer != nil {
			_ = s.WebServer.RemoveOwnerConfigs(ctx, owner)
		}
		if s.Snapshots != nil {
			s.Snapshots.PurgeOwner(owner)
		}
		removed, dErr := s.Store.DeleteInstancesByOwner(owner)
		if dErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		if s.Users != nil {
			_ = s.Users.Reload()
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"removed_instances": removed}}

	case "get_tools_status",
		"set_search_indexing",
		"set_maintenance_mode",
		"set_debug_config",
		"read_debug_log",
		"clear_debug_log",
		"set_password_protection",
		"set_wp_cron",
		"set_caching",
		"clear_cache",
		"update_site_title",
		"manage_admin_account",
		"search_replace",
		"db_maintenance",
		"get_safe_wpconfig",
		"update_safe_wpconfig",
		"list_snapshots",
		"create_snapshot",
		"restore_snapshot",
		"delete_snapshot",
		"get_snapshot_download",
		"clone_instance",
		"sync_instance":
		return s.handlePhase4Action(ctx, action, req, dausers.Account{}, true, issuedCSRF)

	case "list_packages",
		"save_default_policy",
		"save_package_policy",
		"delete_package_policy",
		"delete_core_cache",
		"get_updater_config",
		"save_updater_config",
		"check_github_update",
		"list_update_backups",
		"apply_github_update",
		"rollback_github_update",
		"handle_da_hook":
		return s.handlePhase5AdminAction(ctx, action, req, issuedCSRF)

	default:
		return ipc.Response{
			OK:    false,
			Code:  501,
			Error: "action not yet implemented in current daemon phase: " + action,
		}
	}
}

// HandleUserRequest processes End-User Socket commands with strict per-UID and DA-session tenant isolation.
func (s *Service) HandleUserRequest(ctx context.Context, cred auth.PeerCred, req ipc.Request) ipc.Response {
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		return ipc.Response{OK: false, Code: 400, Error: "missing action parameter"}
	}

	mutating := auth.IsMutatingAction(action)
	caller, err := s.Guard.AuthenticateUserRequest(cred, strings.TrimSpace(req.Username), req.SessionID, req.CSRFToken, mutating)
	if err != nil {
		return ipc.Response{OK: false, Code: 403, Error: err.Error()}
	}

	var issuedCSRF string
	if !caller.IsRootCLI && caller.SessionIDHash != "" {
		issuedCSRF, _ = s.Guard.IssueCSRFToken(cred.UID, caller.Username, caller.SessionIDHash)
	}

	switch action {
	case "ping":
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"version":  version.Version,
				"username": caller.Username,
			},
		}

	case "get_bootstrap":
		pol, _ := s.Policies.ResolvePackagePolicy(caller.Account.Package)
		instances := s.Store.ListInstancesByOwner(caller.Username)
		sets := s.Store.ListSetsForOwner(caller.Username)
		jobs := s.Jobs.ListJobs(caller.Username, false, 15)
		var domains []dadomains.DomainTarget
		if s.Domains != nil && caller.Account.HomeDir != "" {
			domains, _ = s.Domains.ListTargets(caller.Account)
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"version":   version.Version,
				"username":  caller.Username,
				"package":   caller.Account.Package,
				"policy":    pol,
				"domains":   domains,
				"instances": instances,
				"sets":      sets,
				"jobs":      jobs,
			},
		}

	case "list_domains":
		if s.Domains == nil {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"domains": []dadomains.DomainTarget{}}}
		}
		list, dErr := s.Domains.ListTargets(caller.Account)
		if dErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"domains": list}}

	case "list_instances":
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data:      map[string]any{"instances": s.Store.ListInstancesByOwner(caller.Username)},
		}

	case "get_instance":
		inst, gErr := s.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), caller.Username)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: inst}

	case "scan_instances":
		if s.Scanner == nil {
			return ipc.Response{OK: false, Code: 503, Error: "discovery scanner is not configured"}
		}
		res, sErr := s.Scanner.ScanAccount(caller.Account, paramBool(req.Params, "reattach", true))
		if sErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: sErr.Error()}
		}
		if s.Shield != nil {
			s.Shield.ReconcileAllOwnership()
			s.Shield.SyncAllWatches()
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}

	case "install_instance":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		return s.dispatchInstall(ctx, caller.Account, req.Params, issuedCSRF)

	case "uninstall_instance":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		inst, gErr := s.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), caller.Username)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		s.cleanupInstanceSecurityArtifacts(ctx, caller.Account, inst)
		if s.Snapshots != nil && paramBool(req.Params, "purge_snapshots", true) {
			s.Snapshots.PurgeInstance(caller.Account, inst.ID)
		}
		dropDB := paramBool(req.Params, "drop_db", false)
		if uErr := s.Lifecycle.Uninstall(ctx, caller.Account, inst.ID, dropDB); uErr != nil {
			if errors.Is(uErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
			return ipc.Response{OK: false, Code: 500, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"uninstalled_id": inst.ID}}

	case "sso_login":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		inst, gErr := s.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), caller.Username)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		if s.Shield != nil {
			s.Shield.ReconcileInstanceOwnership(caller.Account, inst)
		}
		ssoRes, sErr := s.Lifecycle.CreateEphemeralSSO(caller.Account, inst, paramString(req.Params, "admin_user"))
		if sErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: sErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: ssoRes}

	case "reset_admin_password":
		if s.Lifecycle == nil {
			return ipc.Response{OK: false, Code: 503, Error: "lifecycle manager is not configured"}
		}
		rErr := s.Lifecycle.ResetAdminPassword(
			ctx,
			caller.Account,
			strings.TrimSpace(req.InstanceID),
			paramString(req.Params, "admin_user"),
			paramString(req.Params, "new_password"),
		)
		if rErr != nil {
			if errors.Is(rErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
			return ipc.Response{OK: false, Code: 400, Error: rErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"updated": true}}

	case "list_plugins":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		instID := strings.TrimSpace(req.InstanceID)
		forceRefresh := paramBool(req.Params, "force_refresh", false)
		items, lErr := s.Extensions.ListPluginsWithOptions(ctx, caller.Account, instID, forceRefresh)
		if lErr != nil {
			if errors.Is(lErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
			return ipc.Response{OK: false, Code: 500, Error: lErr.Error()}
		}
		updatedInst, _ := s.Store.GetInstanceForOwner(instID, caller.Username)
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"plugins": items, "instance": updatedInst}}

	case "list_themes":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		instID := strings.TrimSpace(req.InstanceID)
		forceRefresh := paramBool(req.Params, "force_refresh", false)
		items, lErr := s.Extensions.ListThemesWithOptions(ctx, caller.Account, instID, forceRefresh)
		if lErr != nil {
			if errors.Is(lErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
			return ipc.Response{OK: false, Code: 500, Error: lErr.Error()}
		}
		updatedInst, _ := s.Store.GetInstanceForOwner(instID, caller.Username)
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"themes": items, "instance": updatedInst}}

	case "list_all_plugins":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		forceRefresh := paramBool(req.Params, "force_refresh", false)
		groups, aErr := s.Extensions.AggregateAccountExtensionsWithOptions(ctx, caller.Account, false, forceRefresh)
		if aErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: aErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"plugins": groups, "instances": s.Store.ListInstancesByOwner(caller.Username)}}

	case "list_all_themes":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		forceRefresh := paramBool(req.Params, "force_refresh", false)
		groups, aErr := s.Extensions.AggregateAccountExtensionsWithOptions(ctx, caller.Account, true, forceRefresh)
		if aErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: aErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"themes": groups, "instances": s.Store.ListInstancesByOwner(caller.Username)}}

	case "search_wporg":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		kind := paramString(req.Params, "kind")
		query := paramString(req.Params, "search")
		page := paramInt(req.Params, "page", 1)
		perPage := paramInt(req.Params, "per_page", 12)
		items, sErr := s.Extensions.SearchWPOrg(ctx, kind, query, page, perPage)
		if sErr != nil {
			return ipc.Response{OK: false, Code: 502, Error: sErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"items": items}}

	case "get_vulns":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		rep, vErr := s.Extensions.ScanInstanceVulnerabilities(ctx, caller.Account, strings.TrimSpace(req.InstanceID))
		if vErr != nil {
			if errors.Is(vErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
			return ipc.Response{OK: false, Code: 500, Error: vErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rep}

	case "manage_plugin", "manage_theme":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		return s.dispatchExtensionAction(ctx, caller.Account, strings.TrimSpace(req.InstanceID), action == "manage_theme", req.Params, issuedCSRF)

	case "smart_update":
		if s.SmartUpdate == nil {
			return ipc.Response{OK: false, Code: 503, Error: "smart update engine is not configured"}
		}
		inst, gErr := s.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), caller.Username)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		return s.dispatchSmartUpdate(ctx, caller.Account, inst, req.Params, issuedCSRF)

	case "bulk_smart_update":
		if s.SmartUpdate == nil {
			return ipc.Response{OK: false, Code: 503, Error: "smart update engine is not configured"}
		}
		return s.dispatchBulkSmartUpdate(
			ctx,
			caller.Username,
			func(instID string) (dausers.Account, error) {
				if _, gErr := s.Store.GetInstanceForOwner(instID, caller.Username); gErr != nil {
					return dausers.Account{}, errors.New("WordPress instance not found or access denied")
				}
				return caller.Account, nil
			},
			req.Params,
			issuedCSRF,
		)

	case "list_sets":
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data:      map[string]any{"sets": s.Store.ListSetsForOwner(caller.Username)},
		}

	case "save_set":
		ps, uErr := s.Store.UpsertSet(parsePluginSetParams(req.Params), caller.Username, false)
		if uErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: ps}

	case "delete_set":
		if dErr := s.Store.DeleteSet(paramString(req.Params, "set_id"), caller.Username, false); dErr != nil {
			if errors.Is(dErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "set not found"}
			}
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"deleted": true}}

	case "apply_set":
		if s.Extensions == nil {
			return ipc.Response{OK: false, Code: 503, Error: "extensions manager is not configured"}
		}
		setID := paramString(req.Params, "set_id")
		if err := s.Extensions.ApplySet(ctx, caller.Account, strings.TrimSpace(req.InstanceID), setID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "instance or set not found"}
			}
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"applied": true, "set_id": setID}}

	case "list_jobs":
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data:      map[string]any{"jobs": s.Jobs.ListJobs(caller.Username, false, req.Limit)},
		}

	case "get_job":
		job, jErr := s.Jobs.GetJobForOwner(strings.TrimSpace(req.JobID), caller.Username, false)
		if jErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "job not found"}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: job}

	case "detach_instance":
		inst, gErr := s.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), caller.Username)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		s.cleanupInstanceSecurityArtifacts(ctx, caller.Account, inst)
		inst.Detached = true
		if _, uErr := s.Store.UpsertInstance(inst); uErr != nil {
			if errors.Is(uErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
			return ipc.Response{OK: false, Code: 500, Error: uErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"detached_id": inst.ID}}

	case "get_security_status",
		"verify_core",
		"set_shield_mode",
		"lock_core",
		"unlock_core",
		"apply_hardening",
		"revert_hardening",
		"list_quarantine",
		"get_quarantine_diff",
		"restore_quarantine",
		"delete_quarantine",
		"list_whitelist",
		"manage_whitelist":
		return s.handleSecurityAction(ctx, action, req, caller.Account, false, issuedCSRF)

	case "get_tools_status",
		"set_search_indexing",
		"set_maintenance_mode",
		"set_debug_config",
		"read_debug_log",
		"clear_debug_log",
		"set_password_protection",
		"set_wp_cron",
		"set_caching",
		"clear_cache",
		"update_site_title",
		"manage_admin_account",
		"search_replace",
		"db_maintenance",
		"get_safe_wpconfig",
		"update_safe_wpconfig",
		"list_snapshots",
		"create_snapshot",
		"restore_snapshot",
		"delete_snapshot",
		"get_snapshot_download",
		"clone_instance",
		"sync_instance":
		return s.handlePhase4Action(ctx, action, req, caller.Account, false, issuedCSRF)

	default:
		return ipc.Response{
			OK:    false,
			Code:  501,
			Error: "action not yet implemented in current daemon phase: " + action,
		}
	}
}

func (s *Service) resolveAdminInstanceAndOwner(instanceID string) (store.InstanceRecord, dausers.Account, error) {
	inst, err := s.Store.GetInstance(strings.TrimSpace(instanceID))
	if err != nil {
		return store.InstanceRecord{}, dausers.Account{}, errors.New("WordPress instance not found")
	}
	acct, ok := s.Users.LookupByUsername(inst.Owner)
	if !ok {
		return store.InstanceRecord{}, dausers.Account{}, errors.New("instance owner account not found")
	}
	return inst, acct, nil
}

func (s *Service) dispatchExtensionAction(
	ctx context.Context,
	acct dausers.Account,
	instanceID string,
	isTheme bool,
	params map[string]any,
	issuedCSRF string,
) ipc.Response {
	actReq := extensions.ActionRequest{
		Operation: paramString(params, "operation"),
		Slug:      paramString(params, "slug"),
		Slugs:     paramStringSlice(params, "slugs"),
		Version:   paramString(params, "version"),
		Activate:  paramBool(params, "activate", false),
		ZipPath:   paramString(params, "zip_path"),
		ZipBase64: paramString(params, "zip_base64"),
	}

	var items []extensions.ExtensionItem
	var err error
	if isTheme {
		items, err = s.Extensions.ManageTheme(ctx, acct, instanceID, actReq)
	} else {
		items, err = s.Extensions.ManagePlugin(ctx, acct, instanceID, actReq)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
		}
		return ipc.Response{OK: false, Code: 400, Error: err.Error()}
	}
	key := "plugins"
	if isTheme {
		key = "themes"
	}
	updatedInst, _ := s.Store.GetInstance(instanceID)
	return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{key: items, "instance": updatedInst}}
}

func (s *Service) dispatchSmartUpdate(
	ctx context.Context,
	acct dausers.Account,
	inst store.InstanceRecord,
	params map[string]any,
	issuedCSRF string,
) ipc.Response {
	updReq := smartupdate.Request{
		InstanceID:  inst.ID,
		PluginSlugs: paramStringSlice(params, "plugin_slugs"),
		AllPlugins:  paramBool(params, "all_plugins", false),
		ThemeSlugs:  paramStringSlice(params, "theme_slugs"),
		AllThemes:   paramBool(params, "all_themes", false),
	}

	if paramBool(params, "sync", false) || s.Jobs == nil {
		outcome, err := s.SmartUpdate.UpdateInstance(ctx, acct, updReq, nil)
		if err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: outcome}
	}

	jobRec, err := s.Jobs.Enqueue(
		"smart_update",
		acct.Username,
		inst.ID,
		"Running Smart Safe Update on "+inst.Domain+inst.SubPath,
		func(jobCtx context.Context, report store.ProgressReporter) error {
			outcome, uErr := s.SmartUpdate.UpdateInstance(jobCtx, acct, updReq, report)
			if uErr != nil {
				return uErr
			}
			if outcome.RolledBack {
				// Signal rolled_back status clearly in job message without crashing job runner
				report(100, fmt.Sprintf("Auto-rolled back %v (%s)", outcome.CulpritSlugs, outcome.FaultReason))
			}
			return nil
		},
	)
	if err != nil {
		return ipc.Response{OK: false, Code: 429, Error: err.Error()}
	}
	return ipc.Response{
		OK:        true,
		CSRFToken: issuedCSRF,
		JobID:     jobRec.ID,
		Data:      jobRec,
	}
}

func (s *Service) dispatchBulkSmartUpdate(
	ctx context.Context,
	jobOwner string,
	resolveOwner func(instanceID string) (dausers.Account, error),
	params map[string]any,
	issuedCSRF string,
) ipc.Response {
	bulkReq := smartupdate.BulkRequest{
		InstanceIDs: paramStringSlice(params, "instance_ids"),
		PluginSlugs: paramStringSlice(params, "plugin_slugs"),
		AllPlugins:  paramBool(params, "all_plugins", false),
		ThemeSlugs:  paramStringSlice(params, "theme_slugs"),
		AllThemes:   paramBool(params, "all_themes", false),
	}
	if len(bulkReq.InstanceIDs) == 0 {
		return ipc.Response{OK: false, Code: 400, Error: "instance_ids is required"}
	}

	if paramBool(params, "sync", false) || s.Jobs == nil {
		out, err := s.SmartUpdate.RunBulkUpdate(ctx, resolveOwner, bulkReq, nil)
		if err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: out}
	}

	jobRec, err := s.Jobs.Enqueue(
		"bulk_smart_update",
		jobOwner,
		"",
		fmt.Sprintf("Running Bulk Smart Safe Update across %d site(s)", len(bulkReq.InstanceIDs)),
		func(jobCtx context.Context, report store.ProgressReporter) error {
			_, bErr := s.SmartUpdate.RunBulkUpdate(jobCtx, resolveOwner, bulkReq, report)
			return bErr
		},
	)
	if err != nil {
		return ipc.Response{OK: false, Code: 429, Error: err.Error()}
	}
	return ipc.Response{
		OK:        true,
		CSRFToken: issuedCSRF,
		JobID:     jobRec.ID,
		Data:      jobRec,
	}
}

func (s *Service) dispatchInstall(ctx context.Context, acct dausers.Account, params map[string]any, issuedCSRF string) ipc.Response {
	instReq := lifecycle.InstallRequest{
		Domain:        paramString(params, "domain"),
		SubPath:       paramString(params, "sub_path"),
		SiteTitle:     paramString(params, "site_title"),
		WPVersion:     paramString(params, "wp_version"),
		Locale:        paramString(params, "locale"),
		AdminUser:     paramString(params, "admin_user"),
		AdminPassword: paramString(params, "admin_password"),
		AdminEmail:    paramString(params, "admin_email"),
		TablePrefix:   paramString(params, "table_prefix"),
		SetID:         paramString(params, "set_id"),
	}

	if paramBool(params, "sync", false) || s.Jobs == nil {
		res, err := s.Lifecycle.Install(ctx, acct, instReq, nil)
		if err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		s.postInstallSecurityHook(ctx, acct, res.Instance.ID)
		if refreshed, gErr := s.Store.GetInstance(res.Instance.ID); gErr == nil {
			res.Instance = refreshed
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: res}
	}

	preparedReq, oneTimePassword, prepErr := s.Lifecycle.PrepareInstallRequest(acct, instReq)
	if prepErr != nil {
		return ipc.Response{OK: false, Code: 400, Error: prepErr.Error()}
	}

	jobRec, err := s.Jobs.Enqueue(
		"install",
		acct.Username,
		"",
		"Preparing WordPress installation on "+preparedReq.Domain+preparedReq.SubPath,
		func(jobCtx context.Context, report store.ProgressReporter) error {
			res, iErr := s.Lifecycle.Install(jobCtx, acct, preparedReq, report)
			if iErr != nil {
				return iErr
			}
			s.postInstallSecurityHook(jobCtx, acct, res.Instance.ID)
			return nil
		},
	)
	if err != nil {
		return ipc.Response{OK: false, Code: 429, Error: err.Error()}
	}
	payload := map[string]any{
		"job":        jobRec,
		"admin_user": preparedReq.AdminUser,
	}
	if oneTimePassword != "" {
		payload["generated_password"] = oneTimePassword
	}
	return ipc.Response{
		OK:        true,
		CSRFToken: issuedCSRF,
		JobID:     jobRec.ID,
		Data:      payload,
	}
}

func (s *Service) buildPingData() ipc.PingData {
	var watches int
	if s.Shield != nil {
		watches, _ = s.Shield.WatchStats()
	}
	var wsKind string
	if s.WebServer != nil {
		wsKind = string(s.WebServer.DetectKind())
	}
	return ipc.PingData{
		Service:         "da-wptoolkitd",
		Version:         version.Version,
		ProtocolVersion: ipc.ProtocolVersion,
		UptimeSeconds:   int64(time.Since(s.StartedAt).Seconds()),
		ManagedSites:    len(s.Store.ListAllInstances(false)),
		InotifyWatches:  watches,
		WebServer:       wsKind,
	}
}

func (s *Service) cleanupInstanceSecurityArtifacts(ctx context.Context, acct dausers.Account, inst store.InstanceRecord) {
	if s.QuickTools != nil {
		s.QuickTools.CleanupInstance(ctx, acct, inst)
	}
	if s.Shield != nil {
		s.Shield.CleanupInstance(acct, inst)
	}
	if s.WebServer != nil {
		_ = s.WebServer.RemoveInstanceConfigs(ctx, inst.Owner, inst.ID)
	}
}

func (s *Service) postInstallSecurityHook(ctx context.Context, acct dausers.Account, instanceID string) {
	inst, err := s.Store.GetInstance(instanceID)
	if err != nil {
		return
	}
	pol := config.DefaultPackagePolicy()
	if s.Policies != nil {
		if resolved, pErr := s.Policies.ResolvePackagePolicy(acct.Package); pErr == nil {
			pol = resolved
		}
	}
	if pol.AutoHardeningOnInstall && s.Hardening != nil {
		_, _ = s.Hardening.Apply(ctx, acct, instanceID, hardening.ApplyRequest{
			Preset: hardening.PresetCritical,
		})
	}
	if s.Shield != nil {
		if latest, gErr := s.Store.GetInstance(instanceID); gErr == nil {
			s.Shield.ReconcileInstanceOwnership(acct, latest)
			s.Shield.SyncInstanceWatch(latest)
		} else {
			s.Shield.ReconcileInstanceOwnership(acct, inst)
			s.Shield.SyncInstanceWatch(inst)
		}
	}
}

func (s *Service) handleSecurityAction(
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
	case "get_security_status":
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		var rep hardening.Report
		if s.Hardening != nil {
			r, hErr := s.Hardening.Check(acct, inst.ID)
			if hErr == nil {
				rep = r
			}
		}
		var qCount int
		var wl []string
		if s.Shield != nil {
			qCount = len(s.Shield.Quarantine.List(inst.Owner, inst.ID, isAdmin, false))
			wl = s.Shield.Quarantine.ListWhitelist(inst.ID)
		}
		if refreshed, gErr := s.Store.GetInstance(inst.ID); gErr == nil {
			inst = refreshed
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"instance_id":          inst.ID,
				"core_shield_mode":     inst.CoreShieldMode,
				"core_integrity_clean": inst.CoreIntegrityClean,
				"security_score":       inst.SecurityScore,
				"security_total":       inst.SecurityTotal,
				"web_server":           rep.WebServer,
				"rules":                rep.Rules,
				"quarantine_count":     qCount,
				"whitelist":            wl,
			},
		}

	case "verify_core":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		heal := paramBool(req.Params, "heal", true)
		if isAdmin && paramBool(req.Params, "all", false) {
			var reports []integrity.VerifyReport
			for _, inst := range s.Store.ListAllInstances(false) {
				acct, ok := s.Users.LookupByUsername(inst.Owner)
				if !ok {
					continue
				}
				r, vErr := s.Shield.VerifyAndHealInstance(ctx, acct, inst.ID, heal)
				if vErr == nil {
					reports = append(reports, r)
				}
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"reports": reports}}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		rep, vErr := s.Shield.VerifyAndHealInstance(ctx, acct, inst.ID, heal)
		if vErr != nil {
			return ipc.Response{OK: false, Code: 500, Error: vErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rep}

	case "set_shield_mode", "lock_core", "unlock_core":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		targetMode := paramString(req.Params, "mode")
		if action == "lock_core" {
			targetMode = config.ShieldModeFortressLock
		} else if action == "unlock_core" {
			if targetMode == "" {
				targetMode = config.ShieldModeAutoHeal
			}
		}
		updated, sErr := s.Shield.SetMode(ctx, acct, inst.ID, targetMode, !isAdmin)
		if sErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: sErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: updated}

	case "apply_hardening":
		if s.Hardening == nil {
			return ipc.Response{OK: false, Code: 503, Error: "security hardening engine is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		rep, aErr := s.Hardening.Apply(ctx, acct, inst.ID, hardening.ApplyRequest{
			Preset:         paramString(req.Params, "preset"),
			RuleIDs:        paramStringSlice(req.Params, "rule_ids"),
			NewAdminUser:   paramString(req.Params, "new_admin_user"),
			NewTablePrefix: paramString(req.Params, "new_table_prefix"),
		})
		if aErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: aErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rep}

	case "revert_hardening":
		if s.Hardening == nil {
			return ipc.Response{OK: false, Code: 503, Error: "security hardening engine is not configured"}
		}
		inst, acct, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		rep, rErr := s.Hardening.Revert(ctx, acct, inst.ID, paramStringSlice(req.Params, "rule_ids"))
		if rErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: rErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rep}

	case "list_quarantine":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		ownerFilter := userAcct.Username
		if isAdmin {
			ownerFilter = strings.TrimSpace(req.Username)
		}
		instID := strings.TrimSpace(req.InstanceID)
		if instID != "" && !isAdmin {
			if _, err := s.Store.GetInstanceForOwner(instID, userAcct.Username); err != nil {
				return ipc.Response{OK: false, Code: 404, Error: "WordPress instance not found"}
			}
		}
		items := s.Shield.Quarantine.List(ownerFilter, instID, isAdmin, paramBool(req.Params, "include_diff", false))
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"items": items}}

	case "get_quarantine_diff":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		qID := paramString(req.Params, "quarantine_id")
		it, gErr := s.Shield.Quarantine.GetItem(qID, userAcct.Username, isAdmin)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "quarantine item not found"}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: it}

	case "restore_quarantine":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		qID := paramString(req.Params, "quarantine_id")
		it, gErr := s.Shield.Quarantine.GetItem(qID, userAcct.Username, isAdmin)
		if gErr != nil {
			return ipc.Response{OK: false, Code: 404, Error: "quarantine item not found"}
		}
		inst, acct, err := resolveTarget(it.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		whitelist := paramBool(req.Params, "whitelist", true)
		var restored integrity.QuarantineItem
		rErr := s.Shield.WithUpdatingSuppression(acct, inst, func() error {
			var innerErr error
			restored, innerErr = s.Shield.Quarantine.RestoreItem(acct, inst, qID, whitelist, isAdmin)
			return innerErr
		})
		if rErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: rErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: restored}

	case "delete_quarantine":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		qID := paramString(req.Params, "quarantine_id")
		if dErr := s.Shield.Quarantine.DeleteItem(qID, userAcct.Username, isAdmin); dErr != nil {
			if errors.Is(dErr, store.ErrNotFound) {
				return ipc.Response{OK: false, Code: 404, Error: "quarantine item not found"}
			}
			return ipc.Response{OK: false, Code: 400, Error: dErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"deleted": true}}

	case "list_whitelist":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		inst, _, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"whitelist": s.Shield.Quarantine.ListWhitelist(inst.ID)}}

	case "manage_whitelist":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		inst, _, err := resolveTarget(req.InstanceID)
		if err != nil {
			return ipc.Response{OK: false, Code: 404, Error: err.Error()}
		}
		op := strings.ToLower(paramString(req.Params, "operation"))
		relPath := paramString(req.Params, "path")
		var wErr error
		switch op {
		case "add":
			wErr = s.Shield.Quarantine.AddWhitelist(inst.ID, relPath)
		case "remove", "delete":
			wErr = s.Shield.Quarantine.RemoveWhitelist(inst.ID, relPath)
		default:
			return ipc.Response{OK: false, Code: 400, Error: "operation must be add or remove"}
		}
		if wErr != nil {
			return ipc.Response{OK: false, Code: 400, Error: wErr.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"whitelist": s.Shield.Quarantine.ListWhitelist(inst.ID)}}
	}

	return ipc.Response{OK: false, Code: 501, Error: "unsupported security action: " + action}
}

func parsePluginSetParams(params map[string]any) store.PluginSet {
	return store.PluginSet{
		ID:          paramString(params, "id"),
		Name:        paramString(params, "name"),
		Description: paramString(params, "description"),
		Plugins:     paramStringSlice(params, "plugins"),
		Themes:      paramStringSlice(params, "themes"),
		ActiveTheme: paramString(params, "active_theme"),
	}
}

func paramString(params map[string]any, key string) string {
	if params == nil {
		return ""
	}
	v, ok := params[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func paramInt(params map[string]any, key string, fallback int) int {
	if params == nil {
		return fallback
	}
	v, ok := params[key]
	if !ok || v == nil {
		return fallback
	}
	switch val := v.(type) {
	case int:
		return val
	case float64:
		return int(val)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return n
		}
	}
	return fallback
}

func paramStringSlice(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	v, ok := params[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if item != nil {
				s := strings.TrimSpace(fmt.Sprintf("%v", item))
				if s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case string:
		var out []string
		for _, p := range strings.Split(val, ",") {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func paramBool(params map[string]any, key string, fallback bool) bool {
	if params == nil {
		return fallback
	}
	v, ok := params[key]
	if !ok || v == nil {
		return fallback
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return fallback
}
