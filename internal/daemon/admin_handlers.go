package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/ipc"
	"github.com/shostwp-byte/da-wptoolkits/internal/updater"
	"github.com/shostwp-byte/da-wptoolkits/internal/version"
)

// PackageSummary represents a DirectAdmin hosting package and its effective policy in Admin Tab 2.
type PackageSummary struct {
	Name         string               `json:"name"`
	HasOverride  bool                 `json:"has_override"`
	AccountCount int                  `json:"account_count"`
	Policy       config.PackagePolicy `json:"policy"`
}

func (s *Service) handlePhase5AdminAction(
	ctx context.Context,
	action string,
	req ipc.Request,
	issuedCSRF string,
) ipc.Response {
	switch action {
	case "list_packages":
		if s.Policies == nil {
			return ipc.Response{OK: false, Code: 503, Error: "policy store is not configured"}
		}
		defPol, err := s.Policies.LoadDefaultPolicy()
		if err != nil {
			return ipc.Response{OK: false, Code: 500, Error: err.Error()}
		}
		pkgSet := make(map[string]struct{})
		acctCounts := make(map[string]int)
		overrideSet := make(map[string]bool)

		for _, name := range s.Policies.ListPackageOverrides() {
			pkgSet[name] = struct{}{}
			overrideSet[name] = true
		}
		if s.Users != nil {
			for _, acct := range s.Users.ListAccounts() {
				p := strings.TrimSpace(acct.Package)
				if p != "" && config.ValidateIdentifier(p) == nil {
					pkgSet[p] = struct{}{}
					acctCounts[p]++
				}
			}
			for _, p := range discoverDirectAdminPackages(s.Users.DADataRoot) {
				pkgSet[p] = struct{}{}
			}
		}

		names := make([]string, 0, len(pkgSet))
		for name := range pkgSet {
			names = append(names, name)
		}
		sort.Strings(names)

		summaries := make([]PackageSummary, 0, len(names))
		for _, name := range names {
			pol, pErr := s.Policies.ResolvePackagePolicy(name)
			if pErr != nil {
				pol = defPol
			}
			summaries = append(summaries, PackageSummary{
				Name:         name,
				HasOverride:  overrideSet[name],
				AccountCount: acctCounts[name],
				Policy:       pol,
			})
		}

		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"default_policy": defPol,
				"packages":       summaries,
			},
		}

	case "save_default_policy":
		if s.Policies == nil {
			return ipc.Response{OK: false, Code: 503, Error: "policy store is not configured"}
		}
		base, _ := s.Policies.LoadDefaultPolicy()
		merged := mergePolicyParams(base, req.Params)
		if err := s.Policies.SaveDefaultPolicy(merged); err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"default_policy": merged}}

	case "save_package_policy":
		if s.Policies == nil {
			return ipc.Response{OK: false, Code: 503, Error: "policy store is not configured"}
		}
		pkgName := paramString(req.Params, "package_name")
		if pkgName == "" {
			return ipc.Response{OK: false, Code: 400, Error: "package_name is required"}
		}
		base, _ := s.Policies.ResolvePackagePolicy(pkgName)
		merged := mergePolicyParams(base, req.Params)
		if err := s.Policies.SavePackagePolicy(pkgName, merged); err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"package_name": pkgName,
				"has_override": true,
				"policy":       merged,
			},
		}

	case "delete_package_policy":
		if s.Policies == nil {
			return ipc.Response{OK: false, Code: 503, Error: "policy store is not configured"}
		}
		pkgName := paramString(req.Params, "package_name")
		if pkgName == "" {
			return ipc.Response{OK: false, Code: 400, Error: "package_name is required"}
		}
		if err := s.Policies.DeletePackagePolicy(pkgName); err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		inherited, _ := s.Policies.ResolvePackagePolicy(pkgName)
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"package_name": pkgName,
				"has_override": false,
				"policy":       inherited,
			},
		}

	case "delete_core_cache":
		if s.Shield == nil {
			return ipc.Response{OK: false, Code: 503, Error: "core integrity shield is not configured"}
		}
		wpVer := paramString(req.Params, "wp_version")
		locale := paramString(req.Params, "locale")
		if err := s.Shield.Cache.DeleteCachedRelease(wpVer, locale); err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"deleted": true,
				"cache":   s.Shield.Cache.Status(),
			},
		}

	case "get_updater_config":
		if s.Policies == nil {
			return ipc.Response{OK: false, Code: 503, Error: "policy store is not configured"}
		}
		cfg, err := s.Policies.LoadUpdaterConfig(version.DefaultGitHubRepo)
		if err != nil {
			return ipc.Response{OK: false, Code: 500, Error: err.Error()}
		}
		var backups []updater.BackupEntry
		var lastOutcome *updater.UpdateOutcome
		if s.Updater != nil {
			backups, _ = s.Updater.ListBackups()
			lastOutcome = s.Updater.LastOutcome()
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"current_version":  version.Version,
				"commit":           version.Commit,
				"build_time":       version.BuildTime,
				"github_repo":      version.DefaultGitHubRepo,
				"public_key_hex":   version.DefaultReleasePublicKeyHex,
				"update_channel":   cfg.UpdateChannel,
				"backup_retention": cfg.BackupRetention,
				"has_github_token": cfg.GitHubToken != "",
				"backups":          backups,
				"last_outcome":     lastOutcome,
			},
		}

	case "save_updater_config":
		if s.Policies == nil {
			return ipc.Response{OK: false, Code: 503, Error: "policy store is not configured"}
		}
		channel := paramString(req.Params, "update_channel")
		retention := paramInt(req.Params, "backup_retention", 0)
		clearToken := paramBool(req.Params, "clear_github_token", false)
		newTokenPtr := paramOptionalString(req.Params, "github_token")
		updateToken := newTokenPtr != nil && *newTokenPtr != ""
		var newToken string
		if newTokenPtr != nil {
			newToken = *newTokenPtr
		}
		saved, err := s.Policies.SaveUpdaterConfig(version.DefaultGitHubRepo, channel, retention, newToken, updateToken, clearToken)
		if err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"github_repo":      version.DefaultGitHubRepo,
				"update_channel":   saved.UpdateChannel,
				"backup_retention": saved.BackupRetention,
				"has_github_token": saved.GitHubToken != "",
			},
		}

	case "check_github_update":
		cfg := s.loadEffectiveUpdaterConfig()
		if s.Updater != nil {
			if strings.TrimSpace(s.GitHubAPIBase) != "" {
				s.Updater.APIBaseURL = s.GitHubAPIBase
			}
			rel, err := s.Updater.CheckLatest(ctx, cfg, paramString(req.Params, "tag"))
			if err != nil {
				return ipc.Response{OK: false, Code: 502, Error: err.Error()}
			}
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: rel}
		}
		relInfo, err := s.queryGitHubLatestRelease(ctx, cfg)
		if err != nil {
			return ipc.Response{OK: false, Code: 502, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: relInfo}

	case "list_update_backups":
		if s.Updater == nil {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"backups": []updater.BackupEntry{}, "last_outcome": nil}}
		}
		backups, err := s.Updater.ListBackups()
		if err != nil {
			return ipc.Response{OK: false, Code: 500, Error: err.Error()}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"backups":      backups,
				"last_outcome": s.Updater.LastOutcome(),
			},
		}

	case "apply_github_update":
		if s.Updater == nil {
			return ipc.Response{OK: false, Code: 503, Error: "self-updater manager is not configured"}
		}
		if strings.TrimSpace(s.GitHubAPIBase) != "" {
			s.Updater.APIBaseURL = s.GitHubAPIBase
		}
		cfg := s.loadEffectiveUpdaterConfig()
		tag := paramString(req.Params, "tag")
		force := paramBool(req.Params, "force", false)
		syncRun := paramBool(req.Params, "sync", false)
		outcome, err := s.Updater.PerformUpdate(ctx, cfg, tag, force, !syncRun)
		if err != nil {
			return ipc.Response{
				OK:        false,
				Code:      500,
				CSRFToken: issuedCSRF,
				Error:     err.Error(),
				Data:      outcome,
			}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: outcome}

	case "rollback_github_update":
		if s.Updater == nil {
			return ipc.Response{OK: false, Code: 503, Error: "self-updater manager is not configured"}
		}
		backupFile := paramString(req.Params, "backup_file")
		syncRun := paramBool(req.Params, "sync", false)
		if !syncRun {
			// Restore files synchronously so errors surface immediately, then schedule restart asynchronously
			bkp, err := s.Updater.RestoreBackup(ctx, backupFile, false)
			if err != nil {
				return ipc.Response{OK: false, Code: 400, CSRFToken: issuedCSRF, Error: err.Error()}
			}
			go func() {
				time.Sleep(350 * time.Millisecond)
				bgCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				if s.Updater.RestartDaemon != nil {
					_ = s.Updater.RestartDaemon(bgCtx)
				}
			}()
			return ipc.Response{
				OK:        true,
				CSRFToken: issuedCSRF,
				Data: map[string]any{
					"restored":   bkp,
					"restarting": true,
				},
			}
		}
		bkp, err := s.Updater.RestoreBackup(ctx, backupFile, true)
		if err != nil {
			return ipc.Response{OK: false, Code: 500, CSRFToken: issuedCSRF, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"restored": bkp, "restarting": false}}

	case "handle_da_hook":
		return s.handleDirectAdminHookEvent(ctx, req, issuedCSRF)
	}

	return ipc.Response{OK: false, Code: 501, Error: "unsupported admin action: " + action}
}

func mergePolicyParams(base config.PackagePolicy, params map[string]any) config.PackagePolicy {
	out := base
	if v := paramOptionalBool(params, "enabled"); v != nil {
		out.Enabled = *v
	}
	if v := paramOptionalInt(params, "max_instances"); v != nil {
		out.MaxInstances = *v
	}
	if v := paramOptionalBool(params, "allow_clone"); v != nil {
		out.AllowClone = *v
	}
	if v := paramOptionalBool(params, "allow_staging_sync"); v != nil {
		out.AllowStagingSync = *v
	}
	if v := paramOptionalBool(params, "allow_core_fortress_lock"); v != nil {
		out.AllowCoreFortressLock = *v
	}
	if v := paramOptionalInt(params, "max_snapshots_per_site"); v != nil {
		out.MaxSnapshotsPerSite = *v
	}
	if v := paramOptionalString(params, "default_core_shield_mode"); v != nil && *v != "" {
		out.DefaultCoreShieldMode = *v
	}
	if v := paramOptionalBool(params, "auto_hardening_on_install"); v != nil {
		out.AutoHardeningOnInstall = *v
	}
	return out
}

func discoverDirectAdminPackages(daDataRoot string) []string {
	if strings.TrimSpace(daDataRoot) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	addFromFile := func(p string) {
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			name := strings.TrimSpace(sc.Text())
			if name != "" && config.ValidateIdentifier(name) == nil {
				seen[name] = struct{}{}
			}
		}
	}

	addFromFile(filepath.Join(daDataRoot, "admin", "packages.list"))
	if matches, err := filepath.Glob(filepath.Join(daDataRoot, "users", "*", "packages.list")); err == nil {
		for _, m := range matches {
			addFromFile(m)
		}
	}

	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type githubReleaseDTO struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
}

func (s *Service) queryGitHubLatestRelease(ctx context.Context, cfg config.UpdaterConfig) (map[string]any, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(s.GitHubAPIBase), "/")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	endpoint := fmt.Sprintf("%s/repos/%s/releases?per_page=10", baseURL, version.DefaultGitHubRepo)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("User-Agent", "DA-WordPressToolkits/"+version.Version)
	if cfg.GitHubToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.GitHubToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GitHub API connection error: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if resp.StatusCode == http.StatusNotFound {
		return map[string]any{
			"current_version":  version.Version,
			"latest_version":   version.Version,
			"update_available": false,
			"update_channel":   cfg.UpdateChannel,
			"changelog":        "Chưa có bản phát hành công khai nào trên kho lưu trữ GitHub.",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var releases []githubReleaseDTO
	if err := json.Unmarshal(raw, &releases); err != nil {
		return nil, fmt.Errorf("invalid GitHub Releases JSON: %w", err)
	}

	var chosen *githubReleaseDTO
	for i := range releases {
		r := &releases[i]
		if r.Draft || strings.TrimSpace(r.TagName) == "" {
			continue
		}
		if r.Prerelease && cfg.UpdateChannel != config.DefaultChannelBeta {
			continue
		}
		chosen = r
		break
	}
	if chosen == nil {
		return map[string]any{
			"current_version":  version.Version,
			"latest_version":   version.Version,
			"update_available": false,
			"update_channel":   cfg.UpdateChannel,
			"changelog":        "Không tìm thấy bản phát hành phù hợp với kênh " + cfg.UpdateChannel + ".",
		}, nil
	}

	isNewer := compareSemVerTags(chosen.TagName, version.Version) > 0
	return map[string]any{
		"current_version":  version.Version,
		"latest_version":   chosen.TagName,
		"release_title":    chosen.Name,
		"prerelease":       chosen.Prerelease,
		"published_at":     chosen.PublishedAt,
		"html_url":         chosen.HTMLURL,
		"changelog":        chosen.Body,
		"update_available": isNewer,
		"update_channel":   cfg.UpdateChannel,
	}, nil
}

func compareSemVerTags(a, b string) int {
	pa, preA := parseSemVerParts(a)
	pb, preB := parseSemVerParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] > pb[i] {
			return 1
		}
		if pa[i] < pb[i] {
			return -1
		}
	}
	if preA == "" && preB != "" {
		return 1
	}
	if preA != "" && preB == "" {
		return -1
	}
	return strings.Compare(preA, preB)
}

func parseSemVerParts(tag string) ([3]int, string) {
	s := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(tag), "v"), "V")
	var pre string
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
	}
	if idx := strings.IndexByte(s, '+'); idx >= 0 {
		s = s[:idx]
	}
	segs := strings.Split(s, ".")
	var nums [3]int
	for i := 0; i < len(segs) && i < 3; i++ {
		nums[i], _ = strconv.Atoi(segs[i])
	}
	return nums, pre
}

func (s *Service) loadEffectiveUpdaterConfig() config.UpdaterConfig {
	cfg := config.UpdaterConfig{
		GitHubRepo:      version.DefaultGitHubRepo,
		UpdateChannel:   config.DefaultChannelStable,
		BackupRetention: config.DefaultBackupRetention,
	}
	if s.Policies != nil {
		if loaded, err := s.Policies.LoadUpdaterConfig(version.DefaultGitHubRepo); err == nil {
			cfg = loaded
		}
	}
	return cfg
}

// handleDirectAdminHookEvent processes all 9 DirectAdmin custom lifecycle hooks idempotently.
func (s *Service) handleDirectAdminHookEvent(ctx context.Context, req ipc.Request, issuedCSRF string) ipc.Response {
	ev := strings.ToLower(strings.TrimSpace(paramString(req.Params, "event")))
	owner := strings.TrimSpace(req.Username)
	if owner == "" {
		owner = strings.TrimSpace(paramString(req.Params, "username"))
	}
	domain := strings.ToLower(strings.TrimSpace(paramString(req.Params, "domain")))
	sub := strings.ToLower(strings.TrimSpace(paramString(req.Params, "subdomain")))

	if s.Users != nil {
		_ = s.Users.Reload()
	}

	switch ev {
	case "domain_create", "subdomain_create":
		if owner == "" {
			return ipc.Response{OK: false, Code: 400, Error: "username is required for " + ev}
		}
		acct, ok := s.Users.LookupByUsername(owner)
		if !ok {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "skipped": "user_not_found"}}
		}
		var discovered int
		if s.Scanner != nil {
			if res, sErr := s.Scanner.ScanAccount(acct, false); sErr == nil {
				discovered = res.DiscoveredTotal
			}
		}
		if s.Shield != nil {
			s.Shield.SyncAllWatches()
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"event":      ev,
				"username":   owner,
				"domain":     domain,
				"subdomain":  sub,
				"discovered": discovered,
			},
		}

	case "domain_destroy":
		if owner == "" || domain == "" {
			return ipc.Response{OK: false, Code: 400, Error: "username and domain are required for domain_destroy"}
		}
		var acct dausers.Account
		if s.Users != nil {
			acct, _ = s.Users.LookupByUsername(owner)
		}
		var removedIDs []string
		for _, inst := range s.Store.ListInstancesByOwner(owner) {
			instDom := strings.ToLower(strings.TrimSpace(inst.Domain))
			if instDom == domain || strings.HasSuffix(instDom, "."+domain) {
				s.cleanupInstanceSecurityArtifacts(ctx, acct, inst)
				if s.Snapshots != nil {
					s.Snapshots.PurgeInstance(acct, inst.ID)
				}
				_ = s.Store.DeleteInstance(inst.ID)
				removedIDs = append(removedIDs, inst.ID)
			}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"event":       ev,
				"username":    owner,
				"domain":      domain,
				"removed_ids": removedIDs,
			},
		}

	case "subdomain_destroy":
		if owner == "" || domain == "" || sub == "" {
			return ipc.Response{OK: false, Code: 400, Error: "username, domain, and subdomain are required for subdomain_destroy"}
		}
		fqdn := sub
		if !strings.HasSuffix(fqdn, "."+domain) {
			fqdn = sub + "." + domain
		}
		var acct dausers.Account
		if s.Users != nil {
			acct, _ = s.Users.LookupByUsername(owner)
		}
		legacyPrefix := ""
		if acct.HomeDir != "" {
			legacyPrefix = filepath.Clean(filepath.Join(acct.HomeDir, "domains", domain, "public_html", sub))
		}
		var removedIDs []string
		for _, inst := range s.Store.ListInstancesByOwner(owner) {
			instDom := strings.ToLower(strings.TrimSpace(inst.Domain))
			cleanDoc := filepath.Clean(inst.DocRoot)
			matchLegacy := legacyPrefix != "" && (cleanDoc == legacyPrefix || strings.HasPrefix(cleanDoc, legacyPrefix+string(os.PathSeparator)))
			if instDom == fqdn || matchLegacy {
				s.cleanupInstanceSecurityArtifacts(ctx, acct, inst)
				if s.Snapshots != nil {
					s.Snapshots.PurgeInstance(acct, inst.ID)
				}
				_ = s.Store.DeleteInstance(inst.ID)
				removedIDs = append(removedIDs, inst.ID)
			}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"event":       ev,
				"username":    owner,
				"subdomain":   fqdn,
				"removed_ids": removedIDs,
			},
		}

	case "user_modify":
		if owner == "" {
			return ipc.Response{OK: false, Code: 400, Error: "username is required for user_modify"}
		}
		acct, ok := s.Users.LookupByUsername(owner)
		if !ok {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "skipped": "user_not_found"}}
		}
		pol := config.DefaultPackagePolicy()
		if s.Policies != nil {
			if p, pErr := s.Policies.ResolvePackagePolicy(acct.Package); pErr == nil {
				pol = p
			}
		}
		var unlockedIDs []string
		if !pol.AllowCoreFortressLock && s.Shield != nil {
			for _, inst := range s.Store.ListInstancesByOwner(owner) {
				if inst.CoreShieldMode == config.ShieldModeFortressLock {
					if _, mErr := s.Shield.SetMode(ctx, acct, inst.ID, config.ShieldModeAutoHeal, false); mErr == nil {
						unlockedIDs = append(unlockedIDs, inst.ID)
					}
				}
			}
		}
		return ipc.Response{
			OK:        true,
			CSRFToken: issuedCSRF,
			Data: map[string]any{
				"event":        ev,
				"username":     owner,
				"package":      acct.Package,
				"suspended":    acct.Suspended,
				"unlocked_ids": unlockedIDs,
			},
		}

	case "user_backup_pre":
		if s.Shield == nil {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"unlocked_ids": []string{}}}
		}
		ids, err := s.Shield.PrepareUserBackup(owner)
		if err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "unlocked_ids": ids}}

	case "user_backup_post":
		if s.Shield == nil {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"relocked_ids": []string{}}}
		}
		ids, err := s.Shield.FinishUserBackup(owner)
		if err != nil {
			return ipc.Response{OK: false, Code: 400, Error: err.Error()}
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "relocked_ids": ids}}

	case "user_restore":
		if owner == "" {
			return ipc.Response{OK: false, Code: 400, Error: "username is required for user_restore"}
		}
		acct, ok := s.Users.LookupByUsername(owner)
		if !ok {
			return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "skipped": "user_not_found"}}
		}
		var res any
		if s.Scanner != nil {
			scanRes, sErr := s.Scanner.ScanAccount(acct, true)
			if sErr != nil {
				return ipc.Response{OK: false, Code: 500, Error: sErr.Error()}
			}
			res = scanRes
		}
		if s.Shield != nil {
			s.Shield.SyncAllWatches()
		}
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "username": owner, "scan": res}}

	case "user_destroy":
		if owner == "" {
			return ipc.Response{OK: false, Code: 400, Error: "username is required for user_destroy"}
		}
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
		return ipc.Response{OK: true, CSRFToken: issuedCSRF, Data: map[string]any{"event": ev, "username": owner, "removed_instances": removed}}

	default:
		return ipc.Response{OK: false, Code: 400, Error: "unknown DirectAdmin hook event: " + ev}
	}
}
