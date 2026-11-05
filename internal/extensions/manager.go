package extensions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

// ExtensionItem describes a single installed WordPress plugin or theme enriched with CVE intelligence.
type ExtensionItem struct {
	Slug            string               `json:"slug"`
	Title           string               `json:"title"`
	Status          string               `json:"status"` // active | inactive | must-use | dropin | parent
	Version         string               `json:"version"`
	UpdateAvailable bool                 `json:"update_available"`
	UpdateVersion   string               `json:"update_version,omitempty"`
	AutoUpdate      bool                 `json:"auto_update"`
	Author          string               `json:"author,omitempty"`
	Vulns           []vulndb.MatchedVuln `json:"vulns,omitempty"`
}

// SiteExtensionRef links an aggregated plugin/theme to a specific WordPress instance owned by the user.
type SiteExtensionRef struct {
	InstanceID      string `json:"instance_id"`
	Domain          string `json:"domain"`
	SubPath         string `json:"sub_path,omitempty"`
	SiteTitle       string `json:"site_title"`
	Status          string `json:"status"`
	Version         string `json:"version"`
	UpdateAvailable bool   `json:"update_available"`
	UpdateVersion   string `json:"update_version,omitempty"`
	AutoUpdate      bool   `json:"auto_update"`
	VulnCount       int    `json:"vuln_count"`
}

// GlobalExtensionGroup powers the cross-site Global Tabs ("Plugins (N)" and "Themes (N)").
type GlobalExtensionGroup struct {
	Slug            string               `json:"slug"`
	Title           string               `json:"title"`
	TotalSites      int                  `json:"total_sites"`
	ActiveSites     int                  `json:"active_sites"`
	OutdatedSites   int                  `json:"outdated_sites"`
	VulnerableSites int                  `json:"vulnerable_sites"`
	LatestAvailable string               `json:"latest_available,omitempty"`
	Vulns           []vulndb.MatchedVuln `json:"vulns,omitempty"`
	Sites           []SiteExtensionRef   `json:"sites"`
}

// InstanceVulnReport summarizes all CVEs affecting a WordPress instance's Core, Plugins, and Themes.
type InstanceVulnReport struct {
	InstanceID     string               `json:"instance_id"`
	Domain         string               `json:"domain"`
	SubPath        string               `json:"sub_path,omitempty"`
	WPVersion      string               `json:"wp_version"`
	TotalVulns     int                  `json:"total_vulns"`
	CriticalOrHigh int                  `json:"critical_or_high"`
	CoreVulns      []vulndb.MatchedVuln `json:"core_vulns,omitempty"`
	Plugins        []ExtensionItem      `json:"vulnerable_plugins,omitempty"`
	Themes         []ExtensionItem      `json:"vulnerable_themes,omitempty"`
}

// ActionRequest defines a WSOD-safe mutation on a plugin or theme.
type ActionRequest struct {
	Operation string   `json:"operation"` // activate | deactivate | delete | autoupdate_on | autoupdate_off | install_slug | install_zip
	Slugs     []string `json:"slugs,omitempty"`
	Slug      string   `json:"slug,omitempty"`
	Version   string   `json:"version,omitempty"`
	Activate  bool     `json:"activate"`
	ZipPath   string   `json:"zip_path,omitempty"`
	ZipBase64 string   `json:"zip_base64,omitempty"`
}

type instanceExtUpdateCounts struct {
	pluginUpdates int
	themeUpdates  int
	hasPlugins    bool
	hasThemes     bool
}

// Manager coordinates plugin/theme listing, WSOD rescue toggles, WP.org search, .zip installs, sets, and CVE scans.
type Manager struct {
	Domains         *dadomains.Resolver
	WPCLI           *wpcli.Runner
	Store           *store.Store
	Vulns           *vulndb.DB
	WPOrgAPIBase    string
	HTTPClient      *http.Client
	LiveUpdateCheck bool

	cacheMu      sync.RWMutex
	versionCache map[string]wpOrgVersionCacheEntry

	countsMu  sync.Mutex
	extCounts map[string]instanceExtUpdateCounts
}

func NewManager(
	domains *dadomains.Resolver,
	wp *wpcli.Runner,
	st *store.Store,
	vulns *vulndb.DB,
) *Manager {
	return &Manager{
		Domains:      domains,
		WPCLI:        wp,
		Store:        st,
		Vulns:        vulns,
		WPOrgAPIBase: DefaultWPOrgAPIBase,
		versionCache: make(map[string]wpOrgVersionCacheEntry),
		extCounts:    make(map[string]instanceExtUpdateCounts),
	}
}

// flexString unmarshals WP-CLI JSON fields that may be emitted as string, bool (`false` when commercial plugins
// populate `new_version => false`), number, null, or nested metadata without failing the entire array decode.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		*f = ""
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	if trimmed == "true" || trimmed == "false" {
		*f = flexString(trimmed)
		return nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		*f = ""
		return nil
	}
	*f = flexString(trimmed)
	return nil
}

type wpcliExtRow struct {
	Name          flexString `json:"name"`
	Title         flexString `json:"title"`
	Status        flexString `json:"status"`
	Update        flexString `json:"update"`
	Version       flexString `json:"version"`
	UpdateVersion flexString `json:"update_version"`
	AutoUpdate    flexString `json:"auto_update"`
	AutoUpdates   flexString `json:"auto_updates"`
	Author        flexString `json:"author"`
}

// ListPlugins lists all plugins of an instance (using --skip-plugins --skip-themes so WSOD sites still work!),
// enriches them with static titles, WordPress.org latest versions & Wordfence CVEs, and refreshes Store counters.
func (m *Manager) ListPlugins(ctx context.Context, acct dausers.Account, instanceID string) ([]ExtensionItem, error) {
	return m.ListPluginsWithOptions(ctx, acct, instanceID, false)
}

// ListPluginsWithOptions lists all plugins of an instance and optionally forces a live transient + WordPress.org refresh.
func (m *Manager) ListPluginsWithOptions(ctx context.Context, acct dausers.Account, instanceID string, forceRefresh bool) ([]ExtensionItem, error) {
	inst, guard, verifiedRoot, phpSel, err := m.resolveInstanceContext(acct, instanceID)
	if err != nil {
		return nil, err
	}

	staticMap := ScanStaticPlugins(guard, verifiedRoot)
	var items []ExtensionItem

	if m.WPCLI != nil {
		if forceRefresh {
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        []string{"transient", "delete", "update_plugins", "--network"},
				SkipPlugins: true,
				SkipThemes:  true,
				Timeout:     10 * time.Second,
			})
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        []string{"transient", "delete", "update_plugins"},
				SkipPlugins: true,
				SkipThemes:  true,
				Timeout:     10 * time.Second,
			})
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        []string{"plugin", "update", "--all", "--dry-run"},
				SkipPlugins: false,
				SkipThemes:  true,
				Timeout:     15 * time.Second,
			})
		}

		stdout, cErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"plugin", "list", "--format=json"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		if cErr == nil {
			var pErr error
			items, pErr = parseWPCLIListJSON(stdout, staticMap, m.Vulns, true)
			if pErr != nil {
				log.Printf("warning: parse wp plugin list JSON on %s (%s): %v", inst.Domain, verifiedRoot, pErr)
			}
		} else {
			log.Printf("warning: wp plugin list on %s (%s): %v", inst.Domain, verifiedRoot, cErr)
		}
	}

	if items == nil {
		// Resilient fallback using static headers + best-effort option lookup
		items = buildStaticFallbackItems(staticMap, m.Vulns, true)
		m.enrichFallbackPluginStates(ctx, acct, verifiedRoot, phpSel, items)
	}

	m.EnrichWithWPOrgLatestVersions(ctx, items, true, forceRefresh)
	m.syncInstancePluginStats(inst, items)
	return items, nil
}

// ListThemes lists all themes of an instance (WSOD-safe), enriches with CVEs, and updates ActiveTheme & ThemeCount.
func (m *Manager) ListThemes(ctx context.Context, acct dausers.Account, instanceID string) ([]ExtensionItem, error) {
	return m.ListThemesWithOptions(ctx, acct, instanceID, false)
}

// ListThemesWithOptions lists all themes of an instance and optionally forces a live transient + WordPress.org refresh.
func (m *Manager) ListThemesWithOptions(ctx context.Context, acct dausers.Account, instanceID string, forceRefresh bool) ([]ExtensionItem, error) {
	inst, guard, verifiedRoot, phpSel, err := m.resolveInstanceContext(acct, instanceID)
	if err != nil {
		return nil, err
	}

	staticMap := ScanStaticThemes(guard, verifiedRoot)
	var items []ExtensionItem

	if m.WPCLI != nil {
		if forceRefresh {
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        []string{"transient", "delete", "update_themes", "--network"},
				SkipPlugins: true,
				SkipThemes:  true,
				Timeout:     10 * time.Second,
			})
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        []string{"transient", "delete", "update_themes"},
				SkipPlugins: true,
				SkipThemes:  true,
				Timeout:     10 * time.Second,
			})
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        []string{"theme", "update", "--all", "--dry-run"},
				SkipPlugins: true,
				SkipThemes:  false,
				Timeout:     15 * time.Second,
			})
		}

		stdout, cErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"theme", "list", "--format=json"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		if cErr == nil {
			var pErr error
			items, pErr = parseWPCLIListJSON(stdout, staticMap, m.Vulns, false)
			if pErr != nil {
				log.Printf("warning: parse wp theme list JSON on %s (%s): %v", inst.Domain, verifiedRoot, pErr)
			}
		} else {
			log.Printf("warning: wp theme list on %s (%s): %v", inst.Domain, verifiedRoot, cErr)
		}
	}

	if items == nil {
		items = buildStaticFallbackItems(staticMap, m.Vulns, false)
	}

	m.EnrichWithWPOrgLatestVersions(ctx, items, false, forceRefresh)
	m.syncInstanceThemeStats(inst, items)
	return items, nil
}

// AggregateAccountExtensions builds the cross-site Global Plugins or Themes catalog across all active instances of acct.
func (m *Manager) AggregateAccountExtensions(ctx context.Context, acct dausers.Account, isThemes bool) ([]GlobalExtensionGroup, error) {
	return m.AggregateAccountExtensionsWithOptions(ctx, acct, isThemes, false)
}

// AggregateAccountExtensionsWithOptions builds the cross-site Global Plugins or Themes catalog with optional live refresh.
func (m *Manager) AggregateAccountExtensionsWithOptions(ctx context.Context, acct dausers.Account, isThemes bool, forceRefresh bool) ([]GlobalExtensionGroup, error) {
	instances := m.Store.ListInstancesByOwner(acct.Username)
	if len(instances) == 0 {
		return []GlobalExtensionGroup{}, nil
	}

	type siteResult struct {
		inst  store.InstanceRecord
		items []ExtensionItem
	}
	results := make([]siteResult, len(instances))

	workers := 4
	if len(instances) < workers {
		workers = len(instances)
	}
	ch := make(chan int, len(instances))
	for i := range instances {
		ch <- i
	}
	close(ch)

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range ch {
				inst := instances[idx]
				var list []ExtensionItem
				var lErr error
				if isThemes {
					list, lErr = m.ListThemesWithOptions(ctx, acct, inst.ID, forceRefresh)
				} else {
					list, lErr = m.ListPluginsWithOptions(ctx, acct, inst.ID, forceRefresh)
				}
				if lErr == nil {
					results[idx] = siteResult{inst: inst, items: list}
				}
			}
		}()
	}
	wg.Wait()

	bySlug := make(map[string]*GlobalExtensionGroup)
	for _, sr := range results {
		if sr.inst.ID == "" {
			continue
		}
		for _, it := range sr.items {
			if it.Status == "dropin" || it.Status == "must-use" {
				continue
			}
			grp, exists := bySlug[it.Slug]
			if !exists {
				grp = &GlobalExtensionGroup{
					Slug:  it.Slug,
					Title: it.Title,
				}
				bySlug[it.Slug] = grp
			}
			if grp.Title == "" || grp.Title == grp.Slug {
				grp.Title = it.Title
			}
			grp.TotalSites++
			if it.Status == "active" || it.Status == "active-network" || it.Status == "parent" {
				grp.ActiveSites++
			}
			if it.UpdateAvailable {
				grp.OutdatedSites++
				if it.UpdateVersion != "" && (grp.LatestAvailable == "" || vulndb.CompareVersions(it.UpdateVersion, grp.LatestAvailable) > 0) {
					grp.LatestAvailable = it.UpdateVersion
				}
			}
			if len(it.Vulns) > 0 {
				grp.VulnerableSites++
				if len(grp.Vulns) == 0 {
					grp.Vulns = it.Vulns
				}
			}
			grp.Sites = append(grp.Sites, SiteExtensionRef{
				InstanceID:      sr.inst.ID,
				Domain:          sr.inst.Domain,
				SubPath:         sr.inst.SubPath,
				SiteTitle:       sr.inst.SiteTitle,
				Status:          it.Status,
				Version:         it.Version,
				UpdateAvailable: it.UpdateAvailable,
				UpdateVersion:   it.UpdateVersion,
				AutoUpdate:      it.AutoUpdate,
				VulnCount:       len(it.Vulns),
			})
		}
	}

	out := make([]GlobalExtensionGroup, 0, len(bySlug))
	for _, g := range bySlug {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].VulnerableSites > 0) != (out[j].VulnerableSites > 0) {
			return out[i].VulnerableSites > 0
		}
		if (out[i].OutdatedSites > 0) != (out[j].OutdatedSites > 0) {
			return out[i].OutdatedSites > 0
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

// ScanInstanceVulnerabilities evaluates Core, Plugins, and Themes against vulndb and persists updated VulnCount/UpdateCount.
func (m *Manager) ScanInstanceVulnerabilities(ctx context.Context, acct dausers.Account, instanceID string) (InstanceVulnReport, error) {
	inst, err := m.Store.GetInstanceForOwner(instanceID, acct.Username)
	if err != nil {
		return InstanceVulnReport{}, err
	}

	plugins, err := m.ListPlugins(ctx, acct, instanceID)
	if err != nil {
		return InstanceVulnReport{}, err
	}
	themes, err := m.ListThemes(ctx, acct, instanceID)
	if err != nil {
		return InstanceVulnReport{}, err
	}

	rep := InstanceVulnReport{
		InstanceID: inst.ID,
		Domain:     inst.Domain,
		SubPath:    inst.SubPath,
		WPVersion:  inst.WPVersion,
	}

	countSev := func(vulns []vulndb.MatchedVuln) {
		for _, v := range vulns {
			rep.TotalVulns++
			if v.Severity == "critical" || v.Severity == "high" {
				rep.CriticalOrHigh++
			}
		}
	}

	if m.Vulns != nil && inst.WPVersion != "" {
		rep.CoreVulns = m.Vulns.MatchCore(inst.WPVersion)
		countSev(rep.CoreVulns)
	}
	for _, p := range plugins {
		if len(p.Vulns) > 0 {
			rep.Plugins = append(rep.Plugins, p)
			countSev(p.Vulns)
		}
	}
	for _, t := range themes {
		if len(t.Vulns) > 0 {
			rep.Themes = append(rep.Themes, t)
			countSev(t.Vulns)
		}
	}

	// Persist exact total UpdateCount & VulnCount onto InstanceRecord
	fresh, gErr := m.Store.GetInstance(inst.ID)
	if gErr == nil {
		updates := 0
		for _, p := range plugins {
			if p.UpdateAvailable {
				updates++
			}
		}
		for _, t := range themes {
			if t.UpdateAvailable {
				updates++
			}
		}
		fresh.UpdateCount = updates
		fresh.VulnCount = rep.TotalVulns
		_, _ = m.Store.UpsertInstance(fresh)
	}
	return rep, nil
}

// ManagePlugin executes WSOD-safe single-site plugin operations (--skip-plugins --skip-themes).
func (m *Manager) ManagePlugin(ctx context.Context, acct dausers.Account, instanceID string, req ActionRequest) ([]ExtensionItem, error) {
	return m.executeExtensionMutation(ctx, acct, instanceID, "plugin", req)
}

// ManageTheme executes WSOD-safe single-site theme operations (--skip-plugins --skip-themes).
func (m *Manager) ManageTheme(ctx context.Context, acct dausers.Account, instanceID string, req ActionRequest) ([]ExtensionItem, error) {
	return m.executeExtensionMutation(ctx, acct, instanceID, "theme", req)
}

// ApplySet installs and activates all plugins & themes belonging to setID on the target WordPress instance.
func (m *Manager) ApplySet(ctx context.Context, acct dausers.Account, instanceID, setID string) error {
	ps, err := m.Store.GetSetForOwner(setID, acct.Username)
	if err != nil {
		return err
	}
	_, _, verifiedRoot, phpSel, err := m.resolveInstanceContext(acct, instanceID)
	if err != nil {
		return err
	}

	for _, pSlug := range ps.Plugins {
		if config.ValidateIdentifier(pSlug) != nil {
			continue
		}
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"plugin", "install", pSlug, "--activate"},
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return fmt.Errorf("install plugin %s from set failed: %w", pSlug, rErr)
		}
	}

	for _, tSlug := range ps.Themes {
		if config.ValidateIdentifier(tSlug) != nil {
			continue
		}
		args := []string{"theme", "install", tSlug}
		if ps.ActiveTheme != "" && strings.EqualFold(ps.ActiveTheme, tSlug) {
			args = append(args, "--activate")
		}
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return fmt.Errorf("install theme %s from set failed: %w", tSlug, rErr)
		}
	}

	if ps.ActiveTheme != "" && config.ValidateIdentifier(ps.ActiveTheme) == nil {
		_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        []string{"theme", "activate", ps.ActiveTheme},
			SkipPlugins: true,
			SkipThemes:  true,
		})
	}

	_, _ = m.ListPlugins(ctx, acct, instanceID)
	_, _ = m.ListThemes(ctx, acct, instanceID)
	return nil
}

func (m *Manager) executeExtensionMutation(
	ctx context.Context,
	acct dausers.Account,
	instanceID string,
	kind string, // "plugin" | "theme"
	req ActionRequest,
) ([]ExtensionItem, error) {
	if m.WPCLI == nil {
		return nil, errors.New("WP-CLI runner is not configured")
	}
	_, guard, verifiedRoot, phpSel, err := m.resolveInstanceContext(acct, instanceID)
	if err != nil {
		return nil, err
	}

	op := strings.ToLower(strings.TrimSpace(req.Operation))
	slugs := collectCleanSlugs(req.Slug, req.Slugs)

	switch op {
	case "activate", "deactivate":
		if kind == "theme" && op == "deactivate" {
			return nil, errors.New("WordPress themes cannot be deactivated directly; activate another theme instead")
		}
		if len(slugs) == 0 {
			return nil, errors.New("at least one valid slug is required")
		}
		args := append([]string{kind, op}, slugs...)
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return nil, fmt.Errorf("%s %s failed: %w", kind, op, rErr)
		}

	case "delete":
		if len(slugs) == 0 {
			return nil, errors.New("at least one valid slug is required")
		}
		if kind == "plugin" {
			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedRoot,
				PHP:         phpSel,
				Args:        append([]string{"plugin", "deactivate"}, slugs...),
				SkipPlugins: true,
				SkipThemes:  true,
			})
		}
		args := append([]string{kind, "delete"}, slugs...)
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return nil, fmt.Errorf("%s delete failed: %w", kind, rErr)
		}

	case "autoupdate_on", "autoupdate_off":
		if len(slugs) == 0 {
			return nil, errors.New("at least one valid slug is required")
		}
		subCmd := "enable"
		if op == "autoupdate_off" {
			subCmd = "disable"
		}
		args := append([]string{kind, "auto-updates", subCmd}, slugs...)
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return nil, fmt.Errorf("%s auto-updates %s failed: %w", kind, subCmd, rErr)
		}

	case "install_slug":
		if len(slugs) == 0 {
			return nil, errors.New("at least one valid WordPress.org slug is required")
		}
		args := append([]string{kind, "install"}, slugs...)
		if ver := strings.TrimSpace(req.Version); ver != "" {
			if err := config.ValidateIdentifier(ver); err != nil {
				return nil, fmt.Errorf("invalid version %q", ver)
			}
			args = append(args, "--version="+ver)
		}
		if req.Activate {
			args = append(args, "--activate")
		}
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return nil, fmt.Errorf("%s install failed: %w", kind, rErr)
		}

	case "install_zip":
		srcZip := strings.TrimSpace(req.ZipPath)
		if srcZip != "" && req.ZipBase64 == "" {
			homeGuard, gErr := fsguard.New(filepath.Clean(acct.HomeDir), nil)
			if gErr != nil {
				return nil, gErr
			}
			verifiedZip, vErr := homeGuard.VerifyExistingPath(srcZip)
			if vErr != nil {
				return nil, vErr
			}
			srcZip = verifiedZip
		} else if req.ZipBase64 == "" {
			return nil, errors.New("either zip_path or zip_base64 is required for install_zip")
		}
		_ = guard

		stageDir := filepath.Join(verifiedRoot, "wp-content", "upgrade")
		stagedZip, _, cleanup, sErr := StageCustomerZip(stageDir, srcZip, req.ZipBase64, acct.UID, acct.GID)
		if sErr != nil {
			return nil, sErr
		}
		defer cleanup()

		args := []string{kind, "install", stagedZip, "--force"}
		if req.Activate {
			args = append(args, "--activate")
		}
		if _, rErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedRoot,
			PHP:         phpSel,
			Args:        args,
			SkipPlugins: true,
			SkipThemes:  true,
		}); rErr != nil {
			return nil, fmt.Errorf("%s .zip install failed: %w", kind, rErr)
		}

	default:
		return nil, fmt.Errorf("unsupported %s operation %q", kind, op)
	}

	if kind == "theme" {
		return m.ListThemes(ctx, acct, instanceID)
	}
	return m.ListPlugins(ctx, acct, instanceID)
}

func (m *Manager) resolveInstanceContext(acct dausers.Account, instanceID string) (store.InstanceRecord, *fsguard.Guard, string, daphp.Selection, error) {
	inst, err := m.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return store.InstanceRecord{}, nil, "", daphp.Selection{}, err
	}
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return store.InstanceRecord{}, nil, "", daphp.Selection{}, err
	}
	verifiedRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return store.InstanceRecord{}, nil, "", daphp.Selection{}, err
	}
	var phpSel daphp.Selection
	if m.Domains != nil {
		if tgt, fErr := m.Domains.FindTarget(acct, inst.Domain); fErr == nil {
			phpSel = tgt.PHP
		}
	}
	return inst, guard, verifiedRoot, phpSel, nil
}

func parseWPCLIListJSON(rawJSON string, staticMap map[string]StaticHeader, vdb *vulndb.DB, isPlugin bool) ([]ExtensionItem, error) {
	jsonSlice, ok := extractJSONArray(rawJSON)
	if !ok {
		return nil, errors.New("no JSON array found in WP-CLI output")
	}
	var rows []wpcliExtRow
	if err := json.Unmarshal([]byte(jsonSlice), &rows); err != nil {
		return nil, err
	}

	items := make([]ExtensionItem, 0, len(rows))
	for _, r := range rows {
		slug := strings.TrimSpace(string(r.Name))
		if slug == "" {
			continue
		}
		hdr := staticMap[slug]
		title := strings.TrimSpace(string(r.Title))
		if title == "" || strings.EqualFold(title, "false") || strings.EqualFold(title, "null") {
			title = hdr.Title
		}
		if title == "" {
			title = slug
		}
		author := strings.TrimSpace(string(r.Author))
		if author == "" || strings.EqualFold(author, "false") || strings.EqualFold(author, "null") {
			author = hdr.Author
		}
		ver := strings.TrimSpace(string(r.Version))
		if ver == "" || strings.EqualFold(ver, "false") || strings.EqualFold(ver, "null") {
			ver = hdr.Version
		}
		updVer := strings.TrimSpace(string(r.UpdateVersion))
		if strings.EqualFold(updVer, "false") || strings.EqualFold(updVer, "none") || strings.EqualFold(updVer, "null") {
			updVer = ""
		}

		autoUpd := isTruthyWPCLIFlag(string(r.AutoUpdate)) || isTruthyWPCLIFlag(string(r.AutoUpdates))
		hasUpd := strings.EqualFold(strings.TrimSpace(string(r.Update)), "available") ||
			(updVer != "" && ver != "" && vulndb.CompareVersions(updVer, ver) > 0) ||
			(updVer != "" && ver == "")
		if !hasUpd {
			updVer = ""
		}

		status := strings.ToLower(strings.TrimSpace(string(r.Status)))
		if status == "" || status == "false" || status == "null" {
			status = "inactive"
		}

		var vulns []vulndb.MatchedVuln
		if vdb != nil && ver != "" {
			if isPlugin {
				vulns = vdb.MatchPlugin(slug, ver)
			} else {
				vulns = vdb.MatchTheme(slug, ver)
			}
		}

		items = append(items, ExtensionItem{
			Slug:            slug,
			Title:           title,
			Status:          status,
			Version:         ver,
			UpdateAvailable: hasUpd,
			UpdateVersion:   updVer,
			AutoUpdate:      autoUpd,
			Author:          author,
			Vulns:           vulns,
		})
	}

	sortExtensionItems(items)
	return items, nil
}

func extractJSONArray(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	end := strings.LastIndexByte(trimmed, ']')
	if end < 0 {
		return "", false
	}
	for i := 0; i <= end; i++ {
		if trimmed[i] != '[' {
			continue
		}
		j := i + 1
		for j <= end && (trimmed[j] == ' ' || trimmed[j] == '\t' || trimmed[j] == '\r' || trimmed[j] == '\n') {
			j++
		}
		if j <= end && (trimmed[j] == '{' || trimmed[j] == ']') {
			return trimmed[i : end+1], true
		}
	}
	return "", false
}

func isTruthyWPCLIFlag(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "on" || s == "true" || s == "1" || s == "yes" || s == "enabled"
}

func (m *Manager) enrichFallbackPluginStates(
	ctx context.Context,
	acct dausers.Account,
	verifiedRoot string,
	phpSel daphp.Selection,
	items []ExtensionItem,
) {
	if m.WPCLI == nil || len(items) == 0 {
		return
	}
	out, err := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedRoot,
		PHP:         phpSel,
		Args:        []string{"option", "get", "active_plugins", "--format=json"},
		SkipPlugins: true,
		SkipThemes:  true,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		return
	}
	arrRaw, ok := extractJSONArrayOrScalarList(out)
	if !ok {
		return
	}
	var activeEntries []string
	if json.Unmarshal([]byte(arrRaw), &activeEntries) != nil {
		return
	}
	activeSlugs := make(map[string]struct{}, len(activeEntries))
	for _, entry := range activeEntries {
		s := strings.TrimSpace(entry)
		if idx := strings.IndexByte(s, '/'); idx > 0 {
			s = s[:idx]
		} else {
			s = strings.TrimSuffix(s, ".php")
		}
		if s != "" {
			activeSlugs[s] = struct{}{}
		}
	}

	autoSlugs := make(map[string]struct{})
	if autoOut, aErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
		Account:     acct,
		DocRoot:     verifiedRoot,
		PHP:         phpSel,
		Args:        []string{"option", "get", "auto_update_plugins", "--format=json"},
		SkipPlugins: true,
		SkipThemes:  true,
		Timeout:     10 * time.Second,
	}); aErr == nil {
		if autoRaw, aOK := extractJSONArrayOrScalarList(autoOut); aOK {
			var autoEntries []string
			if json.Unmarshal([]byte(autoRaw), &autoEntries) == nil {
				for _, entry := range autoEntries {
					s := strings.TrimSpace(entry)
					if idx := strings.IndexByte(s, '/'); idx > 0 {
						s = s[:idx]
					} else {
						s = strings.TrimSuffix(s, ".php")
					}
					if s != "" {
						autoSlugs[s] = struct{}{}
					}
				}
			}
		}
	}

	for i := range items {
		if _, isAct := activeSlugs[items[i].Slug]; isAct {
			items[i].Status = "active"
		} else if items[i].Status == "unknown" {
			items[i].Status = "inactive"
		}
		if _, isAuto := autoSlugs[items[i].Slug]; isAuto {
			items[i].AutoUpdate = true
		}
	}
}

func extractJSONArrayOrScalarList(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	start := strings.IndexByte(trimmed, '[')
	end := strings.LastIndexByte(trimmed, ']')
	if start >= 0 && end >= start {
		return trimmed[start : end+1], true
	}
	return "", false
}

func buildStaticFallbackItems(staticMap map[string]StaticHeader, vdb *vulndb.DB, isPlugin bool) []ExtensionItem {
	items := make([]ExtensionItem, 0, len(staticMap))
	for slug, hdr := range staticMap {
		var vulns []vulndb.MatchedVuln
		if vdb != nil && hdr.Version != "" {
			if isPlugin {
				vulns = vdb.MatchPlugin(slug, hdr.Version)
			} else {
				vulns = vdb.MatchTheme(slug, hdr.Version)
			}
		}
		items = append(items, ExtensionItem{
			Slug:    slug,
			Title:   hdr.Title,
			Status:  "unknown",
			Version: hdr.Version,
			Author:  hdr.Author,
			Vulns:   vulns,
		})
	}
	sortExtensionItems(items)
	return items
}

func sortExtensionItems(items []ExtensionItem) {
	sort.Slice(items, func(i, j int) bool {
		if (len(items[i].Vulns) > 0) != (len(items[j].Vulns) > 0) {
			return len(items[i].Vulns) > 0
		}
		if items[i].UpdateAvailable != items[j].UpdateAvailable {
			return items[i].UpdateAvailable
		}
		return items[i].Slug < items[j].Slug
	})
}

func (m *Manager) syncInstancePluginStats(inst store.InstanceRecord, items []ExtensionItem) {
	fresh, err := m.Store.GetInstance(inst.ID)
	if err != nil {
		return
	}
	regCount := 0
	updates := 0
	vulns := 0
	for _, it := range items {
		if it.Status != "dropin" && it.Status != "must-use" {
			regCount++
		}
		if it.UpdateAvailable {
			updates++
		}
		vulns += len(it.Vulns)
	}
	if m.Vulns != nil && fresh.WPVersion != "" {
		vulns += len(m.Vulns.MatchCore(fresh.WPVersion))
	}

	m.countsMu.Lock()
	if m.extCounts == nil {
		m.extCounts = make(map[string]instanceExtUpdateCounts)
	}
	c := m.extCounts[inst.ID]
	c.pluginUpdates = updates
	c.hasPlugins = true
	m.extCounts[inst.ID] = c
	totalUpdates := updates
	if c.hasThemes {
		totalUpdates += c.themeUpdates
	}
	m.countsMu.Unlock()

	fresh.PluginCount = regCount
	fresh.UpdateCount = totalUpdates
	fresh.VulnCount = vulns
	_, _ = m.Store.UpsertInstance(fresh)
}

func (m *Manager) syncInstanceThemeStats(inst store.InstanceRecord, items []ExtensionItem) {
	fresh, err := m.Store.GetInstance(inst.ID)
	if err != nil {
		return
	}
	themeUpdates := 0
	for _, it := range items {
		if it.Status == "active" {
			fresh.ActiveTheme = it.Title
		}
		if it.UpdateAvailable {
			themeUpdates++
		}
	}

	m.countsMu.Lock()
	if m.extCounts == nil {
		m.extCounts = make(map[string]instanceExtUpdateCounts)
	}
	c := m.extCounts[inst.ID]
	c.themeUpdates = themeUpdates
	c.hasThemes = true
	m.extCounts[inst.ID] = c
	hasPlugins := c.hasPlugins
	totalUpdates := c.pluginUpdates + themeUpdates
	m.countsMu.Unlock()

	fresh.ThemeCount = len(items)
	if hasPlugins {
		fresh.UpdateCount = totalUpdates
	} else if themeUpdates > fresh.UpdateCount {
		fresh.UpdateCount = themeUpdates
	}
	_, _ = m.Store.UpsertInstance(fresh)
}

func collectCleanSlugs(single string, many []string) []string {
	var raw []string
	if strings.TrimSpace(single) != "" {
		raw = append(raw, single)
	}
	raw = append(raw, many...)

	seen := make(map[string]struct{}, len(raw))
	var out []string
	for _, item := range raw {
		for _, part := range strings.Split(item, ",") {
			s := strings.ToLower(strings.TrimSpace(part))
			if s == "" {
				continue
			}
			if config.ValidateIdentifier(s) == nil {
				if _, dup := seen[s]; !dup {
					seen[s] = struct{}{}
					out = append(out, s)
				}
			}
		}
	}
	return out
}
