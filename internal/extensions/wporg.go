package extensions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
)

const (
	DefaultWPOrgAPIBase   = "https://api.wordpress.org"
	wpOrgVersionCacheTTL  = 30 * time.Minute
	wpOrgMaxCheckWorkers  = 6
	wpOrgCheckSlugTimeout = 5 * time.Second
)

type wpOrgVersionCacheEntry struct {
	version   string
	notFound  bool
	expiresAt time.Time
}

// WPOrgItem represents a plugin or theme search result from WordPress.org enriched with CVE checks.
type WPOrgItem struct {
	Slug             string               `json:"slug"`
	Name             string               `json:"name"`
	Version          string               `json:"version"`
	Author           string               `json:"author"`
	Rating           int                  `json:"rating"` // 0..100
	ActiveInstalls   int                  `json:"active_installs,omitempty"`
	ShortDescription string               `json:"short_description"`
	IconURL          string               `json:"icon_url,omitempty"`
	Homepage         string               `json:"homepage,omitempty"`
	Vulns            []vulndb.MatchedVuln `json:"vulns,omitempty"`
}

// SearchWPOrg queries the official WordPress.org Plugins or Themes repository (kind = "plugin" | "theme").
func (m *Manager) SearchWPOrg(ctx context.Context, kind, search string, page, perPage int) ([]WPOrgItem, error) {
	q := strings.TrimSpace(search)
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 || perPage > 24 {
		perPage = 12
	}

	baseURL := strings.TrimRight(m.WPOrgAPIBase, "/")
	if baseURL == "" {
		baseURL = DefaultWPOrgAPIBase
	}

	isTheme := strings.EqualFold(strings.TrimSpace(kind), "theme") || strings.EqualFold(strings.TrimSpace(kind), "themes")

	params := url.Values{}
	if isTheme {
		params.Set("action", "query_themes")
	} else {
		params.Set("action", "query_plugins")
		params.Set("request[fields][icons]", "1")
		params.Set("request[fields][active_installs]", "1")
		params.Set("request[fields][short_description]", "1")
	}
	if q != "" {
		params.Set("request[search]", q)
	} else {
		params.Set("request[browse]", "popular")
	}
	params.Set("request[page]", strconv.Itoa(page))
	params.Set("request[per_page]", strconv.Itoa(perPage))

	endpoint := baseURL + "/plugins/info/1.2/?" + params.Encode()
	if isTheme {
		endpoint = baseURL + "/themes/info/1.2/?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DA-WordPressManager/1.0")

	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WordPress.org API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("WordPress.org API returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	if isTheme {
		var payload struct {
			Themes []struct {
				Slug          string `json:"slug"`
				Name          string `json:"name"`
				Version       string `json:"version"`
				Rating        int    `json:"rating"`
				ScreenshotURL string `json:"screenshot_url"`
				Homepage      string `json:"homepage"`
				Description   string `json:"description"`
				Author        any    `json:"author"`
			} `json:"themes"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, fmt.Errorf("decode WP.org themes response: %w", err)
		}
		out := make([]WPOrgItem, 0, len(payload.Themes))
		for _, th := range payload.Themes {
			item := WPOrgItem{
				Slug:             th.Slug,
				Name:             stripSimpleHTML(th.Name),
				Version:          th.Version,
				Author:           extractAuthorString(th.Author),
				Rating:           th.Rating,
				ShortDescription: truncateText(stripSimpleHTML(th.Description), 180),
				IconURL:          th.ScreenshotURL,
				Homepage:         th.Homepage,
			}
			if m.Vulns != nil {
				item.Vulns = m.Vulns.MatchTheme(item.Slug, item.Version)
			}
			out = append(out, item)
		}
		return out, nil
	}

	var payload struct {
		Plugins []struct {
			Slug             string         `json:"slug"`
			Name             string         `json:"name"`
			Version          string         `json:"version"`
			Author           string         `json:"author"`
			Rating           int            `json:"rating"`
			ActiveInstalls   int            `json:"active_installs"`
			ShortDescription string         `json:"short_description"`
			Homepage         string         `json:"homepage"`
			Icons            map[string]any `json:"icons"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode WP.org plugins response: %w", err)
	}

	out := make([]WPOrgItem, 0, len(payload.Plugins))
	for _, pl := range payload.Plugins {
		item := WPOrgItem{
			Slug:             pl.Slug,
			Name:             stripSimpleHTML(pl.Name),
			Version:          pl.Version,
			Author:           stripSimpleHTML(pl.Author),
			Rating:           pl.Rating,
			ActiveInstalls:   pl.ActiveInstalls,
			ShortDescription: truncateText(stripSimpleHTML(pl.ShortDescription), 180),
			IconURL:          pickIconURL(pl.Icons),
			Homepage:         pl.Homepage,
		}
		if m.Vulns != nil {
			item.Vulns = m.Vulns.MatchPlugin(item.Slug, item.Version)
		}
		out = append(out, item)
	}
	return out, nil
}

func pickIconURL(icons map[string]any) string {
	for _, key := range []string{"2x", "1x", "svg", "default"} {
		if v, ok := icons[key]; ok {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "http") {
				return s
			}
		}
	}
	return ""
}

func extractAuthorString(v any) string {
	switch val := v.(type) {
	case string:
		return stripSimpleHTML(val)
	case map[string]any:
		if dn, ok := val["display_name"].(string); ok && dn != "" {
			return stripSimpleHTML(dn)
		}
		if un, ok := val["user_nicename"].(string); ok {
			return un
		}
	}
	return ""
}

func stripSimpleHTML(s string) string {
	var out strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

func truncateText(s string, maxChars int) string {
	runes := []rune(s)
	if len(runes) <= maxChars {
		return s
	}
	return strings.TrimSpace(string(runes[:maxChars])) + "..."
}

// EnrichWithWPOrgLatestVersions checks installed plugin/theme slugs against the official WordPress.org API
// (using a 30-minute in-memory positive & negative cache) so outdated extensions are detected reliably
// even when WordPress's _site_transient_update_plugins / _site_transient_update_themes is stale or empty.
func (m *Manager) EnrichWithWPOrgLatestVersions(ctx context.Context, items []ExtensionItem, isPlugin bool, forceRefresh bool) {
	if len(items) == 0 || (!m.LiveUpdateCheck && !forceRefresh) {
		return
	}

	kindPrefix := "plugin:"
	if !isPlugin {
		kindPrefix = "theme:"
	}

	now := time.Now()
	var toFetch []string
	seen := make(map[string]struct{}, len(items))

	m.cacheMu.RLock()
	for _, it := range items {
		if it.Status == "dropin" || it.Status == "must-use" {
			continue
		}
		slug := strings.ToLower(strings.TrimSpace(it.Slug))
		if slug == "" || config.ValidateIdentifier(slug) != nil {
			continue
		}
		if _, dup := seen[slug]; dup {
			continue
		}
		seen[slug] = struct{}{}

		if !forceRefresh && m.versionCache != nil {
			if cached, ok := m.versionCache[kindPrefix+slug]; ok && now.Before(cached.expiresAt) {
				continue
			}
		}
		toFetch = append(toFetch, slug)
	}
	m.cacheMu.RUnlock()

	if len(toFetch) > 0 {
		workers := wpOrgMaxCheckWorkers
		if len(toFetch) < workers {
			workers = len(toFetch)
		}
		ch := make(chan string, len(toFetch))
		for _, s := range toFetch {
			ch <- s
		}
		close(ch)

		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for slug := range ch {
					ver, notFound, fErr := m.fetchWPOrgLatestVersion(ctx, slug, isPlugin)
					if fErr != nil {
						continue
					}
					m.cacheMu.Lock()
					if m.versionCache == nil {
						m.versionCache = make(map[string]wpOrgVersionCacheEntry)
					}
					m.versionCache[kindPrefix+slug] = wpOrgVersionCacheEntry{
						version:   ver,
						notFound:  notFound,
						expiresAt: time.Now().Add(wpOrgVersionCacheTTL),
					}
					m.cacheMu.Unlock()
				}
			}()
		}
		wg.Wait()
	}

	changed := false
	m.cacheMu.RLock()
	for i := range items {
		it := &items[i]
		if it.Status == "dropin" || it.Status == "must-use" {
			continue
		}
		slug := strings.ToLower(strings.TrimSpace(it.Slug))
		cached, ok := m.versionCache[kindPrefix+slug]
		if !ok || cached.notFound || cached.version == "" {
			continue
		}
		if it.Version != "" && vulndb.CompareVersions(cached.version, it.Version) > 0 {
			if !it.UpdateAvailable || it.UpdateVersion == "" || vulndb.CompareVersions(cached.version, it.UpdateVersion) > 0 {
				it.UpdateAvailable = true
				it.UpdateVersion = cached.version
				changed = true
			}
		}
	}
	m.cacheMu.RUnlock()

	if changed {
		sortExtensionItems(items)
	}
}

func (m *Manager) fetchWPOrgLatestVersion(ctx context.Context, slug string, isPlugin bool) (version string, notFound bool, err error) {
	baseURL := strings.TrimRight(m.WPOrgAPIBase, "/")
	if baseURL == "" {
		baseURL = DefaultWPOrgAPIBase
	}

	params := url.Values{}
	var endpoint string
	if isPlugin {
		params.Set("action", "plugin_information")
		params.Set("request[slug]", slug)
		params.Set("request[fields][sections]", "0")
		params.Set("request[fields][versions]", "0")
		params.Set("request[fields][screenshots]", "0")
		params.Set("request[fields][ratings]", "0")
		params.Set("request[fields][banners]", "0")
		params.Set("request[fields][compatibility]", "0")
		params.Set("request[fields][contributors]", "0")
		params.Set("request[fields][tags]", "0")
		params.Set("request[fields][description]", "0")
		params.Set("request[fields][short_description]", "0")
		endpoint = baseURL + "/plugins/info/1.2/?" + params.Encode()
	} else {
		params.Set("action", "theme_information")
		params.Set("request[slug]", slug)
		params.Set("request[fields][sections]", "0")
		params.Set("request[fields][versions]", "0")
		params.Set("request[fields][rating]", "0")
		params.Set("request[fields][tags]", "0")
		params.Set("request[fields][description]", "0")
		endpoint = baseURL + "/themes/info/1.2/?" + params.Encode()
	}

	reqCtx, cancel := context.WithTimeout(ctx, wpOrgCheckSlugTimeout)
	defer cancel()

	req, rErr := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if rErr != nil {
		return "", false, rErr
	}
	req.Header.Set("User-Agent", "DA-WordPressManager/1.0")

	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: wpOrgCheckSlugTimeout}
	}
	resp, dErr := client.Do(req)
	if dErr != nil {
		return "", false, dErr
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", true, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if readErr != nil {
		return "", false, readErr
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "false" || trimmed == "null" {
		return "", true, nil
	}

	var info struct {
		Version string `json:"version"`
		Error   string `json:"error"`
	}
	if uErr := json.Unmarshal(raw, &info); uErr != nil {
		return "", false, uErr
	}
	if strings.TrimSpace(info.Error) != "" {
		return "", true, nil
	}
	return strings.TrimSpace(info.Version), false, nil
}
