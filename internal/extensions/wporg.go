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
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
)

const DefaultWPOrgAPIBase = "https://api.wordpress.org"

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
	req.Header.Set("User-Agent", "DA-WordPressToolkits/1.0")

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
