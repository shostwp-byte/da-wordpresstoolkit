package vulndb

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultWordfenceFeedURL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
	DefaultSyncInterval     = 12 * time.Hour
	maxRawFeedBytes         = 160 * 1024 * 1024 // 160 MB uncompressed safety ceiling
	SoftwarePlugin          = "plugin"
	SoftwareTheme           = "theme"
	SoftwareCore            = "core"
)

// Rule stores a compact, indexed vulnerability rule for a single software slug.
type Rule struct {
	ID              string         `json:"id"`
	CVE             string         `json:"cve,omitempty"`
	CVELink         string         `json:"cve_link,omitempty"`
	Title           string         `json:"title"`
	Severity        string         `json:"severity"`
	CVSSScore       float64        `json:"cvss_score"`
	Patched         bool           `json:"patched"`
	PatchedVersions []string       `json:"patched_versions,omitempty"`
	References      []string       `json:"references,omitempty"`
	Published       string         `json:"published,omitempty"`
	Ranges          []VersionRange `json:"ranges"`
}

// MatchedVuln describes an active vulnerability affecting an installed WordPress core, plugin, or theme.
type MatchedVuln struct {
	ID          string   `json:"id"`
	CVE         string   `json:"cve,omitempty"`
	CVELink     string   `json:"cve_link,omitempty"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	CVSSScore   float64  `json:"cvss_score"`
	Patched     bool     `json:"patched"`
	FixedIn     string   `json:"fixed_in,omitempty"`
	Unpatched   bool     `json:"unpatched"`
	References  []string `json:"references,omitempty"`
	PublishedAt string   `json:"published_at,omitempty"`
}

// Status reports the current state of the local CVE intelligence index.
type Status struct {
	TotalRules     int       `json:"total_rules"`
	IndexedPlugins int       `json:"indexed_plugins"`
	IndexedThemes  int       `json:"indexed_themes"`
	CoreRules      int       `json:"core_rules"`
	LastSyncedAt   time.Time `json:"last_synced_at"`
	FeedURL        string    `json:"feed_url"`
	LastError      string    `json:"last_error,omitempty"`
}

type persistedIndex struct {
	SchemaVersion int               `json:"schema_version"`
	LastSyncedAt  time.Time         `json:"last_synced_at"`
	FeedURL       string            `json:"feed_url"`
	Plugins       map[string][]Rule `json:"plugins"`
	Themes        map[string][]Rule `json:"themes"`
	Core          []Rule            `json:"core"`
}

// DB maintains an in-memory + crash-safe persisted CVE index synchronized from Wordfence Community Feed v2.
type DB struct {
	StateDir   string
	FeedURL    string
	HTTPClient *http.Client

	mu           sync.RWMutex
	plugins      map[string][]Rule
	themes       map[string][]Rule
	core         []Rule
	totalRules   int
	lastSyncedAt time.Time
	lastError    string
}

// Open initializes the local CVE database from stateDir/vulndb_index.json if present.
func Open(stateDir, feedURL string) (*DB, error) {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = "/var/lib/da-wptoolkit/state"
	}
	if strings.TrimSpace(feedURL) == "" {
		feedURL = DefaultWordfenceFeedURL
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}

	db := &DB{
		StateDir: stateDir,
		FeedURL:  feedURL,
		HTTPClient: &http.Client{
			Timeout: 90 * time.Second,
		},
		plugins: make(map[string][]Rule),
		themes:  make(map[string][]Rule),
	}
	_ = db.loadFromDisk()
	return db, nil
}

func (db *DB) indexPath() string {
	return filepath.Join(db.StateDir, "vulndb_index.json")
}

// Status returns index statistics for Admin UI & CLI reporting.
func (db *DB) Status() Status {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return Status{
		TotalRules:     db.totalRules,
		IndexedPlugins: len(db.plugins),
		IndexedThemes:  len(db.themes),
		CoreRules:      len(db.core),
		LastSyncedAt:   db.lastSyncedAt,
		FeedURL:        db.FeedURL,
		LastError:      db.lastError,
	}
}

// StartAutoSync refreshes the Wordfence CVE feed periodically in the background.
func (db *DB) StartAutoSync(ctx context.Context, interval time.Duration, onSynced func(Status)) {
	if interval <= 0 {
		interval = DefaultSyncInterval
	}
	go func() {
		// Initial delayed check if index is empty or older than interval
		st := db.Status()
		if st.TotalRules == 0 || time.Since(st.LastSyncedAt) >= interval {
			if _, err := db.Sync(ctx, ""); err == nil && onSynced != nil {
				onSynced(db.Status())
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := db.Sync(ctx, ""); err == nil && onSynced != nil {
					onSynced(db.Status())
				}
			}
		}
	}()
}

// Sync fetches and indexes the Wordfence Community Feed from overrideSource (HTTP/HTTPS URL or local file path),
// defaulting to db.FeedURL when overrideSource is empty.
func (db *DB) Sync(ctx context.Context, overrideSource string) (Status, error) {
	src := strings.TrimSpace(overrideSource)
	if src == "" {
		src = db.FeedURL
	}

	var reader io.ReadCloser
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			db.recordErr(err)
			return db.Status(), err
		}
		req.Header.Set("User-Agent", "DA-WordPressManager-VulnSync/1.0")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Accept-Encoding", "gzip")

		client := db.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 90 * time.Second}
		}
		resp, err := client.Do(req)
		if err != nil {
			db.recordErr(err)
			return db.Status(), fmt.Errorf("download CVE feed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err := fmt.Errorf("CVE feed HTTP %d", resp.StatusCode)
			db.recordErr(err)
			return db.Status(), err
		}

		var bodyReader io.Reader = resp.Body
		if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") {
			gz, gzErr := gzip.NewReader(resp.Body)
			if gzErr != nil {
				db.recordErr(gzErr)
				return db.Status(), gzErr
			}
			defer gz.Close()
			bodyReader = gz
		}
		reader = io.NopCloser(io.LimitReader(bodyReader, maxRawFeedBytes))
	} else {
		f, err := os.Open(src)
		if err != nil {
			db.recordErr(err)
			return db.Status(), err
		}
		defer f.Close()
		var bodyReader io.Reader = f
		if strings.HasSuffix(strings.ToLower(src), ".gz") {
			gz, gzErr := gzip.NewReader(f)
			if gzErr != nil {
				db.recordErr(gzErr)
				return db.Status(), gzErr
			}
			defer gz.Close()
			bodyReader = gz
		}
		reader = io.NopCloser(io.LimitReader(bodyReader, maxRawFeedBytes))
	}
	defer reader.Close()

	if err := db.LoadStream(reader, src); err != nil {
		db.recordErr(err)
		return db.Status(), err
	}
	return db.Status(), nil
}

// HasSlugRules performs a zero-allocation O(1) check for whether any CVE rule exists for (softwareType, slug).
func (db *DB) HasSlugRules(softwareType, slug string) bool {
	norm := strings.ToLower(strings.TrimSpace(slug))
	db.mu.RLock()
	defer db.mu.RUnlock()
	switch strings.ToLower(strings.TrimSpace(softwareType)) {
	case SoftwarePlugin:
		return len(db.plugins[norm]) > 0
	case SoftwareTheme:
		return len(db.themes[norm]) > 0
	case SoftwareCore:
		return len(db.core) > 0
	default:
		return false
	}
}

// MatchPlugin returns all known CVEs affecting the given plugin slug and installed version, sorted by CVSS descending.
func (db *DB) MatchPlugin(slug, installedVersion string) []MatchedVuln {
	return db.Match(SoftwarePlugin, slug, installedVersion)
}

// MatchTheme returns all known CVEs affecting the given theme slug and installed version.
func (db *DB) MatchTheme(slug, installedVersion string) []MatchedVuln {
	return db.Match(SoftwareTheme, slug, installedVersion)
}

// MatchCore returns all known CVEs affecting the given WordPress core version.
func (db *DB) MatchCore(installedVersion string) []MatchedVuln {
	return db.Match(SoftwareCore, "wordpress", installedVersion)
}

// Match evaluates indexed CVE rules against (softwareType, slug, installedVersion) in O(1) map lookup time.
func (db *DB) Match(softwareType, slug, installedVersion string) []MatchedVuln {
	ver := strings.TrimSpace(installedVersion)
	if ver == "" {
		return nil
	}
	normSlug := strings.ToLower(strings.TrimSpace(slug))

	db.mu.RLock()
	var rules []Rule
	switch strings.ToLower(strings.TrimSpace(softwareType)) {
	case SoftwarePlugin:
		rules = db.plugins[normSlug]
	case SoftwareTheme:
		rules = db.themes[normSlug]
	case SoftwareCore:
		rules = db.core
	}
	db.mu.RUnlock()

	if len(rules) == 0 {
		return nil
	}

	var matched []MatchedVuln
	for _, rule := range rules {
		hit := false
		for _, rng := range rule.Ranges {
			if InAffectedRange(ver, rng) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}

		fixedIn := pickLowestPatchedVersionAbove(ver, rule.PatchedVersions)
		matched = append(matched, MatchedVuln{
			ID:          rule.ID,
			CVE:         rule.CVE,
			CVELink:     rule.CVELink,
			Title:       rule.Title,
			Severity:    rule.Severity,
			CVSSScore:   rule.CVSSScore,
			Patched:     rule.Patched,
			FixedIn:     fixedIn,
			Unpatched:   !rule.Patched,
			References:  rule.References,
			PublishedAt: rule.Published,
		})
	}

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].CVSSScore != matched[j].CVSSScore {
			return matched[i].CVSSScore > matched[j].CVSSScore
		}
		return matched[i].ID < matched[j].ID
	})
	return matched
}

type wfFeedEntry struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CVE        string   `json:"cve"`
	CVELink    string   `json:"cve_link"`
	References []string `json:"references"`
	Published  string   `json:"published"`
	CVSS       struct {
		Score  float64 `json:"score"`
		Rating string  `json:"rating"`
	} `json:"cvss"`
	Software []struct {
		Type             string                  `json:"type"`
		Name             string                  `json:"name"`
		Slug             string                  `json:"slug"`
		Patched          bool                    `json:"patched"`
		PatchedVersions  []string                `json:"patched_versions"`
		AffectedVersions map[string]VersionRange `json:"affected_versions"`
	} `json:"software"`
}

// LoadStream parses a Wordfence Intelligence v2 JSON stream incrementally (token-by-token) to keep RAM usage minimal,
// then atomically updates both the in-memory index and stateDir/vulndb_index.json.
func (db *DB) LoadStream(r io.Reader, sourceLabel string) error {
	dec := json.NewDecoder(r)

	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("read CVE JSON header: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return errors.New("unexpected CVE feed root token: expected JSON object or array")
	}

	plugins := make(map[string][]Rule)
	themes := make(map[string][]Rule)
	var core []Rule
	totalRules := 0

	ingestEntry := func(fallbackID string, entry wfFeedEntry) {
		id := strings.TrimSpace(entry.ID)
		if id == "" {
			id = fallbackID
		}
		severity := normalizeSeverity(entry.CVSS.Rating, entry.CVSS.Score)
		refs := entry.References
		if len(refs) > 3 {
			refs = append([]string(nil), refs[:3]...)
		}

		for _, sw := range entry.Software {
			swType := strings.ToLower(strings.TrimSpace(sw.Type))
			slug := strings.ToLower(strings.TrimSpace(sw.Slug))
			if slug == "" && swType != SoftwareCore {
				continue
			}

			ranges := make([]VersionRange, 0, len(sw.AffectedVersions))
			for _, vr := range sw.AffectedVersions {
				if strings.TrimSpace(vr.FromVersion) == "" && strings.TrimSpace(vr.ToVersion) == "" {
					continue
				}
				ranges = append(ranges, vr)
			}
			if len(ranges) == 0 {
				continue
			}

			rule := Rule{
				ID:              id,
				CVE:             strings.TrimSpace(entry.CVE),
				CVELink:         strings.TrimSpace(entry.CVELink),
				Title:           strings.TrimSpace(entry.Title),
				Severity:        severity,
				CVSSScore:       entry.CVSS.Score,
				Patched:         sw.Patched,
				PatchedVersions: sw.PatchedVersions,
				References:      refs,
				Published:       strings.TrimSpace(entry.Published),
				Ranges:          ranges,
			}

			switch swType {
			case SoftwarePlugin:
				plugins[slug] = append(plugins[slug], rule)
				totalRules++
			case SoftwareTheme:
				themes[slug] = append(themes[slug], rule)
				totalRules++
			case SoftwareCore:
				core = append(core, rule)
				totalRules++
			}
		}
	}

	if delim == '{' {
		for dec.More() {
			keyTok, kErr := dec.Token()
			if kErr != nil {
				return fmt.Errorf("parse CVE map key: %w", kErr)
			}
			keyStr, _ := keyTok.(string)
			var entry wfFeedEntry
			if dErr := dec.Decode(&entry); dErr != nil {
				return fmt.Errorf("decode CVE entry %q: %w", keyStr, dErr)
			}
			ingestEntry(keyStr, entry)
		}
	} else {
		for dec.More() {
			var entry wfFeedEntry
			if dErr := dec.Decode(&entry); dErr != nil {
				return fmt.Errorf("decode CVE array entry: %w", dErr)
			}
			ingestEntry("", entry)
		}
	}

	now := time.Now().UTC()
	snap := persistedIndex{
		SchemaVersion: 1,
		LastSyncedAt:  now,
		FeedURL:       sourceLabel,
		Plugins:       plugins,
		Themes:        themes,
		Core:          core,
	}
	payload, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := atomicWriteIndex(db.indexPath(), payload); err != nil {
		return err
	}

	db.mu.Lock()
	db.plugins = plugins
	db.themes = themes
	db.core = core
	db.totalRules = totalRules
	db.lastSyncedAt = now
	db.lastError = ""
	db.mu.Unlock()
	return nil
}

func (db *DB) loadFromDisk() error {
	p := db.indexPath()
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked CVE index %s", p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var snap persistedIndex
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}

	total := len(snap.Core)
	for _, list := range snap.Plugins {
		total += len(list)
	}
	for _, list := range snap.Themes {
		total += len(list)
	}

	db.mu.Lock()
	if snap.Plugins != nil {
		db.plugins = snap.Plugins
	}
	if snap.Themes != nil {
		db.themes = snap.Themes
	}
	db.core = snap.Core
	db.totalRules = total
	db.lastSyncedAt = snap.LastSyncedAt
	db.mu.Unlock()
	return nil
}

func (db *DB) recordErr(err error) {
	if err == nil {
		return
	}
	db.mu.Lock()
	db.lastError = err.Error()
	db.mu.Unlock()
}

func normalizeSeverity(rating string, score float64) string {
	switch strings.ToLower(strings.TrimSpace(rating)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

func pickLowestPatchedVersionAbove(installed string, patched []string) string {
	best := ""
	for _, pv := range patched {
		cand := strings.TrimSpace(pv)
		if cand == "" {
			continue
		}
		if CompareVersions(cand, installed) > 0 {
			if best == "" || CompareVersions(cand, best) < 0 {
				best = cand
			}
		}
	}
	if best == "" && len(patched) > 0 {
		return strings.TrimSpace(patched[0])
	}
	return best
}

func atomicWriteIndex(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked file %s", path)
	}
	tmp, err := os.CreateTemp(dir, ".vulndb-*")
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
	if err := tmp.Chmod(0o600); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
