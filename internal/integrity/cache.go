package integrity

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
)

const (
	DefaultCoreCacheDir     = "/var/cache/da-wptoolkit/wp-core"
	DefaultChecksumsAPIBase = "https://api.wordpress.org/core/checksums/1.0/"
	DefaultDownloadBaseURL  = "https://wordpress.org"
	maxCoreArchiveBytes     = 120 * 1024 * 1024 // 120 MB safety ceiling
	maxSingleCoreFileBytes  = 16 * 1024 * 1024  // 16 MB safety ceiling per core file
)

var reValidWPVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9._-]+)?$`)

// CoreFileHash stores official MD5 and locally verified SHA-256 digests for a single WordPress Core file.
type CoreFileHash struct {
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// CoreManifest indexes every verified non-wp-content Core file for a specific (version, locale) release.
type CoreManifest struct {
	Version  string                  `json:"version"`
	Locale   string                  `json:"locale"`
	SyncedAt time.Time               `json:"synced_at"`
	Files    map[string]CoreFileHash `json:"files"` // POSIX relPath -> digests
}

// CachedReleaseInfo summarizes a cached WordPress Core package for Admin Panel Tab 3.
type CachedReleaseInfo struct {
	Key       string    `json:"key"`
	Version   string    `json:"version"`
	Locale    string    `json:"locale"`
	FileCount int       `json:"file_count"`
	SizeBytes int64     `json:"size_bytes"`
	SyncedAt  time.Time `json:"synced_at"`
}

// CacheStatus reports total disk usage and cached releases in /var/cache/da-wptoolkit/wp-core/.
type CacheStatus struct {
	BaseDir    string              `json:"base_dir"`
	TotalBytes int64               `json:"total_bytes"`
	Releases   []CachedReleaseInfo `json:"releases"`
}

// CoreCache manages verified WordPress Core file pools so Auto-Heal restores corrupted files offline in < 50ms.
type CoreCache struct {
	BaseDir          string
	ChecksumsAPIBase string
	DownloadBaseURL  string
	HTTPClient       *http.Client

	mu        sync.RWMutex
	manifests map[string]*CoreManifest
}

// NewCoreCache initializes the Local Verified Core Cache rooted at baseDir.
func NewCoreCache(baseDir string) *CoreCache {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = DefaultCoreCacheDir
	}
	return &CoreCache{
		BaseDir:          baseDir,
		ChecksumsAPIBase: DefaultChecksumsAPIBase,
		DownloadBaseURL:  DefaultDownloadBaseURL,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		manifests: make(map[string]*CoreManifest),
	}
}

func normalizeVersionAndLocale(version, locale string) (string, string, error) {
	v := strings.TrimSpace(version)
	if !reValidWPVersion.MatchString(v) {
		return "", "", fmt.Errorf("invalid WordPress version %q", version)
	}
	loc := strings.TrimSpace(locale)
	if loc == "" {
		loc = "en_US"
	}
	if err := config.ValidateIdentifier(loc); err != nil {
		return "", "", fmt.Errorf("invalid WordPress locale %q: %w", locale, err)
	}
	return v, loc, nil
}

func releaseKey(version, locale string) string {
	return version + "-" + locale
}

func (c *CoreCache) releaseDir(version, locale string) string {
	return filepath.Join(c.BaseDir, releaseKey(version, locale))
}

// CleanFilePath returns the verified clean file path on disk for relPath inside the Core Cache.
func (c *CoreCache) CleanFilePath(version, locale, relPath string) (string, error) {
	v, loc, err := normalizeVersionAndLocale(version, locale)
	if err != nil {
		return "", err
	}
	normRel, err := normalizeCoreRelPath(relPath)
	if err != nil {
		return "", err
	}
	p := filepath.Join(c.releaseDir(v, loc), "files", filepath.FromSlash(normRel))
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

// GetCachedManifest returns a previously verified CoreManifest from memory or disk without network calls.
func (c *CoreCache) GetCachedManifest(version, locale string) (*CoreManifest, bool) {
	v, loc, err := normalizeVersionAndLocale(version, locale)
	if err != nil {
		return nil, false
	}
	key := releaseKey(v, loc)

	c.mu.RLock()
	if m, ok := c.manifests[key]; ok {
		c.mu.RUnlock()
		return m, true
	}
	c.mu.RUnlock()

	manifestPath := filepath.Join(c.releaseDir(v, loc), "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, false
	}
	var m CoreManifest
	if err := json.Unmarshal(raw, &m); err != nil || len(m.Files) == 0 {
		return nil, false
	}

	c.mu.Lock()
	c.manifests[key] = &m
	c.mu.Unlock()
	return &m, true
}

// EnsureVerifiedCore loads a cached Core release or downloads & cryptographically verifies it from wordpress.org.
func (c *CoreCache) EnsureVerifiedCore(ctx context.Context, version, locale string) (*CoreManifest, error) {
	v, loc, err := normalizeVersionAndLocale(version, locale)
	if err != nil {
		return nil, err
	}
	if m, ok := c.GetCachedManifest(v, loc); ok {
		return m, nil
	}

	checksums, resolvedLoc, err := c.fetchOfficialChecksums(ctx, v, loc)
	if err != nil {
		return nil, err
	}
	if m, ok := c.GetCachedManifest(v, resolvedLoc); ok {
		return m, nil
	}

	return c.downloadAndVerifyTarball(ctx, v, resolvedLoc, checksums)
}

// SeedVerifiedTree registers a clean WordPress Core directory tree into the Local Verified Core Cache
// (computing MD5 + SHA-256 digests and excluding wp-content/*, wp-config.php, and .htaccess).
func (c *CoreCache) SeedVerifiedTree(version, locale, cleanSourceDir string) (*CoreManifest, error) {
	v, loc, err := normalizeVersionAndLocale(version, locale)
	if err != nil {
		return nil, err
	}

	relDir := c.releaseDir(v, loc)
	stagingDir := relDir + ".staging"
	_ = os.RemoveAll(stagingDir)
	filesRoot := filepath.Join(stagingDir, "files")
	if err := os.MkdirAll(filesRoot, 0o755); err != nil {
		return nil, err
	}

	manifest := &CoreManifest{
		Version:  v,
		Locale:   loc,
		SyncedAt: time.Now().UTC(),
		Files:    make(map[string]CoreFileHash),
	}

	err = filepath.WalkDir(cleanSourceDir, func(curPath string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relOS, rErr := filepath.Rel(cleanSourceDir, curPath)
		if rErr != nil || relOS == "." {
			return rErr
		}
		relPosix := filepath.ToSlash(relOS)

		// Skip user-mutable directories and runtime config files
		if relPosix == "wp-content" || strings.HasPrefix(relPosix, "wp-content/") ||
			relPosix == "wp-config.php" || relPosix == ".htaccess" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		raw, readErr := os.ReadFile(curPath)
		if readErr != nil {
			return readErr
		}
		md5Sum := md5.Sum(raw)
		shaSum := sha256.Sum256(raw)

		destPath := filepath.Join(filesRoot, filepath.FromSlash(relPosix))
		if mkErr := os.MkdirAll(filepath.Dir(destPath), 0o755); mkErr != nil {
			return mkErr
		}
		if wErr := os.WriteFile(destPath, raw, 0o644); wErr != nil {
			return wErr
		}

		manifest.Files[relPosix] = CoreFileHash{
			MD5:    hex.EncodeToString(md5Sum[:]),
			SHA256: hex.EncodeToString(shaSum[:]),
			Size:   int64(len(raw)),
		}
		return nil
	})
	if err != nil {
		_ = os.RemoveAll(stagingDir)
		return nil, err
	}
	if len(manifest.Files) == 0 {
		_ = os.RemoveAll(stagingDir)
		return nil, errors.New("clean source tree contained zero WordPress core files")
	}

	if err := c.commitStagingRelease(v, loc, stagingDir, relDir, manifest); err != nil {
		_ = os.RemoveAll(stagingDir)
		return nil, err
	}
	return manifest, nil
}

func (c *CoreCache) fetchOfficialChecksums(ctx context.Context, version, locale string) (map[string]string, string, error) {
	out, err := c.queryChecksumsOnce(ctx, version, locale)
	if err == nil && len(out) > 0 {
		return out, locale, nil
	}
	if locale != "en_US" {
		fallback, fbErr := c.queryChecksumsOnce(ctx, version, "en_US")
		if fbErr == nil && len(fallback) > 0 {
			return fallback, "en_US", nil
		}
	}
	if err != nil {
		return nil, locale, err
	}
	return nil, locale, fmt.Errorf("wordpress.org returned empty checksum set for %s (%s)", version, locale)
}

func (c *CoreCache) queryChecksumsOnce(ctx context.Context, version, locale string) (map[string]string, error) {
	u, err := url.Parse(c.ChecksumsAPIBase)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("version", version)
	q.Set("locale", locale)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums API HTTP %d", resp.StatusCode)
	}

	var envelope struct {
		Checksums json.RawMessage `json:"checksums"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&envelope); err != nil {
		return nil, err
	}
	// Note: api.wordpress.org returns `"checksums": false` when version/locale does not exist
	var parsed map[string]string
	if err := json.Unmarshal(envelope.Checksums, &parsed); err != nil {
		return nil, nil
	}
	filtered := make(map[string]string, len(parsed))
	for relPath, md5Hex := range parsed {
		clean := strings.TrimPrefix(path.Clean(strings.ReplaceAll(relPath, "\\", "/")), "/")
		if clean == "" || clean == "." || strings.HasPrefix(clean, "../") {
			continue
		}
		if clean == "wp-content" || strings.HasPrefix(clean, "wp-content/") {
			continue
		}
		filtered[clean] = strings.ToLower(strings.TrimSpace(md5Hex))
	}
	return filtered, nil
}

func (c *CoreCache) candidateTarballURLs(version, locale string) []string {
	base := strings.TrimRight(c.DownloadBaseURL, "/")
	var urls []string
	if locale != "" && locale != "en_US" {
		if c.DownloadBaseURL == DefaultDownloadBaseURL {
			urls = append(urls,
				"https://downloads.wordpress.org/release/"+locale+"/wordpress-"+version+".tar.gz",
			)
		} else {
			urls = append(urls, base+"/release/"+locale+"/wordpress-"+version+".tar.gz")
		}
	}
	urls = append(urls, base+"/wordpress-"+version+".tar.gz")
	return urls
}

func (c *CoreCache) downloadCoreTarballStream(ctx context.Context, version, locale string) (io.ReadCloser, error) {
	candidates := c.candidateTarballURLs(version, locale)
	var lastErr error
	for _, tarURL := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("download WordPress core %s (%s) HTTP %d", version, locale, resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("download WordPress core %s failed", version)
	}
	return nil, lastErr
}

func (c *CoreCache) downloadAndVerifyTarball(ctx context.Context, version, locale string, expectedMD5 map[string]string) (*CoreManifest, error) {
	bodyStream, err := c.downloadCoreTarballStream(ctx, version, locale)
	if err != nil {
		return nil, err
	}
	defer bodyStream.Close()

	gz, err := gzip.NewReader(io.LimitReader(bodyStream, maxCoreArchiveBytes))
	if err != nil {
		return nil, fmt.Errorf("open core tar.gz stream: %w", err)
	}
	defer gz.Close()

	relDir := c.releaseDir(version, locale)
	stagingDir := relDir + ".staging"
	_ = os.RemoveAll(stagingDir)
	filesRoot := filepath.Join(stagingDir, "files")
	if err := os.MkdirAll(filesRoot, 0o755); err != nil {
		return nil, err
	}

	manifest := &CoreManifest{
		Version:  version,
		Locale:   locale,
		SyncedAt: time.Now().UTC(),
		Files:    make(map[string]CoreFileHash, len(expectedMD5)),
	}

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = os.RemoveAll(stagingDir)
			return nil, fmt.Errorf("read core tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rawName := strings.TrimPrefix(strings.ReplaceAll(hdr.Name, "\\", "/"), "/")
		rawName = strings.TrimPrefix(rawName, "wordpress/")
		normRel, nErr := normalizeCoreRelPath(rawName)
		if nErr != nil {
			continue
		}
		if normRel == "wp-content" || strings.HasPrefix(normRel, "wp-content/") {
			continue
		}
		wantMD5, tracked := expectedMD5[normRel]
		if !tracked {
			continue
		}
		if hdr.Size > maxSingleCoreFileBytes {
			_ = os.RemoveAll(stagingDir)
			return nil, fmt.Errorf("core file %s exceeds safety limit (%d bytes)", normRel, hdr.Size)
		}

		data, rErr := io.ReadAll(io.LimitReader(tr, maxSingleCoreFileBytes+1))
		if rErr != nil {
			_ = os.RemoveAll(stagingDir)
			return nil, rErr
		}
		gotMD5Sum := md5.Sum(data)
		gotMD5 := hex.EncodeToString(gotMD5Sum[:])
		if gotMD5 != wantMD5 {
			_ = os.RemoveAll(stagingDir)
			return nil, fmt.Errorf("official MD5 checksum mismatch on %s: expected %s, got %s", normRel, wantMD5, gotMD5)
		}
		gotSHA := sha256.Sum256(data)

		destPath := filepath.Join(filesRoot, filepath.FromSlash(normRel))
		if mkErr := os.MkdirAll(filepath.Dir(destPath), 0o755); mkErr != nil {
			_ = os.RemoveAll(stagingDir)
			return nil, mkErr
		}
		if wErr := os.WriteFile(destPath, data, 0o644); wErr != nil {
			_ = os.RemoveAll(stagingDir)
			return nil, wErr
		}

		manifest.Files[normRel] = CoreFileHash{
			MD5:    gotMD5,
			SHA256: hex.EncodeToString(gotSHA[:]),
			Size:   int64(len(data)),
		}
	}

	if len(manifest.Files) == 0 {
		_ = os.RemoveAll(stagingDir)
		return nil, fmt.Errorf("tarball for WordPress %s matched zero verified core files", version)
	}

	// Verify all expected core files were present in tarball
	for rel := range expectedMD5 {
		if _, ok := manifest.Files[rel]; !ok {
			_ = os.RemoveAll(stagingDir)
			return nil, fmt.Errorf("incomplete core archive: missing verified file %s", rel)
		}
	}

	if err := c.commitStagingRelease(version, locale, stagingDir, relDir, manifest); err != nil {
		_ = os.RemoveAll(stagingDir)
		return nil, err
	}
	return manifest, nil
}

func (c *CoreCache) commitStagingRelease(version, locale, stagingDir, finalDir string, manifest *CoreManifest) error {
	if err := os.MkdirAll(c.BaseDir, 0o755); err != nil {
		return err
	}
	rawManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stagingDir, "manifest.json"), append(rawManifest, '\n'), 0o600); err != nil {
		return err
	}
	_ = os.RemoveAll(finalDir)
	if err := os.Rename(stagingDir, finalDir); err != nil {
		return err
	}

	c.mu.Lock()
	c.manifests[releaseKey(version, locale)] = manifest
	c.mu.Unlock()
	return nil
}

// Status inspects /var/cache/da-wptoolkit/wp-core/ and reports cached releases and disk usage.
func (c *CoreCache) Status() CacheStatus {
	st := CacheStatus{
		BaseDir:  c.BaseDir,
		Releases: []CachedReleaseInfo{},
	}
	entries, err := os.ReadDir(c.BaseDir)
	if err != nil {
		return st
	}
	for _, ent := range entries {
		if !ent.IsDir() || strings.HasSuffix(ent.Name(), ".staging") {
			continue
		}
		mPath := filepath.Join(c.BaseDir, ent.Name(), "manifest.json")
		raw, rErr := os.ReadFile(mPath)
		if rErr != nil {
			continue
		}
		var m CoreManifest
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		var size int64
		for _, fh := range m.Files {
			size += fh.Size
		}
		st.TotalBytes += size
		st.Releases = append(st.Releases, CachedReleaseInfo{
			Key:       ent.Name(),
			Version:   m.Version,
			Locale:    m.Locale,
			FileCount: len(m.Files),
			SizeBytes: size,
			SyncedAt:  m.SyncedAt,
		})
	}
	sort.Slice(st.Releases, func(i, j int) bool {
		return st.Releases[i].Key < st.Releases[j].Key
	})
	return st
}

// DeleteCachedRelease removes a cached WordPress Core (version, locale) tree from disk and memory.
func (c *CoreCache) DeleteCachedRelease(version, locale string) error {
	v, loc, err := normalizeVersionAndLocale(version, locale)
	if err != nil {
		return err
	}
	key := releaseKey(v, loc)
	dir := c.releaseDir(v, loc)
	if info, lErr := os.Lstat(dir); lErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to remove symlinked core cache directory %s", dir)
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.manifests, key)
	c.mu.Unlock()
	return nil
}

func normalizeCoreRelPath(rel string) (string, error) {
	s := strings.TrimSpace(strings.ReplaceAll(rel, "\\", "/"))
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimPrefix(s, "/")
	if s == "" || s == "." {
		return "", errors.New("empty relative core path")
	}
	cleaned := path.Clean(s)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "\x00") {
		return "", fmt.Errorf("invalid relative core path %q", rel)
	}
	return cleaned, nil
}
