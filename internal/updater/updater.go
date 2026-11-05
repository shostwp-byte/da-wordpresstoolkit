package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/ipc"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/version"
)

const (
	DefaultBinPath        = "/usr/local/sbin/da-wptoolkit"
	DefaultPluginDir      = "/usr/local/directadmin/plugins/da_wp_toolkits"
	DefaultHooksBaseDir   = "/usr/local/directadmin/scripts/custom"
	DefaultShareDir       = "/usr/local/share/da-wptoolkit"
	DefaultServiceName    = "da-wptoolkitd"
	maxArchiveDownloadLen = 128 * 1024 * 1024 // 128 MB hard cap
	maxExtractedBytes     = 256 * 1024 * 1024 // 256 MB anti-zipbomb cap
)

// ReleaseInfo describes the latest matching GitHub Release and its downloadable signed assets.
type ReleaseInfo struct {
	CurrentVersion       string `json:"current_version"`
	LatestVersion        string `json:"latest_version"`
	ReleaseTitle         string `json:"release_title,omitempty"`
	Prerelease           bool   `json:"prerelease"`
	PublishedAt          string `json:"published_at,omitempty"`
	HTMLURL              string `json:"html_url,omitempty"`
	Changelog            string `json:"changelog,omitempty"`
	UpdateAvailable      bool   `json:"update_available"`
	UpdateChannel        string `json:"update_channel"`
	TargetArch           string `json:"target_arch"`
	TarballAssetName     string `json:"tarball_asset_name,omitempty"`
	TarballDownloadURL   string `json:"-"`
	ChecksumsDownloadURL string `json:"-"`
	SignatureDownloadURL string `json:"-"`
	UseAPIStreamHeader   bool   `json:"-"`
}

// BackupEntry represents a rollback snapshot of the daemon binary and DirectAdmin plugin UI.
type BackupEntry struct {
	FileName  string    `json:"file_name"`
	FilePath  string    `json:"file_path"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
}

// UpdateOutcome records the result of an atomic self-update or auto-rollback operation (TC-10).
type UpdateOutcome struct {
	PreviousVersion string    `json:"previous_version"`
	TargetVersion   string    `json:"target_version"`
	BackupPath      string    `json:"backup_path"`
	RolledBack      bool      `json:"rolled_back"`
	FaultReason     string    `json:"fault_reason,omitempty"`
	ElapsedMs       int64     `json:"elapsed_ms"`
	Detached        bool      `json:"detached"`
	UnitName        string    `json:"unit_name,omitempty"`
	CompletedAt     time.Time `json:"completed_at"`
}

type backupMeta struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

type ghAssetDTO struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type ghReleaseDTO struct {
	TagName     string       `json:"tag_name"`
	Name        string       `json:"name"`
	Draft       bool         `json:"draft"`
	Prerelease  bool         `json:"prerelease"`
	PublishedAt string       `json:"published_at"`
	HTMLURL     string       `json:"html_url"`
	Body        string       `json:"body"`
	Assets      []ghAssetDTO `json:"assets"`
}

// Manager orchestrates Ed25519-verified GitHub self-updates, snapshot backups, and instant/auto rollback.
type Manager struct {
	StateDir       string
	BinPath        string
	PluginDir      string
	HooksBaseDir   string
	ShareDir       string
	AdminSockPath  string
	ServiceName    string
	GitHubRepo     string
	PublicKeyHex   string
	APIBaseURL     string
	TargetArch     string
	CurrentVersion string
	Store          *store.Store
	HTTPClient     *http.Client

	RestartDaemon    func(ctx context.Context) error
	HealthCheck      func(ctx context.Context) error
	DetachedLauncher func(ctx context.Context, stagedDir, backupPath, targetVersion string) (string, error)
}

// NewManager creates an Ed25519 self-updater configured with production DirectAdmin defaults.
func NewManager(stateDir string, st *store.Store) *Manager {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = store.DefaultStateDir
	}
	m := &Manager{
		StateDir:       stateDir,
		BinPath:        DefaultBinPath,
		PluginDir:      DefaultPluginDir,
		HooksBaseDir:   DefaultHooksBaseDir,
		ShareDir:       DefaultShareDir,
		AdminSockPath:  ipc.DefaultAdminSocketPath,
		ServiceName:    DefaultServiceName,
		GitHubRepo:     version.DefaultGitHubRepo,
		PublicKeyHex:   version.DefaultReleasePublicKeyHex,
		APIBaseURL:     "https://api.github.com",
		TargetArch:     runtime.GOARCH,
		CurrentVersion: version.Version,
		Store:          st,
		HTTPClient:     &http.Client{Timeout: 60 * time.Second},
	}
	m.RestartDaemon = m.defaultRestartDaemon
	m.HealthCheck = m.defaultHealthCheck
	m.DetachedLauncher = m.defaultDetachedLauncher
	return m
}

func (m *Manager) backupsDir() string {
	return filepath.Join(m.StateDir, "backups")
}

func (m *Manager) stagingRootDir() string {
	return filepath.Join(m.StateDir, "updater", "staging")
}

func (m *Manager) outcomeFilePath() string {
	return filepath.Join(m.StateDir, "updater", "last_outcome.json")
}

// LastOutcome returns the most recent completed update or auto-rollback record, if any.
func (m *Manager) LastOutcome() *UpdateOutcome {
	raw, err := os.ReadFile(m.outcomeFilePath())
	if err != nil {
		return nil
	}
	var out UpdateOutcome
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return &out
}

func (m *Manager) saveOutcome(out UpdateOutcome) {
	_ = os.MkdirAll(filepath.Dir(m.outcomeFilePath()), 0o700)
	if raw, err := json.MarshalIndent(out, "", "  "); err == nil {
		_ = writeFileAtomic(m.outcomeFilePath(), raw, 0o600)
	}
}

func (m *Manager) recordSecurityEvent(severity, msg string) {
	if m.Store == nil {
		return
	}
	m.Store.RecordSecurityEvent(store.SecurityAuditEvent{
		Severity: severity,
		Category: "self_updater",
		Owner:    "root",
		Message:  msg,
	})
}

// CheckLatest queries GitHub Releases API and resolves the latest release and signed asset URLs.
func (m *Manager) CheckLatest(ctx context.Context, cfg config.UpdaterConfig, requestedTag string) (ReleaseInfo, error) {
	arch := strings.TrimSpace(m.TargetArch)
	if arch == "" {
		arch = runtime.GOARCH
	}
	curVer := strings.TrimSpace(m.CurrentVersion)
	if curVer == "" {
		curVer = version.Version
	}
	ch := strings.TrimSpace(cfg.UpdateChannel)
	if ch == "" {
		ch = config.DefaultChannelStable
	}

	baseURL := strings.TrimRight(strings.TrimSpace(m.APIBaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	repo := strings.TrimSpace(m.GitHubRepo)
	if repo == "" {
		repo = version.DefaultGitHubRepo
	}

	endpoint := fmt.Sprintf("%s/repos/%s/releases?per_page=15", baseURL, repo)
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ReleaseInfo{}, err
	}
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("User-Agent", "DA-WordPressToolkits/"+curVer)
	if cfg.GitHubToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+cfg.GitHubToken)
	}

	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("GitHub API connection error: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode == http.StatusNotFound {
		return ReleaseInfo{
			CurrentVersion:  curVer,
			LatestVersion:   curVer,
			UpdateAvailable: false,
			UpdateChannel:   ch,
			TargetArch:      arch,
			Changelog:       "Chưa có bản phát hành công khai nào trên kho lưu trữ GitHub.",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return ReleaseInfo{}, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	var releases []ghReleaseDTO
	if err := json.Unmarshal(raw, &releases); err != nil {
		return ReleaseInfo{}, fmt.Errorf("invalid GitHub Releases JSON: %w", err)
	}

	wantTag := strings.TrimSpace(requestedTag)
	var chosen *ghReleaseDTO
	for i := range releases {
		r := &releases[i]
		if r.Draft || strings.TrimSpace(r.TagName) == "" {
			continue
		}
		if wantTag != "" {
			if strings.EqualFold(strings.TrimSpace(r.TagName), wantTag) || strings.EqualFold("v"+strings.TrimPrefix(wantTag, "v"), r.TagName) {
				chosen = r
				break
			}
			continue
		}
		if r.Prerelease && ch != config.DefaultChannelBeta {
			continue
		}
		chosen = r
		break
	}

	if chosen == nil {
		if wantTag != "" {
			return ReleaseInfo{}, fmt.Errorf("release tag %q not found on %s", wantTag, repo)
		}
		return ReleaseInfo{
			CurrentVersion:  curVer,
			LatestVersion:   curVer,
			UpdateAvailable: false,
			UpdateChannel:   ch,
			TargetArch:      arch,
			Changelog:       "Không tìm thấy bản phát hành phù hợp với kênh " + ch + ".",
		}, nil
	}

	tarballName := fmt.Sprintf("da-wptoolkit-linux-%s.tar.gz", arch)
	info := ReleaseInfo{
		CurrentVersion:   curVer,
		LatestVersion:    chosen.TagName,
		ReleaseTitle:     chosen.Name,
		Prerelease:       chosen.Prerelease,
		PublishedAt:      chosen.PublishedAt,
		HTMLURL:          chosen.HTMLURL,
		Changelog:        chosen.Body,
		UpdateAvailable:  CompareSemVer(chosen.TagName, curVer) > 0,
		UpdateChannel:    ch,
		TargetArch:       arch,
		TarballAssetName: tarballName,
	}

	useAPIStream := cfg.GitHubToken != ""
	info.UseAPIStreamHeader = useAPIStream
	for _, a := range chosen.Assets {
		dlURL := a.BrowserDownloadURL
		if useAPIStream && a.URL != "" {
			dlURL = a.URL
		} else if dlURL == "" {
			dlURL = a.URL
		}
		switch a.Name {
		case tarballName:
			info.TarballDownloadURL = dlURL
		case "checksums.txt":
			info.ChecksumsDownloadURL = dlURL
		case "checksums.txt.sig":
			info.SignatureDownloadURL = dlURL
		}
	}
	return info, nil
}

// StageAndVerifyRelease downloads checksums.txt + checksums.txt.sig, verifies the Ed25519 signature,
// downloads da-wptoolkit-linux-<arch>.tar.gz while verifying its SHA-256 digest, and extracts it safely.
func (m *Manager) StageAndVerifyRelease(ctx context.Context, cfg config.UpdaterConfig, rel ReleaseInfo) (string, error) {
	if rel.ChecksumsDownloadURL == "" || rel.SignatureDownloadURL == "" || rel.TarballDownloadURL == "" {
		return "", fmt.Errorf("release %s is missing signed release assets (%s, checksums.txt, checksums.txt.sig)", rel.LatestVersion, rel.TarballAssetName)
	}

	safeTag := sanitizeTagForFilename(rel.LatestVersion)
	stageDir := filepath.Join(m.stagingRootDir(), safeTag)
	_ = os.RemoveAll(stageDir)
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return "", err
	}

	cleanupOnErr := true
	defer func() {
		if cleanupOnErr {
			_ = os.RemoveAll(stageDir)
		}
	}()

	checksumsBytes, err := m.downloadSmallBytes(ctx, rel.ChecksumsDownloadURL, cfg.GitHubToken, rel.UseAPIStreamHeader, 512*1024)
	if err != nil {
		return "", fmt.Errorf("download checksums.txt: %w", err)
	}
	sigBytes, err := m.downloadSmallBytes(ctx, rel.SignatureDownloadURL, cfg.GitHubToken, rel.UseAPIStreamHeader, 16*1024)
	if err != nil {
		return "", fmt.Errorf("download checksums.txt.sig: %w", err)
	}

	digests, err := VerifyChecksumsSignature(checksumsBytes, sigBytes, m.PublicKeyHex)
	if err != nil {
		m.recordSecurityEvent("critical", fmt.Sprintf("Blocked GitHub update %s: %v", rel.LatestVersion, err))
		return "", err
	}

	expectedSHA256, ok := digests[rel.TarballAssetName]
	if !ok {
		m.recordSecurityEvent("critical", fmt.Sprintf("Blocked GitHub update %s: %s missing from signed checksums.txt", rel.LatestVersion, rel.TarballAssetName))
		return "", fmt.Errorf("%w: %s", ErrMissingChecksum, rel.TarballAssetName)
	}

	tarballPath := filepath.Join(stageDir, rel.TarballAssetName)
	actualSHA256, err := m.downloadAndHashFile(ctx, rel.TarballDownloadURL, cfg.GitHubToken, rel.UseAPIStreamHeader, tarballPath)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", rel.TarballAssetName, err)
	}
	if !constantTimeHexEqual(actualSHA256, expectedSHA256) {
		m.recordSecurityEvent("critical", fmt.Sprintf("Blocked GitHub update %s: SHA-256 mismatch for %s (got %s, expected %s)", rel.LatestVersion, rel.TarballAssetName, actualSHA256, expectedSHA256))
		return "", fmt.Errorf("%w: got %s, expected %s", ErrChecksumMismatch, actualSHA256, expectedSHA256)
	}

	payloadDir := filepath.Join(stageDir, "payload")
	if err := extractTarGzSafe(tarballPath, payloadDir); err != nil {
		return "", fmt.Errorf("extract verified release archive: %w", err)
	}
	_ = os.Remove(tarballPath)

	stagedBin := filepath.Join(payloadDir, "bin", "da-wptoolkit")
	st, err := os.Stat(stagedBin)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1024 {
		return "", errors.New("verified release archive does not contain valid bin/da-wptoolkit binary")
	}

	cleanupOnErr = false
	return payloadDir, nil
}

// CreateBackup snapshots the currently installed binary and DirectAdmin plugin UI (excluding live data/)
// into <StateDir>/backups/backup_<timestamp>_<ver>.tar.gz and rotates old backups per retention.
func (m *Manager) CreateBackup(retention int) (BackupEntry, error) {
	if retention <= 0 {
		retention = config.DefaultBackupRetention
	}
	if err := os.MkdirAll(m.backupsDir(), 0o700); err != nil {
		return BackupEntry{}, err
	}

	now := time.Now().UTC()
	curVer := strings.TrimSpace(m.CurrentVersion)
	if curVer == "" {
		curVer = version.Version
	}
	fileName := fmt.Sprintf("backup_%s_%s.tar.gz", now.Format("20060102T150405Z"), sanitizeTagForFilename(curVer))
	outPath := filepath.Join(m.backupsDir(), fileName)
	tmpPath := outPath + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return BackupEntry{}, err
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	writeErr := func() error {
		metaBytes, _ := json.Marshal(backupMeta{Version: curVer, CreatedAt: now})
		if err := addTarBytes(tw, "backup_meta.json", metaBytes, 0o600, now); err != nil {
			return err
		}
		if info, sErr := os.Lstat(m.BinPath); sErr == nil && info.Mode().IsRegular() {
			if err := addTarFileFromDisk(tw, m.BinPath, "bin/da-wptoolkit", 0o755); err != nil {
				return err
			}
		}
		if info, sErr := os.Lstat(m.PluginDir); sErr == nil && info.IsDir() {
			err := filepath.WalkDir(m.PluginDir, func(p string, d os.DirEntry, wErr error) error {
				if wErr != nil {
					return wErr
				}
				rel, rErr := filepath.Rel(m.PluginDir, p)
				if rErr != nil || rel == "." {
					return rErr
				}
				relSlash := filepath.ToSlash(rel)
				// Never overwrite live policy configurations in plugin/data/ during rollback!
				if relSlash == "data" || strings.HasPrefix(relSlash, "data/") {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if d.Type()&os.ModeSymlink != 0 {
					return nil
				}
				if d.IsDir() {
					return tw.WriteHeader(&tar.Header{
						Name:     "plugin/" + relSlash + "/",
						Typeflag: tar.TypeDir,
						Mode:     0o755,
						ModTime:  now,
					})
				}
				if d.Type().IsRegular() {
					fi, iErr := d.Info()
					mode := int64(0o644)
					if iErr == nil && (fi.Mode().Perm()&0o111 != 0 || strings.HasSuffix(relSlash, ".raw") || strings.HasSuffix(relSlash, "index.html") || strings.HasSuffix(relSlash, ".sh")) {
						mode = 0o755
					}
					return addTarFileFromDisk(tw, p, "plugin/"+relSlash, mode)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	}()

	closeTwErr := tw.Close()
	closeGwErr := gw.Close()
	closeFErr := f.Close()
	if writeErr != nil || closeTwErr != nil || closeGwErr != nil || closeFErr != nil {
		_ = os.Remove(tmpPath)
		if writeErr != nil {
			return BackupEntry{}, writeErr
		}
		return BackupEntry{}, errors.New("failed finalizing rollback backup archive")
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return BackupEntry{}, err
	}

	sum, _ := sha256FileHex(outPath)
	st, _ := os.Stat(outPath)
	var size int64
	if st != nil {
		size = st.Size()
	}

	m.pruneBackups(retention)
	return BackupEntry{
		FileName:  fileName,
		FilePath:  outPath,
		Version:   curVer,
		CreatedAt: now,
		SizeBytes: size,
		SHA256:    sum,
	}, nil
}

func (m *Manager) pruneBackups(retention int) {
	list, err := m.ListBackups()
	if err != nil || len(list) <= retention {
		return
	}
	for _, old := range list[retention:] {
		_ = os.Remove(old.FilePath)
	}
}

// ListBackups returns available rollback snapshot archives sorted newest-first.
func (m *Manager) ListBackups() ([]BackupEntry, error) {
	entries, err := os.ReadDir(m.backupsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []BackupEntry{}, nil
		}
		return nil, err
	}

	var out []BackupEntry
	for _, ent := range entries {
		if ent.IsDir() || !ent.Type().IsRegular() {
			continue
		}
		name := ent.Name()
		if !strings.HasPrefix(name, "backup_") || !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		fullPath := filepath.Join(m.backupsDir(), name)
		fi, iErr := ent.Info()
		if iErr != nil {
			continue
		}
		meta := readBackupMeta(fullPath)
		createdAt := fi.ModTime().UTC()
		if !meta.CreatedAt.IsZero() {
			createdAt = meta.CreatedAt
		}
		ver := meta.Version
		if ver == "" {
			ver = inferVersionFromBackupName(name)
		}
		sum, _ := sha256FileHex(fullPath)
		out = append(out, BackupEntry{
			FileName:  name,
			FilePath:  fullPath,
			Version:   ver,
			CreatedAt: createdAt,
			SizeBytes: fi.Size(),
			SHA256:    sum,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// RestoreBackup restores the daemon binary and DirectAdmin plugin UI from a snapshot backup
// while strictly preserving <StateDir> Registry files and plugin/data/ policies.
func (m *Manager) RestoreBackup(ctx context.Context, backupRef string, restartAndVerify bool) (BackupEntry, error) {
	list, err := m.ListBackups()
	if err != nil {
		return BackupEntry{}, err
	}
	if len(list) == 0 {
		return BackupEntry{}, errors.New("no rollback snapshot backups available")
	}

	var chosen *BackupEntry
	ref := strings.TrimSpace(backupRef)
	if ref == "" {
		chosen = &list[0]
	} else {
		baseRef := filepath.Base(ref)
		for i := range list {
			if list[i].FileName == baseRef || filepath.Clean(list[i].FilePath) == filepath.Clean(ref) {
				chosen = &list[i]
				break
			}
		}
		if chosen == nil {
			return BackupEntry{}, fmt.Errorf("rollback snapshot %q not found in %s", ref, m.backupsDir())
		}
	}

	tmpDir, err := os.MkdirTemp(m.backupsDir(), ".restore_*")
	if err != nil {
		return *chosen, err
	}
	defer os.RemoveAll(tmpDir)

	if err := extractTarGzSafe(chosen.FilePath, tmpDir); err != nil {
		return *chosen, fmt.Errorf("extract rollback backup: %w", err)
	}

	if err := m.installExtractedPayload(tmpDir, false); err != nil {
		return *chosen, fmt.Errorf("apply rollback files: %w", err)
	}

	if restartAndVerify {
		if m.RestartDaemon != nil {
			if rErr := m.RestartDaemon(ctx); rErr != nil {
				return *chosen, fmt.Errorf("restart daemon after rollback: %w", rErr)
			}
		}
		if m.HealthCheck != nil {
			if hErr := m.HealthCheck(ctx); hErr != nil {
				return *chosen, fmt.Errorf("daemon healthcheck after rollback failed: %w", hErr)
			}
		}
	}

	m.recordSecurityEvent("info", fmt.Sprintf("Restored rollback snapshot %s (%s)", chosen.FileName, chosen.Version))
	return *chosen, nil
}

// ApplyStagedWithAutoRollback atomically swaps the verified release payload into place, restarts the daemon,
// runs healthcheck, and automatically rolls back to backupPath within seconds if startup or healthcheck fails (TC-10).
func (m *Manager) ApplyStagedWithAutoRollback(ctx context.Context, stagedPayloadDir string, backupPath string, targetVersion string) (UpdateOutcome, error) {
	start := time.Now()
	curVer := strings.TrimSpace(m.CurrentVersion)
	if curVer == "" {
		curVer = version.Version
	}

	outcome := UpdateOutcome{
		PreviousVersion: curVer,
		TargetVersion:   targetVersion,
		BackupPath:      backupPath,
	}

	applyErr := m.installExtractedPayload(stagedPayloadDir, true)
	if applyErr == nil && m.RestartDaemon != nil {
		applyErr = m.RestartDaemon(ctx)
	}
	if applyErr == nil && m.HealthCheck != nil {
		applyErr = m.HealthCheck(ctx)
	}

	if applyErr != nil {
		outcome.RolledBack = true
		outcome.FaultReason = applyErr.Error()
		m.recordSecurityEvent("warning", fmt.Sprintf("Self-update to %s failed healthcheck (%v) — triggering automatic rollback from %s", targetVersion, applyErr, filepath.Base(backupPath)))

		_, rbErr := m.RestoreBackup(ctx, backupPath, true)
		outcome.ElapsedMs = time.Since(start).Milliseconds()
		outcome.CompletedAt = time.Now().UTC()
		m.saveOutcome(outcome)
		if rbErr != nil {
			return outcome, fmt.Errorf("update to %s failed (%v) AND auto-rollback encountered error: %w", targetVersion, applyErr, rbErr)
		}
		return outcome, fmt.Errorf("update to %s failed healthcheck (%v); automatically rolled back to %s in %dms", targetVersion, applyErr, curVer, outcome.ElapsedMs)
	}

	_ = os.RemoveAll(filepath.Dir(stagedPayloadDir))
	outcome.ElapsedMs = time.Since(start).Milliseconds()
	outcome.CompletedAt = time.Now().UTC()
	m.saveOutcome(outcome)
	m.recordSecurityEvent("info", fmt.Sprintf("Successfully updated DA-WordPressToolkits %s -> %s (%dms)", curVer, targetVersion, outcome.ElapsedMs))
	return outcome, nil
}

// PerformUpdate runs the full Ed25519 self-update flow: Check -> Verify & Stage -> Backup -> Apply (detached or sync).
func (m *Manager) PerformUpdate(ctx context.Context, cfg config.UpdaterConfig, requestedTag string, force bool, detached bool) (UpdateOutcome, error) {
	rel, err := m.CheckLatest(ctx, cfg, requestedTag)
	if err != nil {
		return UpdateOutcome{}, err
	}
	if !rel.UpdateAvailable && !force && strings.TrimSpace(requestedTag) == "" {
		return UpdateOutcome{
			PreviousVersion: rel.CurrentVersion,
			TargetVersion:   rel.LatestVersion,
			CompletedAt:     time.Now().UTC(),
		}, fmt.Errorf("already running latest version (%s)", rel.CurrentVersion)
	}

	stagedPayloadDir, err := m.StageAndVerifyRelease(ctx, cfg, rel)
	if err != nil {
		return UpdateOutcome{}, err
	}

	bkp, err := m.CreateBackup(cfg.BackupRetention)
	if err != nil {
		_ = os.RemoveAll(filepath.Dir(stagedPayloadDir))
		return UpdateOutcome{}, fmt.Errorf("create pre-update backup: %w", err)
	}

	if detached && m.DetachedLauncher != nil {
		unitName, lErr := m.DetachedLauncher(ctx, stagedPayloadDir, bkp.FilePath, rel.LatestVersion)
		if lErr != nil {
			return UpdateOutcome{}, lErr
		}
		return UpdateOutcome{
			PreviousVersion: rel.CurrentVersion,
			TargetVersion:   rel.LatestVersion,
			BackupPath:      bkp.FilePath,
			Detached:        true,
			UnitName:        unitName,
			CompletedAt:     time.Now().UTC(),
		}, nil
	}

	return m.ApplyStagedWithAutoRollback(ctx, stagedPayloadDir, bkp.FilePath, rel.LatestVersion)
}

func (m *Manager) installExtractedPayload(payloadDir string, includeHooksAndScripts bool) error {
	srcBin := filepath.Join(payloadDir, "bin", "da-wptoolkit")
	if info, err := os.Lstat(srcBin); err == nil && info.Mode().IsRegular() {
		if err := copyFileAtomic(srcBin, m.BinPath, 0o755); err != nil {
			return fmt.Errorf("atomic swap binary %s: %w", m.BinPath, err)
		}
	}

	srcPlugin := filepath.Join(payloadDir, "plugin")
	if info, err := os.Lstat(srcPlugin); err == nil && info.IsDir() && strings.TrimSpace(m.PluginDir) != "" {
		if err := syncDirPreservingSubdir(srcPlugin, m.PluginDir, "data"); err != nil {
			return fmt.Errorf("sync plugin directory: %w", err)
		}
	}

	if !includeHooksAndScripts {
		return nil
	}

	srcHooks := filepath.Join(payloadDir, "scripts", "da_hooks")
	if info, err := os.Lstat(srcHooks); err == nil && info.IsDir() && strings.TrimSpace(m.HooksBaseDir) != "" {
		entries, _ := os.ReadDir(srcHooks)
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".sh") {
				continue
			}
			hookName := strings.TrimSuffix(ent.Name(), ".sh")
			dstHook := filepath.Join(m.HooksBaseDir, hookName, "da_wp_toolkits.sh")
			if err := copyFileAtomic(filepath.Join(srcHooks, ent.Name()), dstHook, 0o700); err != nil {
				return fmt.Errorf("install hook %s: %w", hookName, err)
			}
		}
	}

	srcUpdateSh := filepath.Join(payloadDir, "scripts", "update.sh")
	if info, err := os.Lstat(srcUpdateSh); err == nil && info.Mode().IsRegular() && strings.TrimSpace(m.ShareDir) != "" {
		dstUpdateSh := filepath.Join(m.ShareDir, "scripts", "update.sh")
		_ = copyFileAtomic(srcUpdateSh, dstUpdateSh, 0o700)
	}
	return nil
}

func (m *Manager) defaultRestartDaemon(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	svc := strings.TrimSpace(m.ServiceName)
	if svc == "" {
		svc = DefaultServiceName
	}
	cmd := exec.CommandContext(ctx, "systemctl", "restart", svc)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s failed: %w (%s)", svc, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) defaultHealthCheck(ctx context.Context) error {
	deadline := time.Now().Add(8 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		cli := ipc.NewClient(m.AdminSockPath)
		cli.Timeout = 1500 * time.Millisecond
		resp, err := cli.Send(ctx, ipc.Request{Action: "ping"})
		if err == nil && resp.OK {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New(resp.Error)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("timeout waiting for daemon ping response")
	}
	return lastErr
}

func (m *Manager) defaultDetachedLauncher(ctx context.Context, stagedDir, backupPath, targetVersion string) (string, error) {
	unitName := fmt.Sprintf("da-wptoolkit-updater-%d", time.Now().Unix())
	scriptPath := filepath.Join(m.ShareDir, "scripts", "update.sh")
	systemdRun, lookErr := exec.LookPath("systemd-run")
	if lookErr == nil {
		var cmdArgs []string
		cmdArgs = append(cmdArgs, "--unit="+unitName, "--collect")
		if info, err := os.Stat(scriptPath); err == nil && info.Mode().IsRegular() {
			cmdArgs = append(cmdArgs, scriptPath, "--staged", stagedDir, "--backup", backupPath, "--target-version", targetVersion)
		} else {
			cmdArgs = append(cmdArgs, m.BinPath, "apply-staged", "--staged", stagedDir, "--backup", backupPath, "--target-version", targetVersion)
		}
		cmd := exec.CommandContext(ctx, systemdRun, cmdArgs...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("systemd-run failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return unitName, nil
	}
	// Fallback when systemd-run is unavailable: run asynchronously in background goroutine
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, _ = m.ApplyStagedWithAutoRollback(bgCtx, stagedDir, backupPath, targetVersion)
	}()
	return unitName, nil
}

func (m *Manager) downloadSmallBytes(ctx context.Context, urlStr, token string, useOctetStream bool, maxBytes int64) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DA-WordPressToolkits/"+version.Version)
	if useOctetStream {
		req.Header.Set("Accept", "application/octet-stream")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from release asset server", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func (m *Manager) downloadAndHashFile(ctx context.Context, urlStr, token string, useOctetStream bool, dstPath string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "DA-WordPressToolkits/"+version.Version)
	if useOctetStream {
		req.Header.Set("Accept", "application/octet-stream")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := m.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d downloading release tarball", resp.StatusCode)
	}

	f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	limited := io.LimitReader(resp.Body, maxArchiveDownloadLen+1)
	written, copyErr := io.Copy(io.MultiWriter(f, h), limited)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(dstPath)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dstPath)
		return "", closeErr
	}
	if written > maxArchiveDownloadLen {
		_ = os.Remove(dstPath)
		return "", errors.New("release archive exceeds 128 MB safety limit")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractTarGzSafe(archivePath, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	cleanDest := filepath.Clean(destDir)

	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		cleanRel := path.Clean(strings.TrimPrefix(filepath.ToSlash(hdr.Name), "/"))
		if cleanRel == "." || cleanRel == "" {
			continue
		}
		if strings.HasPrefix(cleanRel, "../") || cleanRel == ".." || strings.Contains(cleanRel, "/../") {
			return fmt.Errorf("unsafe tar entry path %q", hdr.Name)
		}

		targetPath := filepath.Join(cleanDest, filepath.FromSlash(cleanRel))
		if !strings.HasPrefix(filepath.Clean(targetPath), cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes destination: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 || totalBytes+hdr.Size > maxExtractedBytes {
				return errors.New("extracted archive size exceeds safety limit")
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			perm := os.FileMode(hdr.Mode) & 0o777
			if perm == 0 {
				perm = 0o644
			}
			outF, oErr := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
			if oErr != nil {
				return oErr
			}
			n, cErr := io.Copy(outF, io.LimitReader(tr, hdr.Size+1))
			_ = outF.Close()
			if cErr != nil {
				return cErr
			}
			totalBytes += n
		default:
			return fmt.Errorf("disallowed tar entry type %d for %q (symlinks/devices forbidden)", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}

func syncDirPreservingSubdir(srcDir, dstDir, preserveRel string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(srcDir, func(p string, d os.DirEntry, wErr error) error {
		if wErr != nil {
			return wErr
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil || rel == "." {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if preserveRel != "" && (relSlash == preserveRel || strings.HasPrefix(relSlash, preserveRel+"/")) {
			// Only seed .example files if missing; never overwrite live policy files!
			if d.Type().IsRegular() && strings.HasSuffix(relSlash, ".example") {
				target := filepath.Join(dstDir, rel)
				if _, sErr := os.Stat(target); errors.Is(sErr, os.ErrNotExist) {
					_ = copyFileAtomic(p, target, 0o644)
				}
			}
			return nil
		}
		target := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type().IsRegular() {
			fi, iErr := d.Info()
			perm := os.FileMode(0o644)
			if iErr == nil && (fi.Mode().Perm()&0o111 != 0 || strings.HasSuffix(relSlash, ".raw") || strings.HasSuffix(relSlash, "index.html") || strings.HasSuffix(relSlash, ".sh")) {
				perm = 0o755
			}
			return copyFileAtomic(p, target, perm)
		}
		return nil
	})
}

func copyFileAtomic(srcPath, dstPath string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	if info, err := os.Lstat(dstPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s", dstPath)
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	tmpPath := fmt.Sprintf("%s.tmp.%d", dstPath, time.Now().UnixNano())
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(tmpPath)
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	}
	_ = os.Chmod(tmpPath, perm)
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func writeFileAtomic(dstPath string, data []byte, perm os.FileMode) error {
	tmpPath := fmt.Sprintf("%s.tmp.%d", dstPath, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func addTarBytes(tw *tar.Writer, arcName string, content []byte, mode int64, modTime time.Time) error {
	hdr := &tar.Header{
		Name:     arcName,
		Typeflag: tar.TypeReg,
		Size:     int64(len(content)),
		Mode:     mode,
		ModTime:  modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}

func addTarFileFromDisk(tw *tar.Writer, srcPath, arcName string, mode int64) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := &tar.Header{
		Name:     arcName,
		Typeflag: tar.TypeReg,
		Size:     fi.Size(),
		Mode:     mode,
		ModTime:  fi.ModTime().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func readBackupMeta(archivePath string) backupMeta {
	f, err := os.Open(archivePath)
	if err != nil {
		return backupMeta{}
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return backupMeta{}
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Name == "backup_meta.json" && hdr.Size < 16384 {
			raw, rErr := io.ReadAll(io.LimitReader(tr, 16384))
			if rErr == nil {
				var m backupMeta
				if json.Unmarshal(raw, &m) == nil {
					return m
				}
			}
			break
		}
	}
	return backupMeta{}
}

func sanitizeTagForFilename(tag string) string {
	var b strings.Builder
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

func inferVersionFromBackupName(name string) string {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(name, "backup_"), ".tar.gz")
	if idx := strings.IndexByte(trimmed, '_'); idx >= 0 && idx+1 < len(trimmed) {
		return trimmed[idx+1:]
	}
	return "unknown"
}

// CompareSemVer compares two semantic version tags (e.g. "v1.0.0" vs "v0.6.0").
// Returns 1 if a > b, -1 if a < b, and 0 if equal.
func CompareSemVer(a, b string) int {
	pa, preA := parseSemVer(a)
	pb, preB := parseSemVer(b)
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

func parseSemVer(tag string) ([3]int, string) {
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
