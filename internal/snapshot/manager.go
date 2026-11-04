package snapshot

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	"github.com/shostwp-byte/da-wptoolkits/internal/wpcli"
)

const (
	KindManual    = "manual"
	KindPreSync   = "pre_sync"
	KindPreUpdate = "pre_update"

	SnapshotsSubdirName     = "wp-snapshots"
	archiveMetaEntry        = ".da-wptk-snapshot/metadata.json"
	archiveDatabaseSQLEntry = ".da-wptk-snapshot/database.sql"
	archiveFilesPrefix      = "files/"
	maxDecompressBytes      = 20 * 1024 * 1024 * 1024 // 20 GB archive extraction safety cap
)

// SnapshotRecord stores metadata for a per-instance Zstandard (.tar.zst) snapshot.
type SnapshotRecord struct {
	ID          string    `json:"id"`
	InstanceID  string    `json:"instance_id"`
	Owner       string    `json:"owner"`
	Domain      string    `json:"domain"`
	SubPath     string    `json:"sub_path,omitempty"`
	Note        string    `json:"note,omitempty"`
	Kind        string    `json:"kind"` // manual | pre_sync | pre_update
	WPVersion   string    `json:"wp_version"`
	DBName      string    `json:"db_name"`
	TablePrefix string    `json:"table_prefix"`
	FileName    string    `json:"file_name"`
	SizeBytes   int64     `json:"size_bytes"`
	FileCount   int       `json:"file_count"`
	IncludesDB  bool      `json:"includes_db"`
	CreatedAt   time.Time `json:"created_at"`
}

// CreateRequest configures a new per-instance Zstd snapshot.
type CreateRequest struct {
	InstanceID  string `json:"instance_id"`
	Note        string `json:"note,omitempty"`
	Kind        string `json:"kind,omitempty"`
	IncludeDB   *bool  `json:"include_db,omitempty"` // default true
	AdminBypass bool   `json:"-"`
}

// RestoreResult summarizes a completed 1-Click Snapshot Restore operation.
type RestoreResult struct {
	Snapshot         SnapshotRecord       `json:"snapshot"`
	Instance         store.InstanceRecord `json:"instance"`
	RestoredFiles    int                  `json:"restored_files"`
	DatabaseRestored bool                 `json:"database_restored"`
}

type persistedSnapshotIndex struct {
	SchemaVersion int                       `json:"schema_version"`
	Snapshots     map[string]SnapshotRecord `json:"snapshots"`
}

// Manager manages Zstandard (.tar.zst) per-instance snapshots stored inside the customer's home quota
// (/home/<user>/wp-snapshots/<instance_id>/) with strict Symlink Escape blocking (TC-02) and automatic rotation.
type Manager struct {
	StateDir              string
	Domains               *dadomains.Resolver
	WPCLI                 *wpcli.Runner
	Store                 *store.Store
	Policies              *config.PolicyStore
	ZstdBin               string
	NiceBin               string
	IoniceBin             string
	WithShieldSuppression func(acct dausers.Account, inst store.InstanceRecord, fn func() error) error

	mu        sync.RWMutex
	snapshots map[string]SnapshotRecord
}

func NewManager(
	stateDir string,
	domains *dadomains.Resolver,
	wp *wpcli.Runner,
	st *store.Store,
	policies *config.PolicyStore,
) (*Manager, error) {
	if strings.TrimSpace(stateDir) == "" {
		if st != nil && st.StateDir != "" {
			stateDir = st.StateDir
		} else {
			stateDir = store.DefaultStateDir
		}
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot state dir %s: %w", stateDir, err)
	}

	m := &Manager{
		StateDir:  stateDir,
		Domains:   domains,
		WPCLI:     wp,
		Store:     st,
		Policies:  policies,
		snapshots: make(map[string]SnapshotRecord),
	}
	if wp != nil {
		m.NiceBin = wp.NiceBin
		m.IoniceBin = wp.IoniceBin
	}
	if err := m.loadIndex(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) indexPath() string {
	return filepath.Join(m.StateDir, "snapshots.json")
}

func (m *Manager) loadIndex() error {
	p := m.indexPath()
	info, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked snapshot index %s", p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var parsed persistedSnapshotIndex
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("corrupt snapshot index %s: %w", p, err)
	}
	if parsed.Snapshots != nil {
		m.snapshots = parsed.Snapshots
	}
	return nil
}

func (m *Manager) flushIndexLocked() error {
	payload, err := json.MarshalIndent(persistedSnapshotIndex{
		SchemaVersion: 1,
		Snapshots:     m.snapshots,
	}, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	p := m.indexPath()
	if st, sErr := os.Lstat(p); sErr == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s", p)
	}
	tmp, err := os.CreateTemp(m.StateDir, ".snapshots-*")
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
	if _, err := tmp.Write(payload); err != nil {
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
	if err := os.Rename(tmpPath, p); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ListSnapshots returns all snapshots for an instance owned by acct.Username (newest first).
func (m *Manager) ListSnapshots(acct dausers.Account, instanceID string) ([]SnapshotRecord, error) {
	inst, err := m.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	var out []SnapshotRecord
	for _, s := range m.snapshots {
		if s.InstanceID == inst.ID && s.Owner == acct.Username {
			out = append(out, s)
		}
	}
	m.mu.RUnlock()

	sortSnapshotsNewestFirst(out)
	return out, nil
}

// GetSnapshot returns metadata for a single snapshot owned by acct.Username.
func (m *Manager) GetSnapshot(acct dausers.Account, instanceID, snapshotID string) (SnapshotRecord, error) {
	inst, err := m.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return SnapshotRecord{}, err
	}
	m.mu.RLock()
	rec, ok := m.snapshots[strings.TrimSpace(snapshotID)]
	m.mu.RUnlock()
	if !ok || rec.InstanceID != inst.ID || rec.Owner != acct.Username {
		return SnapshotRecord{}, store.ErrNotFound
	}
	return rec, nil
}

// ResolveDownloadPath verifies and returns the absolute filesystem path to a customer's `.tar.zst` archive.
func (m *Manager) ResolveDownloadPath(acct dausers.Account, instanceID, snapshotID string) (string, SnapshotRecord, error) {
	rec, err := m.GetSnapshot(acct, instanceID, snapshotID)
	if err != nil {
		return "", SnapshotRecord{}, err
	}
	snapDir, err := ensureVerifiedCustomerSnapshotDir(acct, rec.InstanceID, false)
	if err != nil {
		return "", SnapshotRecord{}, err
	}
	if strings.ContainsAny(rec.FileName, `/\`) || rec.FileName == "" || rec.FileName == ".." {
		return "", SnapshotRecord{}, errors.New("invalid snapshot file name")
	}
	archivePath := filepath.Join(snapDir, rec.FileName)
	st, err := os.Lstat(archivePath)
	if err != nil {
		return "", SnapshotRecord{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", SnapshotRecord{}, fsguard.ErrSymlinkBlocked
	}
	if !st.Mode().IsRegular() {
		return "", SnapshotRecord{}, errors.New("snapshot archive is not a regular file")
	}
	return archivePath, rec, nil
}

// CreateSnapshot packages WordPress files + MariaDB SQL dump into a Zstd (.tar.zst) archive inside
// /home/<user>/wp-snapshots/<instance_id>/, blocks Symlink Escape attempts (TC-02), and auto-rotates older snapshots.
func (m *Manager) CreateSnapshot(
	ctx context.Context,
	acct dausers.Account,
	req CreateRequest,
	report store.ProgressReporter,
) (SnapshotRecord, error) {
	if report == nil {
		report = func(int, string) {}
	}
	if m.Store == nil {
		return SnapshotRecord{}, errors.New("store is not configured")
	}

	inst, err := m.Store.GetInstanceForOwner(strings.TrimSpace(req.InstanceID), acct.Username)
	if err != nil {
		return SnapshotRecord{}, err
	}

	pol := config.DefaultPackagePolicy()
	if m.Policies != nil {
		if resolved, pErr := m.Policies.ResolvePackagePolicy(acct.Package); pErr == nil {
			pol = resolved
		}
	}
	if !req.AdminBypass && pol.MaxSnapshotsPerSite == 0 {
		return SnapshotRecord{}, errors.New("snapshots are disabled for your hosting package (MAX_SNAPSHOTS_PER_SITE=0)")
	}

	includeDB := true
	if req.IncludeDB != nil {
		includeDB = *req.IncludeDB
	}
	kind := normalizeSnapshotKind(req.Kind)
	note := strings.TrimSpace(req.Note)
	if len(note) > 200 {
		note = note[:200]
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, func(targetPath, reason string) {
		m.recordSymlinkViolation(acct, inst.ID, targetPath, reason)
	})
	if err != nil {
		return SnapshotRecord{}, err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return SnapshotRecord{}, err
	}

	snapDir, err := ensureVerifiedCustomerSnapshotDir(acct, inst.ID, true)
	if err != nil {
		if errors.Is(err, fsguard.ErrSymlinkBlocked) {
			m.recordSymlinkViolation(acct, inst.ID, snapDir, err.Error())
		}
		return SnapshotRecord{}, err
	}

	excludedRels, phpSel := m.resolveInstanceExclusionsAndPHP(acct, inst, verifiedDocRoot)

	snapID, err := newSnapshotID()
	if err != nil {
		return SnapshotRecord{}, err
	}
	now := time.Now().UTC()
	rec := SnapshotRecord{
		ID:          snapID,
		InstanceID:  inst.ID,
		Owner:       acct.Username,
		Domain:      inst.Domain,
		SubPath:     inst.SubPath,
		Note:        note,
		Kind:        kind,
		WPVersion:   inst.WPVersion,
		DBName:      inst.DBName,
		TablePrefix: inst.TablePrefix,
		FileName:    snapID + ".tar.zst",
		IncludesDB:  includeDB,
		CreatedAt:   now,
	}

	// Step 1: Export MariaDB database to a confined 0600 temp SQL file inside verifiedDocRoot
	var dbDumpPath string
	var fallbackSQLBytes []byte
	if includeDB && m.WPCLI != nil {
		report(15, "Exporting WordPress MariaDB database")
		randSuffix, _ := randomHex(6)
		dbDumpPath = filepath.Join(verifiedDocRoot, ".da-wptk-dbdump-"+randSuffix+".sql")
		defer func() {
			if dbDumpPath != "" {
				_ = os.Remove(dbDumpPath)
			}
		}()

		stdout, exportErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
			Account:     acct,
			DocRoot:     verifiedDocRoot,
			PHP:         phpSel,
			Args:        []string{"db", "export", dbDumpPath, "--add-drop-table"},
			SkipPlugins: true,
			SkipThemes:  true,
		})
		if exportErr != nil {
			return SnapshotRecord{}, fmt.Errorf("database export failed: %w", exportErr)
		}

		if st, sErr := os.Lstat(dbDumpPath); sErr == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				m.recordSymlinkViolation(acct, inst.ID, dbDumpPath, "symlinked db dump file detected")
				return SnapshotRecord{}, fsguard.ErrSymlinkBlocked
			}
		} else {
			dbDumpPath = ""
			fallbackSQLBytes = []byte(stdout)
		}
	}

	// Step 2: Walk DocRoot & stream tar directly into Zstd compressor -> temp archive file
	report(45, "Compressing WordPress files and SQL dump with Zstandard (.tar.zst)")
	tmpFile, err := os.CreateTemp(snapDir, ".snap-*.tmp")
	if err != nil {
		return SnapshotRecord{}, err
	}
	tmpArchivePath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpArchivePath)
		}
	}()
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return SnapshotRecord{}, err
	}

	pr, pw := io.Pipe()
	var fileCount int
	var tarProducerErr error
	var producerWG sync.WaitGroup
	producerWG.Add(1)
	go func() {
		defer producerWG.Done()
		tw := tar.NewWriter(pw)
		fileCount, tarProducerErr = m.writeSnapshotTarEntries(ctx, acct, inst, verifiedDocRoot, excludedRels, rec, dbDumpPath, fallbackSQLBytes, tw)
		closeErr := tw.Close()
		if tarProducerErr == nil && closeErr != nil {
			tarProducerErr = closeErr
		}
		if tarProducerErr != nil {
			_ = pw.CloseWithError(tarProducerErr)
		} else {
			_ = pw.Close()
		}
	}()

	compErr := compressZstdStream(ctx, m.ZstdBin, m.NiceBin, m.IoniceBin, pr, tmpFile)
	_ = pr.Close()
	producerWG.Wait()

	if tarProducerErr != nil {
		_ = tmpFile.Close()
		return SnapshotRecord{}, tarProducerErr
	}
	if compErr != nil {
		_ = tmpFile.Close()
		return SnapshotRecord{}, compErr
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return SnapshotRecord{}, err
	}
	st, statErr := tmpFile.Stat()
	if err := tmpFile.Close(); err != nil {
		return SnapshotRecord{}, err
	}
	if statErr != nil {
		return SnapshotRecord{}, statErr
	}

	chownCustomerIfRoot(tmpArchivePath, acct.UID, acct.GID)
	finalArchivePath := filepath.Join(snapDir, rec.FileName)
	if lstat, lErr := os.Lstat(finalArchivePath); lErr == nil && lstat.Mode()&os.ModeSymlink != 0 {
		return SnapshotRecord{}, fsguard.ErrSymlinkBlocked
	}
	if err := os.Rename(tmpArchivePath, finalArchivePath); err != nil {
		return SnapshotRecord{}, err
	}
	cleanupTmp = false

	rec.SizeBytes = st.Size()
	rec.FileCount = fileCount

	// Step 3: Persist index & enforce automatic MaxSnapshotsPerSite rotation
	report(88, "Updating snapshot registry and rotating old snapshots")
	maxKeep := pol.MaxSnapshotsPerSite
	if req.AdminBypass && maxKeep <= 0 {
		maxKeep = 5
	}
	prunedFiles, remainingCount, err := m.saveAndRotateInstanceSnapshots(rec, maxKeep)
	if err != nil {
		_ = os.Remove(finalArchivePath)
		return SnapshotRecord{}, err
	}
	for _, oldFile := range prunedFiles {
		if oldFile != "" && !strings.ContainsAny(oldFile, `/\`) {
			_ = os.Remove(filepath.Join(snapDir, oldFile))
		}
	}

	m.syncInstanceSnapshotCount(acct.Username, inst.ID, remainingCount)
	report(100, "Zstandard snapshot created")
	return rec, nil
}

// RestoreSnapshot extracts a `.tar.zst` snapshot into a verified staging directory first (preventing partial wipes on corrupt archives),
// restores WordPress files while preserving sibling classic subdomains & `.well-known`, and imports the SQL dump.
func (m *Manager) RestoreSnapshot(
	ctx context.Context,
	acct dausers.Account,
	instanceID string,
	snapshotID string,
	report store.ProgressReporter,
) (RestoreResult, error) {
	if report == nil {
		report = func(int, string) {}
	}
	archivePath, rec, err := m.ResolveDownloadPath(acct, instanceID, snapshotID)
	if err != nil {
		return RestoreResult{}, err
	}
	inst, err := m.Store.GetInstanceForOwner(rec.InstanceID, acct.Username)
	if err != nil {
		return RestoreResult{}, err
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, func(targetPath, reason string) {
		m.recordSymlinkViolation(acct, inst.ID, targetPath, reason)
	})
	if err != nil {
		return RestoreResult{}, err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			verifiedDocRoot, err = guard.VerifyProspectivePath(inst.DocRoot)
			if err != nil {
				return RestoreResult{}, err
			}
			if mkErr := os.MkdirAll(verifiedDocRoot, 0o755); mkErr != nil {
				return RestoreResult{}, mkErr
			}
			chownCustomerIfRoot(verifiedDocRoot, acct.UID, acct.GID)
		} else {
			return RestoreResult{}, err
		}
	}

	excludedRels, phpSel := m.resolveInstanceExclusionsAndPHP(acct, inst, verifiedDocRoot)

	// Stage 1: Decompress & unpack tar into a private staging directory inside customer's wp-snapshots dir
	report(25, "Verifying and decompressing Zstandard (.tar.zst) snapshot")
	snapDir := filepath.Dir(archivePath)
	stageDir, err := os.MkdirTemp(snapDir, ".restore-*")
	if err != nil {
		return RestoreResult{}, err
	}
	defer func() { _ = os.RemoveAll(stageDir) }()
	_ = os.Chmod(stageDir, 0o700)

	stageFilesDir := filepath.Join(stageDir, "files")
	if err := os.MkdirAll(stageFilesDir, 0o700); err != nil {
		return RestoreResult{}, err
	}
	stageDBPath := filepath.Join(stageDir, "database.sql")

	extractedFiles, hasDBDump, err := m.unpackArchiveToStage(ctx, archivePath, stageFilesDir, stageDBPath, excludedRels)
	if err != nil {
		return RestoreResult{}, err
	}

	// Stage 2: Under Core Shield suppression, replace DocRoot files (preserving sibling subdomains) & import SQL
	var dbRestored bool
	runFn := func() error {
		report(60, "Restoring WordPress files while preserving sibling subdomains")
		if err := cleanDocRootPreservingExclusions(verifiedDocRoot, excludedRels); err != nil {
			return err
		}
		if err := copyStagedTreeToDocRoot(stageFilesDir, verifiedDocRoot, excludedRels, acct.UID, acct.GID); err != nil {
			return err
		}

		if hasDBDump && m.WPCLI != nil {
			report(82, "Importing MariaDB database snapshot")
			randHexStr, _ := randomHex(6)
			tmpSQL := filepath.Join(verifiedDocRoot, ".da-wptk-restore-"+randHexStr+".sql")
			defer func() { _ = os.Remove(tmpSQL) }()

			if err := copySingleOwnedFile(stageDBPath, tmpSQL, acct.UID, acct.GID, 0o600); err != nil {
				return err
			}
			if _, impErr := m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedDocRoot,
				PHP:         phpSel,
				Args:        []string{"db", "import", tmpSQL},
				SkipPlugins: true,
				SkipThemes:  true,
			}); impErr != nil {
				return fmt.Errorf("database restore failed: %w", impErr)
			}
			dbRestored = true

			_, _ = m.WPCLI.Run(ctx, wpcli.CallOptions{
				Account:     acct,
				DocRoot:     verifiedDocRoot,
				PHP:         phpSel,
				Args:        []string{"cache", "flush"},
				SkipPlugins: true,
				SkipThemes:  true,
			})
		}
		return nil
	}

	if m.WithShieldSuppression != nil {
		err = m.WithShieldSuppression(acct, inst, runFn)
	} else {
		err = runFn()
	}
	if err != nil {
		return RestoreResult{}, err
	}

	if rec.WPVersion != "" {
		inst.WPVersion = rec.WPVersion
	}
	savedInst, uErr := m.Store.UpsertInstance(inst)
	if uErr == nil {
		inst = savedInst
	}

	report(100, "Snapshot restore completed")
	return RestoreResult{
		Snapshot:         rec,
		Instance:         inst,
		RestoredFiles:    extractedFiles,
		DatabaseRestored: dbRestored,
	}, nil
}

// DeleteSnapshot deletes a single `.tar.zst` archive and updates InstanceRecord.SnapshotCount.
func (m *Manager) DeleteSnapshot(acct dausers.Account, instanceID, snapshotID string) error {
	rec, err := m.GetSnapshot(acct, instanceID, snapshotID)
	if err != nil {
		return err
	}

	if snapDir, dErr := ensureVerifiedCustomerSnapshotDir(acct, rec.InstanceID, false); dErr == nil {
		if !strings.ContainsAny(rec.FileName, `/\`) && rec.FileName != "" {
			archivePath := filepath.Join(snapDir, rec.FileName)
			if st, sErr := os.Lstat(archivePath); sErr == nil && st.Mode()&os.ModeSymlink == 0 {
				_ = os.Remove(archivePath)
			}
		}
	}

	m.mu.Lock()
	delete(m.snapshots, rec.ID)
	rem := 0
	for _, s := range m.snapshots {
		if s.InstanceID == rec.InstanceID && s.Owner == acct.Username {
			rem++
		}
	}
	err = m.flushIndexLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}

	m.syncInstanceSnapshotCount(acct.Username, rec.InstanceID, rem)
	return nil
}

// PurgeInstance removes all snapshot records and `.tar.zst` files when an instance is uninstalled.
func (m *Manager) PurgeInstance(acct dausers.Account, instanceID string) {
	id := strings.TrimSpace(instanceID)
	if id == "" {
		return
	}
	m.mu.Lock()
	changed := false
	for k, s := range m.snapshots {
		if s.InstanceID == id && s.Owner == acct.Username {
			delete(m.snapshots, k)
			changed = true
		}
	}
	if changed {
		_ = m.flushIndexLocked()
	}
	m.mu.Unlock()

	if snapDir, err := ensureVerifiedCustomerSnapshotDir(acct, id, false); err == nil {
		_ = os.RemoveAll(snapDir)
	}
}

// PurgeOwner removes all snapshot index entries belonging to a destroyed DirectAdmin user.
func (m *Manager) PurgeOwner(owner string) int {
	u := strings.TrimSpace(owner)
	if u == "" {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	for id, s := range m.snapshots {
		if s.Owner == u {
			delete(m.snapshots, id)
			removed++
		}
	}
	if removed > 0 {
		_ = m.flushIndexLocked()
	}
	return removed
}

func (m *Manager) writeSnapshotTarEntries(
	ctx context.Context,
	acct dausers.Account,
	inst store.InstanceRecord,
	verifiedDocRoot string,
	excludedRels map[string]struct{},
	rec SnapshotRecord,
	dbDumpPath string,
	fallbackSQLBytes []byte,
	tw *tar.Writer,
) (int, error) {
	now := time.Now().UTC()

	// 1. Metadata header entry
	metaBytes, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writeTarBytesEntry(tw, archiveMetaEntry, metaBytes, 0o600, now); err != nil {
		return 0, err
	}

	// 2. Database SQL dump entry (streamed directly from disk when present)
	if rec.IncludesDB {
		if dbDumpPath != "" {
			if err := writeTarRegularFileEntry(tw, archiveDatabaseSQLEntry, dbDumpPath, 0o600, m, acct, inst.ID); err != nil {
				return 0, err
			}
		} else if len(fallbackSQLBytes) > 0 {
			if err := writeTarBytesEntry(tw, archiveDatabaseSQLEntry, fallbackSQLBytes, 0o600, now); err != nil {
				return 0, err
			}
		}
	}

	// 3. Walk verifiedDocRoot recursively without ever following symlinks (TC-02)
	fileCount := 0
	var walkDir func(absDir, relSlash string) error
	walkDir = func(absDir, relSlash string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(absDir)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			name := ent.Name()
			childRel := name
			if relSlash != "" {
				childRel = relSlash + "/" + name
			}

			if isExcludedRelPath(childRel, excludedRels) || isTransientToolkitArtifact(name, childRel) {
				continue
			}

			childAbs := filepath.Join(absDir, name)
			lstat, err := os.Lstat(childAbs)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			if lstat.Mode()&os.ModeSymlink != 0 {
				m.recordSymlinkViolation(acct, inst.ID, childAbs, "symbolic link inside DocRoot blocked during snapshot backup")
				return fmt.Errorf("%w: %s", fsguard.ErrSymlinkBlocked, childAbs)
			}

			tarName := archiveFilesPrefix + childRel
			if lstat.IsDir() {
				hdr := &tar.Header{
					Name:     tarName + "/",
					Typeflag: tar.TypeDir,
					Mode:     0o755,
					ModTime:  lstat.ModTime(),
				}
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
				if isVolatileCacheDir(childRel) {
					continue
				}
				if err := walkDir(childAbs, childRel); err != nil {
					return err
				}
				continue
			}

			if !lstat.Mode().IsRegular() {
				continue
			}

			mode := int64(0o644)
			if childRel == "wp-config.php" {
				mode = 0o600
			}
			if err := writeTarVerifiedCustomerFile(tw, tarName, childAbs, lstat, mode, m, acct, inst.ID); err != nil {
				return err
			}
			fileCount++
		}
		return nil
	}

	if err := walkDir(verifiedDocRoot, ""); err != nil {
		return fileCount, err
	}
	return fileCount, nil
}

func (m *Manager) unpackArchiveToStage(
	ctx context.Context,
	archivePath string,
	stageFilesDir string,
	stageDBPath string,
	excludedRels map[string]struct{},
) (extractedFiles int, hasDBDump bool, err error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	pr, pw := io.Pipe()
	var decErr error
	var decWG sync.WaitGroup
	decWG.Add(1)
	go func() {
		defer decWG.Done()
		decErr = decompressZstdStream(ctx, m.ZstdBin, f, pw, maxDecompressBytes)
		if decErr != nil {
			_ = pw.CloseWithError(decErr)
		} else {
			_ = pw.Close()
		}
	}()

	tr := tar.NewReader(pr)
	var totalBytes int64

	for {
		if err := ctx.Err(); err != nil {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, err
		}
		hdr, rErr := tr.Next()
		if errors.Is(rErr, io.EOF) {
			break
		}
		if rErr != nil {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, fmt.Errorf("read snapshot tar header: %w", rErr)
		}

		// Block symlinks, hardlinks, FIFOs, and device nodes inside snapshot archives
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			if hdr.Typeflag == tar.TypeXGlobalHeader || hdr.Typeflag == tar.TypeXHeader {
				continue
			}
			_ = pr.Close()
			decWG.Wait()
			return 0, false, fmt.Errorf("forbidden tar entry type %d for %q in snapshot archive", hdr.Typeflag, hdr.Name)
		}

		cleanName := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "./")
		if cleanName == "" || strings.HasPrefix(cleanName, "/") || strings.Contains(cleanName, "..") {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, fmt.Errorf("unsafe path %q in snapshot archive", hdr.Name)
		}

		if cleanName == archiveMetaEntry {
			continue
		}
		if cleanName == archiveDatabaseSQLEntry && hdr.Typeflag != tar.TypeDir {
			totalBytes += hdr.Size
			if totalBytes > maxDecompressBytes {
				_ = pr.Close()
				decWG.Wait()
				return 0, false, errors.New("snapshot archive exceeded safety extraction limit")
			}
			if err := extractSingleStreamFile(tr, stageDBPath, hdr.Size, 0o600); err != nil {
				_ = pr.Close()
				decWG.Wait()
				return 0, false, err
			}
			hasDBDump = true
			continue
		}

		if !strings.HasPrefix(cleanName, archiveFilesPrefix) {
			continue
		}
		relSlash := strings.Trim(strings.TrimPrefix(cleanName, archiveFilesPrefix), "/")
		if relSlash == "" || isExcludedRelPath(relSlash, excludedRels) {
			continue
		}

		destPath := filepath.Join(stageFilesDir, filepath.FromSlash(relSlash))
		if !isStrictSubpath(stageFilesDir, destPath) {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, fmt.Errorf("archive entry %q escaped staging directory", hdr.Name)
		}

		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(destPath, 0o755); err != nil {
				_ = pr.Close()
				decWG.Wait()
				return 0, false, err
			}
			continue
		}

		totalBytes += hdr.Size
		if totalBytes > maxDecompressBytes {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, errors.New("snapshot archive exceeded safety extraction limit")
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, err
		}
		mode := os.FileMode(0o644)
		if relSlash == "wp-config.php" {
			mode = 0o600
		}
		if err := extractSingleStreamFile(tr, destPath, hdr.Size, mode); err != nil {
			_ = pr.Close()
			decWG.Wait()
			return 0, false, err
		}
		extractedFiles++
	}

	_ = pr.Close()
	decWG.Wait()
	if decErr != nil {
		return 0, false, decErr
	}
	return extractedFiles, hasDBDump, nil
}

func (m *Manager) saveAndRotateInstanceSnapshots(newRec SnapshotRecord, maxPerSite int) (prunedFileNames []string, remainingCount int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.snapshots[newRec.ID] = newRec

	var instanceSnaps []SnapshotRecord
	for _, s := range m.snapshots {
		if s.InstanceID == newRec.InstanceID && s.Owner == newRec.Owner {
			instanceSnaps = append(instanceSnaps, s)
		}
	}
	sortSnapshotsNewestFirst(instanceSnaps)

	if maxPerSite > 0 && len(instanceSnaps) > maxPerSite {
		for _, old := range instanceSnaps[maxPerSite:] {
			delete(m.snapshots, old.ID)
			prunedFileNames = append(prunedFileNames, old.FileName)
		}
		remainingCount = maxPerSite
	} else {
		remainingCount = len(instanceSnaps)
	}

	if err := m.flushIndexLocked(); err != nil {
		return nil, 0, err
	}
	return prunedFileNames, remainingCount, nil
}

func (m *Manager) syncInstanceSnapshotCount(owner, instanceID string, count int) {
	if m.Store == nil {
		return
	}
	inst, err := m.Store.GetInstanceForOwner(instanceID, owner)
	if err != nil {
		return
	}
	if inst.SnapshotCount != count {
		inst.SnapshotCount = count
		_, _ = m.Store.UpsertInstance(inst)
	}
}

func (m *Manager) resolveInstanceExclusionsAndPHP(acct dausers.Account, inst store.InstanceRecord, verifiedDocRoot string) (map[string]struct{}, daphp.Selection) {
	excl := make(map[string]struct{})
	var phpSel daphp.Selection
	if m.Domains == nil {
		return excl, phpSel
	}
	targets, err := m.Domains.ListTargets(acct)
	if err != nil {
		return excl, phpSel
	}
	for _, t := range targets {
		if t.Domain == inst.Domain {
			phpSel = t.PHP
		}
		cleanOther := filepath.Clean(t.DocRoot)
		if cleanOther == verifiedDocRoot {
			continue
		}
		rel, rErr := filepath.Rel(verifiedDocRoot, cleanOther)
		if rErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			excl[filepath.ToSlash(rel)] = struct{}{}
		}
	}
	return excl, phpSel
}

func (m *Manager) recordSymlinkViolation(acct dausers.Account, instanceID, targetPath, reason string) {
	if m.Store == nil {
		return
	}
	m.Store.RecordSecurityEvent(store.SecurityAuditEvent{
		Severity:   "critical",
		Category:   "symlink_guard",
		Owner:      acct.Username,
		InstanceID: instanceID,
		Message:    fmt.Sprintf("Snapshot symlink guard blocked %s: %s", targetPath, reason),
	})
}

func ensureVerifiedCustomerSnapshotDir(acct dausers.Account, instanceID string, create bool) (string, error) {
	if err := config.ValidateInstanceID(instanceID); err != nil {
		return "", err
	}
	cleanHome := filepath.Clean(strings.TrimSpace(acct.HomeDir))
	if cleanHome == "" || cleanHome == "." {
		return "", errors.New("account HomeDir is empty")
	}

	if st, err := os.Lstat(cleanHome); err != nil {
		return "", err
	} else if st.Mode()&os.ModeSymlink != 0 {
		return cleanHome, fmt.Errorf("%w: home directory %s is a symlink", fsguard.ErrSymlinkBlocked, cleanHome)
	}

	rootSnapDir := filepath.Join(cleanHome, SnapshotsSubdirName)
	if err := verifyOrCreateDirNoSymlink(rootSnapDir, acct.UID, acct.GID, 0o700, create); err != nil {
		return rootSnapDir, err
	}
	instSnapDir := filepath.Join(rootSnapDir, instanceID)
	if err := verifyOrCreateDirNoSymlink(instSnapDir, acct.UID, acct.GID, 0o700, create); err != nil {
		return instSnapDir, err
	}
	return instSnapDir, nil
}

func verifyOrCreateDirNoSymlink(dirPath string, uid, gid uint32, mode os.FileMode, create bool) error {
	st, err := os.Lstat(dirPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if !create {
			return err
		}
		if err := os.Mkdir(dirPath, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		chownCustomerIfRoot(dirPath, uid, gid)
		st, err = os.Lstat(dirPath)
		if err != nil {
			return err
		}
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", fsguard.ErrSymlinkBlocked, dirPath)
	}
	if !st.IsDir() {
		return fmt.Errorf("expected directory at %s", dirPath)
	}
	return nil
}

func writeTarBytesEntry(tw *tar.Writer, name string, data []byte, mode int64, modTime time.Time) error {
	hdr := &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Size:     int64(len(data)),
		Mode:     mode,
		ModTime:  modTime,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := io.Copy(tw, bytes.NewReader(data))
	return err
}

func writeTarRegularFileEntry(tw *tar.Writer, tarName, absPath string, mode int64, m *Manager, acct dausers.Account, instanceID string) error {
	lstat, err := os.Lstat(absPath)
	if err != nil {
		return err
	}
	if lstat.Mode()&os.ModeSymlink != 0 {
		m.recordSymlinkViolation(acct, instanceID, absPath, "symlinked SQL dump blocked")
		return fmt.Errorf("%w: %s", fsguard.ErrSymlinkBlocked, absPath)
	}
	return writeTarVerifiedCustomerFile(tw, tarName, absPath, lstat, mode, m, acct, instanceID)
}

func writeTarVerifiedCustomerFile(tw *tar.Writer, tarName, absPath string, lstat os.FileInfo, mode int64, m *Manager, acct dausers.Account, instanceID string) error {
	f, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fstat, err := f.Stat()
	if err != nil {
		return err
	}
	if !fstat.Mode().IsRegular() || !os.SameFile(lstat, fstat) {
		m.recordSymlinkViolation(acct, instanceID, absPath, "TOCTOU file swap or symlink detected during snapshot read")
		return fmt.Errorf("%w: TOCTOU mismatch on %s", fsguard.ErrSymlinkBlocked, absPath)
	}

	size := fstat.Size()
	hdr := &tar.Header{
		Name:     tarName,
		Typeflag: tar.TypeReg,
		Size:     size,
		Mode:     mode,
		ModTime:  fstat.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	written, err := io.CopyN(tw, f, size)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if written < size {
		pad := make([]byte, size-written)
		if _, pErr := tw.Write(pad); pErr != nil {
			return pErr
		}
	}
	return nil
}

func extractSingleStreamFile(r io.Reader, destPath string, expectedSize int64, mode os.FileMode) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(r, expectedSize))
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func cleanDocRootPreservingExclusions(docRoot string, excludedRels map[string]struct{}) error {
	var cleanRel func(absDir, relSlash string) (keptAny bool, err error)
	cleanRel = func(absDir, relSlash string) (bool, error) {
		entries, err := os.ReadDir(absDir)
		if err != nil {
			return false, err
		}
		kept := false
		for _, ent := range entries {
			name := ent.Name()
			childRel := name
			if relSlash != "" {
				childRel = relSlash + "/" + name
			}
			if childRel == ".well-known" || childRel == "cgi-bin" || isExcludedRelPath(childRel, excludedRels) {
				kept = true
				continue
			}
			childAbs := filepath.Join(absDir, name)
			if hasDescendantExclusion(childRel, excludedRels) && ent.IsDir() {
				subKept, cErr := cleanRel(childAbs, childRel)
				if cErr != nil {
					return true, cErr
				}
				if subKept {
					kept = true
					continue
				}
			}
			if err := os.RemoveAll(childAbs); err != nil {
				return kept, err
			}
		}
		return kept, nil
	}
	_, err := cleanRel(docRoot, "")
	return err
}

func copyStagedTreeToDocRoot(stageFilesDir, docRoot string, excludedRels map[string]struct{}, uid, gid uint32) error {
	var walkCopy func(srcDir, dstDir, relSlash string) error
	walkCopy = func(srcDir, dstDir, relSlash string) error {
		entries, err := os.ReadDir(srcDir)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			name := ent.Name()
			childRel := name
			if relSlash != "" {
				childRel = relSlash + "/" + name
			}
			if isExcludedRelPath(childRel, excludedRels) {
				continue
			}

			srcPath := filepath.Join(srcDir, name)
			dstPath := filepath.Join(dstDir, name)
			lstat, err := os.Lstat(srcPath)
			if err != nil {
				return err
			}
			if lstat.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if lstat.IsDir() {
				if dstStat, dErr := os.Lstat(dstPath); dErr == nil && dstStat.Mode()&os.ModeSymlink != 0 {
					return fsguard.ErrSymlinkBlocked
				}
				if err := os.MkdirAll(dstPath, 0o755); err != nil {
					return err
				}
				chownCustomerIfRoot(dstPath, uid, gid)
				if err := walkCopy(srcPath, dstPath, childRel); err != nil {
					return err
				}
				continue
			}
			if !lstat.Mode().IsRegular() {
				continue
			}
			mode := os.FileMode(0o644)
			if childRel == "wp-config.php" {
				mode = 0o600
			}
			if err := copySingleOwnedFile(srcPath, dstPath, uid, gid, mode); err != nil {
				return err
			}
		}
		return nil
	}
	return walkCopy(stageFilesDir, docRoot, "")
}

func copySingleOwnedFile(srcPath, dstPath string, uid, gid uint32, mode os.FileMode) error {
	if dstStat, err := os.Lstat(dstPath); err == nil && dstStat.Mode()&os.ModeSymlink != 0 {
		return fsguard.ErrSymlinkBlocked
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(dstPath)
	tmp, err := os.CreateTemp(dir, ".da-wptk-r-*")
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

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, in); err != nil {
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
	chownCustomerIfRoot(tmpPath, uid, gid)
	if err := os.Rename(tmpPath, dstPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func isExcludedRelPath(relSlash string, excluded map[string]struct{}) bool {
	for ex := range excluded {
		if relSlash == ex || strings.HasPrefix(relSlash, ex+"/") {
			return true
		}
	}
	return false
}

func hasDescendantExclusion(relSlash string, excluded map[string]struct{}) bool {
	prefix := relSlash + "/"
	for ex := range excluded {
		if strings.HasPrefix(ex, prefix) {
			return true
		}
	}
	return false
}

func isTransientToolkitArtifact(name, relSlash string) bool {
	if strings.HasPrefix(name, ".da-wptk-") || strings.HasPrefix(name, ".wptk-") {
		return true
	}
	if strings.HasPrefix(relSlash, "wp-content/mu-plugins/da-wptk-sso-") {
		return true
	}
	return false
}

func isVolatileCacheDir(relSlash string) bool {
	return relSlash == "wp-content/cache" || relSlash == "wp-content/litespeed/cache"
}

func isStrictSubpath(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func normalizeSnapshotKind(k string) string {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case KindPreSync:
		return KindPreSync
	case KindPreUpdate:
		return KindPreUpdate
	default:
		return KindManual
	}
}

func sortSnapshotsNewestFirst(list []SnapshotRecord) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].CreatedAt.After(list[j].CreatedAt)
		}
		return list[i].ID > list[j].ID
	})
}

func chownCustomerIfRoot(path string, uid, gid uint32) {
	if os.Geteuid() == 0 && uid >= 1000 {
		_ = chownNoFollow(path, uid, gid)
	}
}

func newSnapshotID() (string, error) {
	hexPart, err := randomHex(8)
	if err != nil {
		return "", err
	}
	return "snap_" + hexPart, nil
}

func randomHex(numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
