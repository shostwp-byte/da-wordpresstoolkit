package integrity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

const (
	DefaultAuditInterval   = 30 * time.Minute
	DefaultThrashThreshold = 5
	DefaultThrashWindow    = 30 * time.Second
)

// WatchEvent describes a filesystem mutation detected inside a watched WordPress Core directory.
type WatchEvent struct {
	InstanceID string
	AbsPath    string
	IsDir      bool
}

// WatchOutcome reports how Shield processed a WatchEvent so poll-based watchers never suffer mid-heal baseline races.
type WatchOutcome struct {
	Handled       bool
	RestoredBytes []byte
	RemovedFile   bool
}

// VerifyReport summarizes a Core Integrity verification and optional Auto-Heal pass on an instance.
type VerifyReport struct {
	InstanceID         string   `json:"instance_id"`
	Domain             string   `json:"domain"`
	WPVersion          string   `json:"wp_version"`
	Locale             string   `json:"locale"`
	Mode               string   `json:"mode"`
	Clean              bool     `json:"clean"`
	CheckedFiles       int      `json:"checked_files"`
	ModifiedFiles      []string `json:"modified_files,omitempty"`
	MissingFiles       []string `json:"missing_files,omitempty"`
	UnknownExecutables []string `json:"unknown_executables,omitempty"`
	HealedFiles        []string `json:"healed_files,omitempty"`
	QuarantinedIDs     []string `json:"quarantined_ids,omitempty"`
	EscalatedToLock    bool     `json:"escalated_to_lock"`
	ElapsedMillis      int64    `json:"elapsed_millis"`
}

// ShieldConfig customizes thresholds and intervals for Core Integrity Shield.
type ShieldConfig struct {
	StateDir        string
	CoreCacheDir    string
	QuarantineDir   string
	MaxWatches      int
	PollInterval    time.Duration
	AuditInterval   time.Duration
	ThrashThreshold int
	ThrashWindow    time.Duration
}

// Shield implements 3-mode WordPress Core self-protection:
//   - monitor: SHA-256 verification & alert without modifying disk
//   - auto_heal: real-time inotify + <50ms atomic Core restore + Quarantine Vault + Anti-Thrashing guard
//   - fortress_lock: OS-level root:<user> Core ownership lock compatible with DirectAdmin Backups
type Shield struct {
	Store      *store.Store
	Users      *dausers.Registry
	Policies   *config.PolicyStore
	Cache      *CoreCache
	Quarantine *QuarantineVault
	Locker     *CoreLocker

	AuditInterval   time.Duration
	ThrashThreshold int
	ThrashWindow    time.Duration

	watcher *coreWatcher

	mu            sync.Mutex
	suppressed    map[string]int
	thrashHistory map[string][]time.Time
}

// NewShield constructs the Core Integrity Shield subsystem.
func NewShield(
	st *store.Store,
	users *dausers.Registry,
	policies *config.PolicyStore,
	cfg ShieldConfig,
) (*Shield, error) {
	stateDir := cfg.StateDir
	if strings.TrimSpace(stateDir) == "" && st != nil {
		stateDir = st.StateDir
	}
	if strings.TrimSpace(stateDir) == "" {
		stateDir = store.DefaultStateDir
	}

	vault, err := NewQuarantineVault(stateDir, cfg.QuarantineDir)
	if err != nil {
		return nil, err
	}
	cache := NewCoreCache(cfg.CoreCacheDir)
	locker := newCoreLocker(stateDir)
	watcher := newCoreWatcher(cfg.MaxWatches, cfg.PollInterval)

	auditInt := cfg.AuditInterval
	if auditInt <= 0 {
		auditInt = DefaultAuditInterval
	}
	thrashLim := cfg.ThrashThreshold
	if thrashLim <= 0 {
		thrashLim = DefaultThrashThreshold
	}
	thrashWin := cfg.ThrashWindow
	if thrashWin <= 0 {
		thrashWin = DefaultThrashWindow
	}

	return &Shield{
		Store:           st,
		Users:           users,
		Policies:        policies,
		Cache:           cache,
		Quarantine:      vault,
		Locker:          locker,
		AuditInterval:   auditInt,
		ThrashThreshold: thrashLim,
		ThrashWindow:    thrashWin,
		watcher:         watcher,
		suppressed:      make(map[string]int),
		thrashHistory:   make(map[string][]time.Time),
	}, nil
}

// Start activates real-time kernel inotify monitoring, syncs watches for all managed instances,
// and launches the periodic 30-minute integrity sweep.
func (s *Shield) Start(ctx context.Context) error {
	if err := s.watcher.Start(ctx, s.handleWatchEvent, func() {
		// On kernel IN_Q_OVERFLOW, run an immediate full audit sweep so zero modifications can slip through!
		s.SweepAll(ctx)
	}); err != nil {
		return err
	}

	s.SyncAllWatches()

	go func() {
		ticker := time.NewTicker(s.AuditInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.SweepAll(ctx)
			}
		}
	}()
	return nil
}

// WatchStats returns (activeWatches, maxWatchBudget) for daemon ping & Admin Panel telemetry.
func (s *Shield) WatchStats() (int, int) {
	if s.watcher == nil {
		return 0, 0
	}
	return s.watcher.Stats()
}

// SyncAllWatches registers or removes watches according to each active instance's CoreShieldMode.
func (s *Shield) SyncAllWatches() {
	if s.Store == nil {
		return
	}
	for _, inst := range s.Store.ListAllInstances(false) {
		s.SyncInstanceWatch(inst)
	}
}

// SyncInstanceWatch updates kernel inotify watches for a single instance.
func (s *Shield) SyncInstanceWatch(inst store.InstanceRecord) {
	if s.watcher == nil {
		return
	}
	if inst.Detached || (inst.CoreShieldMode != config.ShieldModeAutoHeal && inst.CoreShieldMode != config.ShieldModeMonitor) {
		s.watcher.UnwatchInstance(inst.ID)
		return
	}
	acct, ok := s.resolveAccount(inst.Owner)
	if !ok || acct.HomeDir == "" {
		return
	}
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return
	}
	_ = s.watcher.SyncInstance(inst.ID, verifiedDocRoot)
}

// SweepAll audits every managed non-detached WordPress instance across the server.
func (s *Shield) SweepAll(ctx context.Context) {
	if s.Store == nil {
		return
	}
	for _, inst := range s.Store.ListAllInstances(false) {
		if ctx.Err() != nil {
			return
		}
		if s.isSuppressed(inst.ID) || inst.UpdatingFlag {
			continue
		}
		acct, ok := s.resolveAccount(inst.Owner)
		if !ok {
			continue
		}
		_, _ = s.VerifyAndHealInstance(ctx, acct, inst.ID, false)
	}
}

func (s *Shield) isSuppressed(instanceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.suppressed[instanceID] > 0
}

func (s *Shield) pushSuppression(instanceID string) {
	s.mu.Lock()
	s.suppressed[instanceID]++
	s.mu.Unlock()
}

func (s *Shield) popSuppression(instanceID string) {
	s.mu.Lock()
	if s.suppressed[instanceID] > 1 {
		s.suppressed[instanceID]--
	} else {
		delete(s.suppressed, instanceID)
	}
	s.mu.Unlock()
}

// WithUpdatingSuppression pauses Core Auto-Heal on inst during authorized Toolkit updates/hardening,
// temporarily unlocking Core if Fortress Lock is enabled and re-locking immediately afterward.
func (s *Shield) WithUpdatingSuppression(acct dausers.Account, inst store.InstanceRecord, fn func() error) error {
	s.pushSuppression(inst.ID)
	defer s.popSuppression(inst.ID)

	wasLocked := inst.CoreShieldMode == config.ShieldModeFortressLock || s.Locker.IsLockedInMemory(inst.ID)
	var manifest *CoreManifest
	if m, ok := s.Cache.GetCachedManifest(inst.WPVersion, inst.Locale); ok {
		manifest = m
	}

	if wasLocked {
		_ = s.Locker.UnlockInstance(acct, inst, manifest)
		defer func() {
			if latest, err := s.Store.GetInstance(inst.ID); err == nil && latest.CoreShieldMode == config.ShieldModeFortressLock {
				if m2, ok := s.Cache.GetCachedManifest(latest.WPVersion, latest.Locale); ok {
					manifest = m2
				}
				_ = s.Locker.LockInstance(acct, latest, manifest)
			}
		}()
	}

	err := fn()
	if latest, gErr := s.Store.GetInstance(inst.ID); gErr == nil {
		s.SyncInstanceWatch(latest)
	}
	return err
}

func (s *Shield) handleWatchEvent(ev WatchEvent) WatchOutcome {
	if s.isSuppressed(ev.InstanceID) || s.Store == nil {
		return WatchOutcome{Handled: true}
	}
	inst, err := s.Store.GetInstance(ev.InstanceID)
	if err != nil || inst.Detached || inst.UpdatingFlag {
		return WatchOutcome{Handled: true}
	}
	acct, ok := s.resolveAccount(inst.Owner)
	if !ok {
		return WatchOutcome{Handled: true}
	}
	return s.inspectSingleEvent(acct, inst, ev.AbsPath)
}

func (s *Shield) inspectSingleEvent(acct dausers.Account, inst store.InstanceRecord, absPath string) WatchOutcome {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return WatchOutcome{Handled: true}
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return WatchOutcome{Handled: true}
	}
	relOS, err := filepath.Rel(verifiedDocRoot, filepath.Clean(absPath))
	if err != nil || relOS == "." || strings.HasPrefix(relOS, "..") {
		return WatchOutcome{Handled: true}
	}
	relPosix := filepath.ToSlash(relOS)
	if relPosix == "wp-content" || strings.HasPrefix(relPosix, "wp-content/") ||
		relPosix == "wp-config.php" || relPosix == ".htaccess" ||
		strings.HasPrefix(filepath.Base(relPosix), ".da-wptk-") {
		return WatchOutcome{Handled: true}
	}
	if s.Quarantine.IsWhitelisted(inst.ID, relPosix) {
		return WatchOutcome{Handled: true}
	}

	manifest, ok := s.Cache.GetCachedManifest(inst.WPVersion, inst.Locale)
	if !ok {
		return WatchOutcome{Handled: true}
	}

	shouldHeal := inst.CoreShieldMode == config.ShieldModeAutoHeal

	// Case 1: Known official WordPress Core file
	if expected, isCore := manifest.Files[relPosix]; isCore {
		target := filepath.Join(verifiedDocRoot, filepath.FromSlash(relPosix))
		st, lErr := os.Lstat(target)
		if lErr != nil {
			if errors.Is(lErr, os.ErrNotExist) {
				if !shouldHeal {
					s.markIntegrityClean(inst, false)
					return WatchOutcome{Handled: true}
				}
				s.pushSuppression(inst.ID)
				var restored []byte
				healed := false
				cleanPath, cErr := s.Cache.CleanFilePath(manifest.Version, manifest.Locale, relPosix)
				if cErr == nil {
					if cleanBytes, rErr := os.ReadFile(cleanPath); rErr == nil {
						if writeGuardedCoreFile(guard, acct, target, cleanBytes, 0o644) == nil {
							healed = true
							restored = cleanBytes
							s.recordEvent("warning", "core_auto_heal", inst, "Restored deleted WordPress Core file "+relPosix)
							s.markIntegrityClean(inst, true)
						}
					}
				}
				s.popSuppression(inst.ID)
				if healed {
					s.recordInterventionAndCheckThrash(acct, inst, manifest)
					return WatchOutcome{Handled: true, RestoredBytes: restored}
				}
				return WatchOutcome{Handled: false}
			}
			return WatchOutcome{Handled: false}
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return WatchOutcome{Handled: true}
		}

		tamperedBytes, rErr := guard.ReadRegularFileSafe(target, maxSingleCoreFileBytes)
		if rErr != nil {
			return WatchOutcome{Handled: false}
		}
		sum := sha256.Sum256(tamperedBytes)
		if hex.EncodeToString(sum[:]) == expected.SHA256 {
			return WatchOutcome{Handled: true, RestoredBytes: tamperedBytes} // Matches verified Core digest 100%
		}

		if !shouldHeal {
			s.markIntegrityClean(inst, false)
			s.recordEvent("warning", "core_tamper_detected", inst, "Detected modified WordPress Core file "+relPosix+" (Monitor mode)")
			return WatchOutcome{Handled: true}
		}

		cleanPath, cErr := s.Cache.CleanFilePath(manifest.Version, manifest.Locale, relPosix)
		if cErr != nil {
			return WatchOutcome{Handled: false}
		}
		cleanBytes, cReadErr := os.ReadFile(cleanPath)
		if cReadErr != nil {
			return WatchOutcome{Handled: false}
		}

		// Persist forensic sample in Quarantine Vault FIRST so evidence is committed before target restoration
		qItem, qErr := s.Quarantine.StoreTamperedFile(inst, relPosix, ReasonModifiedCoreFile, ActionAutoHealed, cleanBytes, tamperedBytes)

		s.pushSuppression(inst.ID)
		wErr := writeGuardedCoreFile(guard, acct, target, cleanBytes, 0o644)
		s.popSuppression(inst.ID)
		if wErr != nil {
			if qErr == nil && qItem.ID != "" {
				_ = s.Quarantine.DeleteItem(qItem.ID, "", true)
			}
			return WatchOutcome{Handled: false}
		}

		s.markIntegrityClean(inst, true)
		s.recordEvent("warning", "core_auto_heal", inst, "Auto-healed modified WordPress Core file "+relPosix)
		s.recordInterventionAndCheckThrash(acct, inst, manifest)
		return WatchOutcome{Handled: true, RestoredBytes: cleanBytes}
	}

	// Case 2: Unknown file inside wp-admin/** or wp-includes/**
	if strings.HasPrefix(relPosix, "wp-admin/") || strings.HasPrefix(relPosix, "wp-includes/") {
		target := filepath.Join(verifiedDocRoot, filepath.FromSlash(relPosix))
		st, lErr := os.Lstat(target)
		if lErr != nil || st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return WatchOutcome{Handled: true}
		}
		raw, rErr := guard.ReadRegularFileSafe(target, maxSingleCoreFileBytes)
		if rErr != nil {
			return WatchOutcome{Handled: false}
		}
		if !isSuspiciousCoreExecutable(relPosix, raw) {
			return WatchOutcome{Handled: true}
		}
		if !shouldHeal {
			s.markIntegrityClean(inst, false)
			s.recordEvent("critical", "core_unknown_exec", inst, "Detected unknown executable in Core directory: "+relPosix)
			return WatchOutcome{Handled: true}
		}

		qItem, qErr := s.Quarantine.StoreTamperedFile(inst, relPosix, ReasonUnknownExecutable, ActionQuarantinedRemoved, nil, raw)

		s.pushSuppression(inst.ID)
		_ = os.Chmod(target, 0o644)
		rmErr := os.Remove(target)
		s.popSuppression(inst.ID)
		if rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			if qErr == nil && qItem.ID != "" {
				_ = s.Quarantine.DeleteItem(qItem.ID, "", true)
			}
			return WatchOutcome{Handled: false}
		}

		s.markIntegrityClean(inst, true)
		s.recordEvent("critical", "core_quarantine", inst, "Quarantined unknown executable backdoor "+relPosix)
		s.recordInterventionAndCheckThrash(acct, inst, manifest)
		return WatchOutcome{Handled: true, RemovedFile: true}
	}
	return WatchOutcome{Handled: true}
}

func (s *Shield) recordInterventionAndCheckThrash(acct dausers.Account, inst store.InstanceRecord, manifest *CoreManifest) bool {
	now := time.Now()
	cutoff := now.Add(-s.ThrashWindow)

	s.mu.Lock()
	hist := s.thrashHistory[inst.ID]
	kept := hist[:0]
	for _, ts := range hist {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	s.thrashHistory[inst.ID] = kept
	count := len(kept)
	s.mu.Unlock()

	if count < s.ThrashThreshold {
		return false
	}

	// Anti-Thrashing Escalation (TC-05): escalate instance immediately to Fortress Core Lock!
	latest, err := s.Store.GetInstance(inst.ID)
	if err != nil {
		latest = inst
	}
	if latest.CoreShieldMode == config.ShieldModeFortressLock {
		return true
	}

	s.pushSuppression(latest.ID)
	lockErr := s.Locker.LockInstance(acct, latest, manifest)
	s.popSuppression(latest.ID)
	if lockErr != nil {
		return false
	}

	if s.watcher != nil {
		s.watcher.UnwatchInstance(latest.ID)
	}
	latest.CoreShieldMode = config.ShieldModeFortressLock
	latest.CoreIntegrityClean = true
	_, _ = s.Store.UpsertInstance(latest)

	s.recordEvent(
		"critical",
		"core_thrash_lock",
		latest,
		fmt.Sprintf("Anti-Thrashing guard triggered (%d attacks within %v): escalated site to Fortress Core Lock (root:%s)", count, s.ThrashWindow, acct.Username),
	)
	return true
}

// VerifyAndHealInstance performs a full SHA-256 checksum & unknown-executable audit on an instance,
// automatically healing and quarantining anomalies when forceHeal == true or CoreShieldMode == "auto_heal".
func (s *Shield) VerifyAndHealInstance(
	ctx context.Context,
	acct dausers.Account,
	instanceID string,
	forceHeal bool,
) (VerifyReport, error) {
	started := time.Now()
	inst, err := s.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return VerifyReport{}, err
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return VerifyReport{}, err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return VerifyReport{}, err
	}

	manifest, err := s.Cache.EnsureVerifiedCore(ctx, inst.WPVersion, inst.Locale)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("load verified WordPress Core %s (%s): %w", inst.WPVersion, inst.Locale, err)
	}

	shouldHeal := forceHeal || inst.CoreShieldMode == config.ShieldModeAutoHeal || inst.CoreShieldMode == config.ShieldModeFortressLock
	wasLocked := inst.CoreShieldMode == config.ShieldModeFortressLock || s.Locker.IsLockedInMemory(inst.ID)

	s.pushSuppression(inst.ID)
	defer s.popSuppression(inst.ID)

	if shouldHeal && wasLocked {
		_ = s.Locker.UnlockInstance(acct, inst, manifest)
	}

	rep := VerifyReport{
		InstanceID:   inst.ID,
		Domain:       inst.Domain + inst.SubPath,
		WPVersion:    inst.WPVersion,
		Locale:       manifest.Locale,
		Mode:         inst.CoreShieldMode,
		CheckedFiles: len(manifest.Files),
	}

	interventions := 0

	// 1. Verify every official Core file in manifest
	for relPosix, expected := range manifest.Files {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		if s.Quarantine.IsWhitelisted(inst.ID, relPosix) {
			continue
		}
		target := filepath.Join(verifiedDocRoot, filepath.FromSlash(relPosix))
		st, lErr := os.Lstat(target)
		if lErr != nil {
			if errors.Is(lErr, os.ErrNotExist) {
				rep.MissingFiles = append(rep.MissingFiles, relPosix)
				if shouldHeal {
					if cleanPath, cErr := s.Cache.CleanFilePath(manifest.Version, manifest.Locale, relPosix); cErr == nil {
						if cleanBytes, rErr := os.ReadFile(cleanPath); rErr == nil {
							if writeGuardedCoreFile(guard, acct, target, cleanBytes, 0o644) == nil {
								rep.HealedFiles = append(rep.HealedFiles, relPosix)
								interventions++
							}
						}
					}
				}
			}
			continue
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			rep.ModifiedFiles = append(rep.ModifiedFiles, relPosix)
			continue
		}

		raw, rErr := guard.ReadRegularFileSafe(target, maxSingleCoreFileBytes)
		if rErr != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) == expected.SHA256 {
			continue
		}

		rep.ModifiedFiles = append(rep.ModifiedFiles, relPosix)
		if shouldHeal {
			if cleanPath, cErr := s.Cache.CleanFilePath(manifest.Version, manifest.Locale, relPosix); cErr == nil {
				if cleanBytes, cReadErr := os.ReadFile(cleanPath); cReadErr == nil {
					if qItem, qErr := s.Quarantine.StoreTamperedFile(inst, relPosix, ReasonModifiedCoreFile, ActionAutoHealed, cleanBytes, raw); qErr == nil {
						rep.QuarantinedIDs = append(rep.QuarantinedIDs, qItem.ID)
					}
					if writeGuardedCoreFile(guard, acct, target, cleanBytes, 0o644) == nil {
						rep.HealedFiles = append(rep.HealedFiles, relPosix)
						interventions++
					}
				}
			}
		}
	}

	// 2. Scan wp-admin/** and wp-includes/** for unknown executable backdoors
	for _, coreSub := range []string{"wp-admin", "wp-includes"} {
		subDir := filepath.Join(verifiedDocRoot, coreSub)
		_ = filepath.WalkDir(subDir, func(cur string, d os.DirEntry, wErr error) error {
			if wErr != nil {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || strings.HasPrefix(d.Name(), ".da-wptk-") {
				return nil
			}
			relOS, rErr := filepath.Rel(verifiedDocRoot, cur)
			if rErr != nil {
				return nil
			}
			relPosix := filepath.ToSlash(relOS)
			if _, isOfficial := manifest.Files[relPosix]; isOfficial {
				return nil
			}
			if s.Quarantine.IsWhitelisted(inst.ID, relPosix) {
				return nil
			}
			raw, rErr := guard.ReadRegularFileSafe(cur, maxSingleCoreFileBytes)
			if rErr != nil || !isSuspiciousCoreExecutable(relPosix, raw) {
				return nil
			}

			rep.UnknownExecutables = append(rep.UnknownExecutables, relPosix)
			if shouldHeal {
				if qItem, qErr := s.Quarantine.StoreTamperedFile(inst, relPosix, ReasonUnknownExecutable, ActionQuarantinedRemoved, nil, raw); qErr == nil {
					rep.QuarantinedIDs = append(rep.QuarantinedIDs, qItem.ID)
				}
				_ = os.Chmod(cur, 0o644)
				if os.Remove(cur) == nil {
					rep.HealedFiles = append(rep.HealedFiles, relPosix)
					interventions++
				}
			}
			return nil
		})
	}

	if shouldHeal && wasLocked {
		_ = s.Locker.LockInstance(acct, inst, manifest)
	}

	totalAnomalies := len(rep.ModifiedFiles) + len(rep.MissingFiles) + len(rep.UnknownExecutables)
	if totalAnomalies == 0 || (shouldHeal && len(rep.HealedFiles) >= totalAnomalies) {
		rep.Clean = true
	}

	if interventions > 0 {
		s.recordEvent(
			"warning",
			"core_auto_heal",
			inst,
			fmt.Sprintf("Core integrity heal completed: healed=%d quarantined=%d", len(rep.HealedFiles), len(rep.QuarantinedIDs)),
		)
	}

	inst.CoreIntegrityClean = rep.Clean
	_, _ = s.Store.UpsertInstance(inst)

	if s.watcher != nil && (inst.CoreShieldMode == config.ShieldModeAutoHeal || inst.CoreShieldMode == config.ShieldModeMonitor) {
		_ = s.watcher.SyncInstance(inst.ID, verifiedDocRoot)
	}

	rep.ElapsedMillis = time.Since(started).Milliseconds()
	return rep, nil
}

// SetMode switches an instance between `monitor`, `auto_heal`, and `fortress_lock`, enforcing hosting package policies.
func (s *Shield) SetMode(
	ctx context.Context,
	acct dausers.Account,
	instanceID string,
	mode string,
	enforcePackagePolicy bool,
) (store.InstanceRecord, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case config.ShieldModeMonitor, config.ShieldModeAutoHeal, config.ShieldModeFortressLock:
	default:
		return store.InstanceRecord{}, fmt.Errorf("invalid core_shield_mode %q (expected monitor, auto_heal, or fortress_lock)", mode)
	}

	if enforcePackagePolicy && mode == config.ShieldModeFortressLock && s.Policies != nil {
		if pol, err := s.Policies.ResolvePackagePolicy(acct.Package); err == nil && !pol.AllowCoreFortressLock {
			return store.InstanceRecord{}, errors.New("Fortress Core Lock is disabled for your hosting package")
		}
	}

	inst, err := s.Store.GetInstanceForOwner(strings.TrimSpace(instanceID), acct.Username)
	if err != nil {
		return store.InstanceRecord{}, err
	}

	manifest, _ := s.Cache.GetCachedManifest(inst.WPVersion, inst.Locale)
	if manifest == nil {
		manifest, _ = s.Cache.EnsureVerifiedCore(ctx, inst.WPVersion, inst.Locale)
	}

	s.pushSuppression(inst.ID)
	defer s.popSuppression(inst.ID)

	if mode == config.ShieldModeFortressLock {
		// Heal any tampered core files BEFORE locking so we never freeze an infected Core!
		if manifest != nil {
			_, _ = s.VerifyAndHealInstance(ctx, acct, inst.ID, true)
			if refreshed, gErr := s.Store.GetInstance(inst.ID); gErr == nil {
				inst = refreshed
			}
		}
		if err := s.Locker.LockInstance(acct, inst, manifest); err != nil {
			return store.InstanceRecord{}, err
		}
	} else if inst.CoreShieldMode == config.ShieldModeFortressLock || s.Locker.IsLockedInMemory(inst.ID) {
		if err := s.Locker.UnlockInstance(acct, inst, manifest); err != nil {
			return store.InstanceRecord{}, err
		}
	}

	// Reset anti-thrashing history when mode is explicitly changed
	s.mu.Lock()
	delete(s.thrashHistory, inst.ID)
	s.mu.Unlock()

	inst.CoreShieldMode = mode
	if mode == config.ShieldModeFortressLock {
		inst.CoreIntegrityClean = true
	}
	saved, err := s.Store.UpsertInstance(inst)
	if err != nil {
		return store.InstanceRecord{}, err
	}
	s.SyncInstanceWatch(saved)
	return saved, nil
}

// PrepareUserBackup temporarily unlocks all Fortress-Locked WordPress sites of `owner` prior to DirectAdmin Full Backup (TC-06).
func (s *Shield) PrepareUserBackup(owner string) ([]string, error) {
	if err := config.ValidateIdentifier(owner); err != nil {
		return nil, err
	}
	acct, ok := s.resolveAccount(owner)
	if !ok {
		return nil, fmt.Errorf("DirectAdmin user %q not found", owner)
	}

	instances := s.Store.ListInstancesByOwner(owner)
	var unlockedIDs []string
	for _, inst := range instances {
		if inst.CoreShieldMode != config.ShieldModeFortressLock && !s.Locker.IsLockedInMemory(inst.ID) {
			continue
		}
		s.pushSuppression(inst.ID)
		manifest, _ := s.Cache.GetCachedManifest(inst.WPVersion, inst.Locale)
		if err := s.Locker.UnlockInstance(acct, inst, manifest); err != nil {
			s.popSuppression(inst.ID)
			return unlockedIDs, err
		}
		unlockedIDs = append(unlockedIDs, inst.ID)
	}

	s.Locker.mu.Lock()
	if len(unlockedIDs) > 0 {
		s.Locker.held[owner] = unlockedIDs
	} else {
		delete(s.Locker.held, owner)
	}
	s.Locker.saveStateLocked()
	s.Locker.mu.Unlock()

	return unlockedIDs, nil
}

// FinishUserBackup immediately re-applies Fortress Core Lock to all sites held during DirectAdmin Backup (TC-06).
func (s *Shield) FinishUserBackup(owner string) ([]string, error) {
	if err := config.ValidateIdentifier(owner); err != nil {
		return nil, err
	}
	acct, ok := s.resolveAccount(owner)
	if !ok {
		return nil, fmt.Errorf("DirectAdmin user %q not found", owner)
	}

	s.Locker.mu.Lock()
	heldIDs := append([]string(nil), s.Locker.held[owner]...)
	delete(s.Locker.held, owner)
	s.Locker.saveStateLocked()
	s.Locker.mu.Unlock()

	var relocked []string
	for _, id := range heldIDs {
		inst, err := s.Store.GetInstance(id)
		if err == nil && !inst.Detached && inst.CoreShieldMode == config.ShieldModeFortressLock {
			manifest, _ := s.Cache.GetCachedManifest(inst.WPVersion, inst.Locale)
			if lErr := s.Locker.LockInstance(acct, inst, manifest); lErr == nil {
				relocked = append(relocked, id)
			}
		}
		s.popSuppression(id)
	}
	return relocked, nil
}

// CleanupInstance releases OS locks, unregisters inotify watches, and purges quarantine entries for an instance.
func (s *Shield) CleanupInstance(acct dausers.Account, inst store.InstanceRecord) {
	s.pushSuppression(inst.ID)
	defer s.popSuppression(inst.ID)

	if s.watcher != nil {
		s.watcher.UnwatchInstance(inst.ID)
	}
	if inst.CoreShieldMode == config.ShieldModeFortressLock || s.Locker.IsLockedInMemory(inst.ID) {
		manifest, _ := s.Cache.GetCachedManifest(inst.WPVersion, inst.Locale)
		_ = s.Locker.UnlockInstance(acct, inst, manifest)
	}
	_ = s.Quarantine.PurgeInstance(inst.Owner, inst.ID)
}

// CleanupOwner releases watches and purges quarantine data for a destroyed DirectAdmin user.
func (s *Shield) CleanupOwner(owner string) {
	if s.Store != nil {
		for _, inst := range s.Store.ListInstancesByOwner(owner) {
			if s.watcher != nil {
				s.watcher.UnwatchInstance(inst.ID)
			}
		}
	}
	_ = s.Quarantine.PurgeOwner(owner)
}

func (s *Shield) resolveAccount(owner string) (dausers.Account, bool) {
	if s.Users != nil {
		if acct, ok := s.Users.LookupByUsername(owner); ok {
			return acct, true
		}
	}
	return dausers.Account{}, false
}

func (s *Shield) markIntegrityClean(inst store.InstanceRecord, clean bool) {
	if s.Store == nil {
		return
	}
	latest, err := s.Store.GetInstance(inst.ID)
	if err != nil {
		return
	}
	if latest.CoreIntegrityClean != clean {
		latest.CoreIntegrityClean = clean
		_, _ = s.Store.UpsertInstance(latest)
	}
}

func (s *Shield) recordEvent(severity, category string, inst store.InstanceRecord, msg string) {
	if s.Store == nil {
		return
	}
	s.Store.RecordSecurityEvent(store.SecurityAuditEvent{
		Severity:   severity,
		Category:   category,
		Owner:      inst.Owner,
		InstanceID: inst.ID,
		Message:    msg,
	})
}

func isSuspiciousCoreExecutable(relPosix string, content []byte) bool {
	ext := strings.ToLower(filepath.Ext(relPosix))
	switch ext {
	case ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar", ".pl", ".py", ".cgi", ".sh", ".asp", ".aspx", ".jsp":
		return true
	}
	sample := content
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	lower := bytes.ToLower(sample)
	return bytes.Contains(lower, []byte("<?php")) || bytes.Contains(lower, []byte("<?="))
}
