package integrity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

const fortressDirectFSMUFile = "da-wptk-direct-fs.php"

const fortressDirectFSMUCode = `<?php
/**
 * Managed by WordPress Manager Fortress Core Lock.
 * Preserves native 'direct' filesystem updates for wp-content (plugins, themes, languages)
 * while WordPress Core (wp-admin, wp-includes) is protected by root ownership.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter( 'filesystem_method', static function ( $method, $args, $context ) {
	if ( defined( 'FS_METHOD' ) && FS_METHOD ) {
		return $method;
	}
	$ctx = is_string( $context ) && $context !== '' ? wp_normalize_path( $context ) : '';
	$wp_content = defined( 'WP_CONTENT_DIR' ) ? wp_normalize_path( WP_CONTENT_DIR ) : '';
	if ( $ctx !== '' && $wp_content !== '' && strpos( rtrim( $ctx, '/' ) . '/', rtrim( $wp_content, '/' ) . '/' ) === 0 ) {
		return 'direct';
	}
	if ( $ctx === '' || @is_writable( $ctx ) ) {
		return 'direct';
	}
	return $method;
}, 999, 3 );
`

// Canonical root-level WordPress Core files inside DocRoot (never wp-config.php or .htaccess).
var canonicalRootCoreFiles = map[string]bool{
	"index.php":            true,
	"license.txt":          true,
	"readme.html":          true,
	"wp-activate.php":      true,
	"wp-blog-header.php":   true,
	"wp-comments-post.php": true,
	"wp-config-sample.php": true,
	"wp-cron.php":          true,
	"wp-links-opml.php":    true,
	"wp-load.php":          true,
	"wp-login.php":         true,
	"wp-mail.php":          true,
	"wp-settings.php":      true,
	"wp-signup.php":        true,
	"wp-trackback.php":     true,
	"xmlrpc.php":           true,
}

type backupHoldState struct {
	HeldByOwner map[string][]string `json:"held_by_owner"` // owner -> []instanceID temporarily unlocked for DA Backup
}

// CoreLocker manages Fortress Core Lock (`root:<user> 0644/0755`) and DirectAdmin Backup Pre/Post holds (TC-06).
type CoreLocker struct {
	StateDir string

	mu     sync.Mutex
	held   map[string][]string
	locked map[string]bool
}

func newCoreLocker(stateDir string) *CoreLocker {
	l := &CoreLocker{
		StateDir: stateDir,
		held:     make(map[string][]string),
		locked:   make(map[string]bool),
	}
	l.loadState()
	return l
}

func (l *CoreLocker) holdPath() string {
	return filepath.Join(l.StateDir, "backup_locks.json")
}

func (l *CoreLocker) loadState() {
	raw, err := os.ReadFile(l.holdPath())
	if err != nil {
		return
	}
	var st backupHoldState
	if json.Unmarshal(raw, &st) == nil && st.HeldByOwner != nil {
		l.held = st.HeldByOwner
	}
}

func (l *CoreLocker) saveStateLocked() {
	_ = os.MkdirAll(l.StateDir, 0o700)
	raw, err := json.MarshalIndent(backupHoldState{HeldByOwner: l.held}, "", "  ")
	if err != nil {
		return
	}
	tmp := l.holdPath() + ".tmp"
	if os.WriteFile(tmp, append(raw, '\n'), 0o600) == nil {
		_ = os.Rename(tmp, l.holdPath())
	}
}

// LockInstance transitions Core directories (`wp-admin`, `wp-includes`, `DocRoot`) and Core PHP files
// to `root:<user>` while leaving `wp-content/`, `wp-config.php`, and `.htaccess` owned by `<user>:<user>`.
func (l *CoreLocker) LockInstance(acct dausers.Account, inst store.InstanceRecord, manifest *CoreManifest) error {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return err
	}

	// Pre-create empty customer-owned .htaccess if absent so WordPress/LSCache can edit it in place while DocRoot is locked.
	htPath := filepath.Join(verifiedDocRoot, ".htaccess")
	if _, err := os.Lstat(htPath); errors.Is(err, os.ErrNotExist) {
		_ = writeGuardedCoreFile(guard, acct, htPath, []byte(""), 0o644)
	}

	// Ensure wp-content/** stays owned & writable by <user>:<user> and install direct-FS bridge for wp-content updates
	_ = EnsureCustomerWPContentOwned(guard, acct, verifiedDocRoot)
	muBridgePath := filepath.Join(verifiedDocRoot, "wp-content", "mu-plugins", fortressDirectFSMUFile)
	_ = writeGuardedCoreFile(guard, acct, muBridgePath, []byte(fortressDirectFSMUCode), 0o644)

	// 1. Lock root Core files in DocRoot
	rootFiles := make(map[string]bool, len(canonicalRootCoreFiles))
	for k := range canonicalRootCoreFiles {
		rootFiles[k] = true
	}
	if manifest != nil {
		for rel := range manifest.Files {
			if !strings.Contains(rel, "/") && rel != "wp-config.php" && rel != ".htaccess" {
				rootFiles[rel] = true
			}
		}
	}
	for name := range rootFiles {
		p := filepath.Join(verifiedDocRoot, name)
		st, lErr := os.Lstat(p)
		if lErr != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			continue
		}
		if err := applyKernelCoreLock(p, false, acct.GID); err != nil {
			return err
		}
	}

	// 2. Lock wp-admin/** and wp-includes/** recursively (post-order on directories so parent chmod 0555 in non-root tests never blocks child updates)
	for _, coreDirName := range []string{"wp-admin", "wp-includes"} {
		coreDir := filepath.Join(verifiedDocRoot, coreDirName)
		if err := lockTreeRecursive(coreDir, acct.GID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	// 3. Lock DocRoot directory last
	if err := applyKernelCoreLock(verifiedDocRoot, true, acct.GID); err != nil {
		return err
	}

	l.mu.Lock()
	l.locked[inst.ID] = true
	l.mu.Unlock()
	return nil
}

// UnlockInstance restores `<user>:<user>` ownership and writable modes across `DocRoot`, `wp-admin/**`, and `wp-includes/**`.
func (l *CoreLocker) UnlockInstance(acct dausers.Account, inst store.InstanceRecord, manifest *CoreManifest) error {
	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return err
	}

	// 1. Unlock DocRoot first so children can be modified cleanly
	_ = releaseKernelCoreLock(verifiedDocRoot, true, acct.UID, acct.GID)

	// 2. Unlock wp-admin/** and wp-includes/** (pre-order on directories)
	for _, coreDirName := range []string{"wp-admin", "wp-includes"} {
		coreDir := filepath.Join(verifiedDocRoot, coreDirName)
		if err := unlockTreeRecursive(coreDir, acct.UID, acct.GID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	// 3. Unlock root Core files in DocRoot
	entries, err := os.ReadDir(verifiedDocRoot)
	if err == nil {
		for _, ent := range entries {
			name := ent.Name()
			if name == "wp-config.php" || name == ".htaccess" || ent.IsDir() {
				continue
			}
			p := filepath.Join(verifiedDocRoot, name)
			st, lErr := os.Lstat(p)
			if lErr != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
				continue
			}
			if canonicalRootCoreFiles[name] || (manifest != nil && manifest.Files[name].SHA256 != "") || !isOwnedAndWritableBy(p, false, acct.UID) {
				_ = releaseKernelCoreLock(p, false, acct.UID, acct.GID)
			}
		}
	}

	// 4. Remove Fortress direct-FS MU bridge (no longer needed when Core is owned by <user>) & ensure wp-content/** is customer-owned
	muBridgePath := filepath.Join(verifiedDocRoot, "wp-content", "mu-plugins", fortressDirectFSMUFile)
	if st, lErr := os.Lstat(muBridgePath); lErr == nil && st.Mode()&os.ModeSymlink == 0 {
		_ = os.Remove(muBridgePath)
	}
	_ = EnsureCustomerWPContentOwned(guard, acct, verifiedDocRoot)

	l.mu.Lock()
	delete(l.locked, inst.ID)
	l.mu.Unlock()
	return nil
}

// NeedsCoreOwnershipRepair reports whether DocRoot or canonical WordPress Core files are not owned/writable by acct.UID
// (e.g., left locked as root:<user> when CoreShieldMode is NOT fortress_lock).
func NeedsCoreOwnershipRepair(acct dausers.Account, verifiedDocRoot string) bool {
	if !isOwnedAndWritableBy(verifiedDocRoot, true, acct.UID) {
		return true
	}
	dirChecks := []string{
		filepath.Join(verifiedDocRoot, "wp-admin"),
		filepath.Join(verifiedDocRoot, "wp-admin", "includes"),
		filepath.Join(verifiedDocRoot, "wp-includes"),
	}
	for _, d := range dirChecks {
		if st, err := os.Lstat(d); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			if !isOwnedAndWritableBy(d, true, acct.UID) {
				return true
			}
		}
	}
	fileChecks := []string{
		filepath.Join(verifiedDocRoot, "index.php"),
		filepath.Join(verifiedDocRoot, "wp-load.php"),
		filepath.Join(verifiedDocRoot, "wp-settings.php"),
		filepath.Join(verifiedDocRoot, "wp-admin", "admin.php"),
		filepath.Join(verifiedDocRoot, "wp-admin", "includes", "file.php"),
		filepath.Join(verifiedDocRoot, "wp-includes", "version.php"),
	}
	for _, f := range fileChecks {
		if st, err := os.Lstat(f); err == nil && st.Mode().IsRegular() && st.Mode()&os.ModeSymlink == 0 {
			if !isOwnedAndWritableBy(f, false, acct.UID) {
				return true
			}
		}
	}
	return false
}

// EnsureCustomerWPContentOwned ensures wp-content and its upgrade/extension directories exist and are owned/writable
// by <user>:<user> (acct.UID:acct.GID) so native wp-admin updates never fail WP_Upgrader::fs_connect() or prompt for FTP.
func EnsureCustomerWPContentOwned(guard *fsguard.Guard, acct dausers.Account, verifiedDocRoot string) error {
	wpContent := filepath.Join(verifiedDocRoot, "wp-content")
	if _, err := guard.VerifyProspectivePath(wpContent); err != nil {
		return err
	}
	if err := ensureCustomerDirNoSymlink(wpContent, acct.UID, acct.GID); err != nil {
		return err
	}

	// WordPress WP_Upgrader always stages downloads in wp-content/upgrade; ensure it exists and is customer-owned.
	upgradeDir := filepath.Join(wpContent, "upgrade")
	if _, err := guard.VerifyProspectivePath(upgradeDir); err == nil {
		_ = ensureCustomerDirNoSymlink(upgradeDir, acct.UID, acct.GID)
	}

	for _, sub := range []string{"upgrade", "plugins", "themes", "languages", "mu-plugins"} {
		subDir := filepath.Join(wpContent, sub)
		st, err := os.Lstat(subDir)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			continue
		}
		_ = repairCustomerTreeIfNeeded(subDir, acct.UID, acct.GID)
	}

	uploadsDir := filepath.Join(wpContent, "uploads")
	if st, err := os.Lstat(uploadsDir); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
		if !isOwnedAndWritableBy(uploadsDir, true, acct.UID) {
			_ = repairCustomerTreeIfNeeded(uploadsDir, acct.UID, acct.GID)
		}
	}
	return nil
}

func ensureCustomerDirNoSymlink(dirPath string, uid, gid uint32) error {
	st, err := os.Lstat(dirPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if mkErr := os.Mkdir(dirPath, 0o755); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
			return mkErr
		}
		return releaseKernelCoreLock(dirPath, true, uid, gid)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fsguard.ErrSymlinkBlocked
	}
	if !st.IsDir() {
		return fmt.Errorf("expected directory at %s", dirPath)
	}
	if !isOwnedAndWritableBy(dirPath, true, uid) {
		return releaseKernelCoreLock(dirPath, true, uid, gid)
	}
	return nil
}

func repairCustomerTreeIfNeeded(rootDir string, uid, gid uint32) error {
	return filepath.WalkDir(rootDir, func(cur string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		isDir := d.IsDir()
		if !isDir && !d.Type().IsRegular() {
			return nil
		}
		if !isOwnedAndWritableBy(cur, isDir, uid) {
			_ = releaseKernelCoreLock(cur, isDir, uid, gid)
		}
		return nil
	})
}

// IsLockedInMemory reports whether CoreLocker currently holds an active OS lock for instanceID.
func (l *CoreLocker) IsLockedInMemory(instanceID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.locked[instanceID]
}

func lockTreeRecursive(dirPath string, gid uint32) error {
	st, err := os.Lstat(dirPath)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fsguard.ErrSymlinkBlocked
	}
	if !st.IsDir() {
		return applyKernelCoreLock(dirPath, false, gid)
	}

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		child := filepath.Join(dirPath, ent.Name())
		cst, cErr := os.Lstat(child)
		if cErr != nil || cst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if cst.IsDir() {
			if err := lockTreeRecursive(child, gid); err != nil {
				return err
			}
		} else if cst.Mode().IsRegular() {
			if err := applyKernelCoreLock(child, false, gid); err != nil {
				return err
			}
		}
	}
	return applyKernelCoreLock(dirPath, true, gid)
}

func unlockTreeRecursive(dirPath string, uid, gid uint32) error {
	st, err := os.Lstat(dirPath)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !st.IsDir() {
		return releaseKernelCoreLock(dirPath, false, uid, gid)
	}

	if err := releaseKernelCoreLock(dirPath, true, uid, gid); err != nil {
		return err
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		child := filepath.Join(dirPath, ent.Name())
		cst, cErr := os.Lstat(child)
		if cErr != nil || cst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if cst.IsDir() {
			_ = unlockTreeRecursive(child, uid, gid)
		} else if cst.Mode().IsRegular() {
			_ = releaseKernelCoreLock(child, false, uid, gid)
		}
	}
	return nil
}

func writeGuardedCoreFile(guard *fsguard.Guard, acct dausers.Account, destPath string, data []byte, perm os.FileMode) error {
	parent := filepath.Dir(destPath)
	verifiedParent, err := guard.VerifyProspectivePath(parent)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(guard.AllowedRoot, verifiedParent)
	if err != nil {
		return err
	}
	cur := guard.AllowedRoot
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		if st, lErr := os.Lstat(cur); lErr != nil {
			if errors.Is(lErr, os.ErrNotExist) {
				if mkErr := os.Mkdir(cur, 0o755); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
					return mkErr
				}
				_ = chownNoFollow(cur, acct.UID, acct.GID)
			} else {
				return lErr
			}
		} else if st.Mode()&os.ModeSymlink != 0 {
			return fsguard.ErrSymlinkBlocked
		} else {
			// Ensure parent dir is writable if previously read-only in non-root mode
			_ = os.Chmod(cur, 0o755)
		}
	}

	target := filepath.Join(verifiedParent, filepath.Base(destPath))
	if st, lErr := os.Lstat(target); lErr == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fsguard.ErrSymlinkBlocked
		}
		// Clear read-only attribute before atomic replace if present
		_ = os.Chmod(target, 0o644)
	}

	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(verifiedParent, fmt.Sprintf(".da-wptk-heal-%s", hex.EncodeToString(rnd[:])))
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	_ = os.Chmod(tmp, perm)
	if err := chownNoFollow(tmp, acct.UID, acct.GID); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
