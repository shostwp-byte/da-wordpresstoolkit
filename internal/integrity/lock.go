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

	// Ensure wp-content exists and stays owned by <user>:<user>
	wpContent := filepath.Join(verifiedDocRoot, "wp-content")
	if st, err := os.Lstat(wpContent); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
		_ = releaseKernelCoreLock(wpContent, true, acct.UID, acct.GID)
	}

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
			if canonicalRootCoreFiles[name] || (manifest != nil && manifest.Files[name].SHA256 != "") {
				p := filepath.Join(verifiedDocRoot, name)
				if st, lErr := os.Lstat(p); lErr == nil && st.Mode()&os.ModeSymlink == 0 && st.Mode().IsRegular() {
					_ = releaseKernelCoreLock(p, false, acct.UID, acct.GID)
				}
			}
		}
	}

	l.mu.Lock()
	delete(l.locked, inst.ID)
	l.mu.Unlock()
	return nil
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
