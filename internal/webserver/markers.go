package webserver

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
)

func markerStart(ruleID string) string {
	return "# BEGIN DA-WPTK:" + ruleID
}

func markerEnd(ruleID string) string {
	return "# END DA-WPTK:" + ruleID
}

// HasMarkerBlock reports whether content contains a managed DA-WPTK rule block.
func HasMarkerBlock(content, ruleID string) bool {
	start := markerStart(ruleID)
	end := markerEnd(ruleID)
	sIdx := strings.Index(content, start)
	if sIdx < 0 {
		return false
	}
	eIdx := strings.Index(content[sIdx:], end)
	return eIdx >= 0
}

// UpsertMarkerBlock inserts or replaces a managed rule block while preserving customer rules.
// When prepend is true, new blocks are placed at the top of .htaccess so security blocks run
// BEFORE WordPress's catch-all `RewriteRule . /index.php [L]`.
func UpsertMarkerBlock(existing, ruleID, body string, prepend bool) (string, bool) {
	norm := strings.ReplaceAll(existing, "\r\n", "\n")
	trimmedBody := strings.Trim(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	fullBlock := markerStart(ruleID) + "\n" + trimmedBody + "\n" + markerEnd(ruleID)

	start := markerStart(ruleID)
	end := markerEnd(ruleID)

	sIdx := strings.Index(norm, start)
	if sIdx >= 0 {
		relEnd := strings.Index(norm[sIdx:], end)
		if relEnd >= 0 {
			eIdx := sIdx + relEnd + len(end)
			currentBlock := norm[sIdx:eIdx]
			if currentBlock == fullBlock {
				return norm, false
			}
			updated := norm[:sIdx] + fullBlock + norm[eIdx:]
			return normalizeNewlines(updated), true
		}
	}

	cleaned := strings.TrimSpace(norm)
	if cleaned == "" {
		return fullBlock + "\n", true
	}
	if prepend {
		return fullBlock + "\n\n" + cleaned + "\n", true
	}
	return cleaned + "\n\n" + fullBlock + "\n", true
}

// RemoveMarkerBlock deletes a managed rule block from content if present.
func RemoveMarkerBlock(existing, ruleID string) (string, bool) {
	norm := strings.ReplaceAll(existing, "\r\n", "\n")
	start := markerStart(ruleID)
	end := markerEnd(ruleID)

	sIdx := strings.Index(norm, start)
	if sIdx < 0 {
		return norm, false
	}
	relEnd := strings.Index(norm[sIdx:], end)
	if relEnd < 0 {
		return norm, false
	}
	eIdx := sIdx + relEnd + len(end)
	if eIdx < len(norm) && norm[eIdx] == '\n' {
		eIdx++
	}
	updated := norm[:sIdx] + norm[eIdx:]
	return normalizeNewlines(updated), true
}

func normalizeNewlines(s string) string {
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return ""
	}
	return trimmed + "\n"
}

func readGuardedCustomerFile(guard *fsguard.Guard, targetPath string) (string, error) {
	raw, err := guard.ReadRegularFileSafe(targetPath, 512*1024)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n"), nil
}

func ensureGuardedCustomerDir(guard *fsguard.Guard, acct dausers.Account, dirPath string) (string, error) {
	verified, err := guard.VerifyProspectivePath(dirPath)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(guard.AllowedRoot, verified)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fsguard.ErrOutsideRoot
	}
	cur := guard.AllowedRoot
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		st, lErr := os.Lstat(cur)
		if lErr != nil {
			if errors.Is(lErr, os.ErrNotExist) {
				if mkErr := os.Mkdir(cur, 0o755); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
					return "", mkErr
				}
				_ = chownNoFollow(cur, acct.UID, acct.GID)
				continue
			}
			return "", lErr
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: %s", fsguard.ErrSymlinkBlocked, cur)
		}
		if !st.IsDir() {
			return "", fmt.Errorf("expected directory at %s", cur)
		}
	}
	return verified, nil
}

func writeGuardedCustomerFileAtomic(guard *fsguard.Guard, acct dausers.Account, targetPath string, content string, perm os.FileMode) error {
	parentDir := filepath.Dir(targetPath)
	verifiedParent, err := ensureGuardedCustomerDir(guard, acct, parentDir)
	if err != nil {
		return err
	}
	leaf := filepath.Base(targetPath)
	verifiedTarget := filepath.Join(verifiedParent, leaf)
	if st, lErr := os.Lstat(verifiedTarget); lErr == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: refusing to overwrite symlink %s", fsguard.ErrSymlinkBlocked, verifiedTarget)
		}
		if st.IsDir() {
			return fmt.Errorf("refusing to overwrite directory %s", verifiedTarget)
		}
	}

	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmpPath := filepath.Join(verifiedParent, fmt.Sprintf(".da-wptk-tmp-%s", hex.EncodeToString(rnd[:])))

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	_ = os.Chmod(tmpPath, perm)
	if err := chownNoFollow(tmpPath, acct.UID, acct.GID); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, verifiedTarget); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
