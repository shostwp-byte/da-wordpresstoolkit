package fsguard

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrSymlinkBlocked = errors.New("security violation: symbolic link traversal blocked")
	ErrOutsideRoot    = errors.New("security violation: path resolves outside user domains root")
)

// ViolationReporter optionally records symlink/TOCTOU escape attempts to the daemon security log.
type ViolationReporter func(targetPath, reason string)

// Guard confines all filesystem operations strictly within a DirectAdmin user's domains directory.
type Guard struct {
	AllowedRoot string // e.g., /home/reno26/domains
	OnViolation ViolationReporter
}

// New creates a path confinement guard rooted at userHomeDir/domains (or an explicit allowedRoot).
func New(allowedRoot string, onViolation ViolationReporter) (*Guard, error) {
	clean := filepath.Clean(strings.TrimSpace(allowedRoot))
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return nil, errors.New("invalid allowedRoot for fsguard")
	}
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: allowedRoot %s is itself a symlink", ErrSymlinkBlocked, clean)
		}
		if resolved, rErr := filepath.EvalSymlinks(clean); rErr == nil {
			clean = filepath.Clean(resolved)
		}
	}
	return &Guard{
		AllowedRoot: clean,
		OnViolation: onViolation,
	}, nil
}

// VerifyExistingPath ensures targetPath exists, contains no symlink components below AllowedRoot,
// and resolves strictly inside AllowedRoot (TC-02).
func (g *Guard) VerifyExistingPath(targetPath string) (string, error) {
	cleanTarget := filepath.Clean(targetPath)
	if !isSubpathOrEqual(g.AllowedRoot, cleanTarget) {
		g.report(targetPath, "lexical path outside allowed domains root")
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, targetPath)
	}

	// Walk every segment below AllowedRoot using Lstat so intermediate symlinks are caught immediately
	if err := g.walkNoSymlinks(cleanTarget, true); err != nil {
		return "", err
	}

	resolved, err := filepath.EvalSymlinks(cleanTarget)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if !isSubpathOrEqual(g.AllowedRoot, resolved) {
		g.report(targetPath, "EvalSymlinks escaped allowed domains root -> "+resolved)
		return "", fmt.Errorf("%w: %s -> %s", ErrOutsideRoot, targetPath, resolved)
	}
	return resolved, nil
}

// VerifyProspectivePath validates a target directory path that may not yet exist on disk
// (e.g., before creating a new subdirectory install /blog), rejecting any symlinked existing ancestor.
func (g *Guard) VerifyProspectivePath(targetPath string) (string, error) {
	cleanTarget := filepath.Clean(targetPath)
	if !isSubpathOrEqual(g.AllowedRoot, cleanTarget) {
		g.report(targetPath, "prospective path outside allowed domains root")
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, targetPath)
	}
	if err := g.walkNoSymlinks(cleanTarget, false); err != nil {
		return "", err
	}
	return cleanTarget, nil
}

// ReadRegularFileSafe opens a customer file without following symlinks (O_NOFOLLOW on Linux)
// after confirming every parent segment lies inside AllowedRoot, reading at most maxBytes.
func (g *Guard) ReadRegularFileSafe(targetPath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	verified, err := g.VerifyExistingPath(targetPath)
	if err != nil {
		return nil, err
	}

	f, err := openNoFollow(verified)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		g.report(targetPath, "openNoFollow rejected target: "+err.Error())
		return nil, fmt.Errorf("%w: %v", ErrSymlinkBlocked, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		g.report(targetPath, "non-regular file rejected (FIFO/device/socket)")
		return nil, fmt.Errorf("refusing to read non-regular file %s", targetPath)
	}

	return io.ReadAll(io.LimitReader(f, maxBytes))
}

// VerifyChildUnderVerifiedRoot checks only the relative child segments beneath an already-verified root directory,
// avoiding redundant full-prefix EvalSymlinks syscalls during high-throughput directory scans while blocking symlinks.
func (g *Guard) VerifyChildUnderVerifiedRoot(verifiedRoot string, maxBytesHint bool, relSegments ...string) (string, error) {
	_ = maxBytesHint
	cur := filepath.Clean(verifiedRoot)
	if !isSubpathOrEqual(g.AllowedRoot, cur) {
		g.report(cur, "base directory outside allowed domains root")
		return "", fmt.Errorf("%w: %s", ErrOutsideRoot, cur)
	}
	for _, seg := range relSegments {
		if seg == "" || seg == "." {
			continue
		}
		if strings.ContainsAny(seg, `/\`) || seg == ".." {
			g.report(cur, "invalid relative segment: "+seg)
			return "", fmt.Errorf("%w: %s", ErrOutsideRoot, seg)
		}
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			g.report(cur, "symbolic link child segment blocked")
			return "", fmt.Errorf("%w: %s", ErrSymlinkBlocked, cur)
		}
	}
	return cur, nil
}

// ReadRegularFileUnderVerifiedRoot safely reads a regular file beneath an already-verified parent directory
// without following symlinks on any intermediate or leaf segment.
func (g *Guard) ReadRegularFileUnderVerifiedRoot(verifiedRoot string, maxBytes int64, relSegments ...string) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	target, err := g.VerifyChildUnderVerifiedRoot(verifiedRoot, false, relSegments...)
	if err != nil {
		return nil, err
	}
	f, err := openNoFollow(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		g.report(target, "openNoFollow rejected target: "+err.Error())
		return nil, fmt.Errorf("%w: %v", ErrSymlinkBlocked, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		g.report(target, "non-regular file rejected (FIFO/device/socket)")
		return nil, fmt.Errorf("refusing to read non-regular file %s", target)
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

func (g *Guard) walkNoSymlinks(cleanTarget string, mustExist bool) error {
	rel, err := filepath.Rel(g.AllowedRoot, cleanTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		g.report(cleanTarget, "relative path escaped allowed root")
		return fmt.Errorf("%w: %s", ErrOutsideRoot, cleanTarget)
	}
	if rel == "." {
		st, err := os.Lstat(g.AllowedRoot)
		if err != nil {
			if !mustExist && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			g.report(g.AllowedRoot, "allowed root is a symlink")
			return fmt.Errorf("%w: %s", ErrSymlinkBlocked, g.AllowedRoot)
		}
		return nil
	}

	parts := strings.Split(rel, string(filepath.Separator))
	cur := g.AllowedRoot
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		cur = filepath.Join(cur, seg)
		st, err := os.Lstat(cur)
		if err != nil {
			if !mustExist && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			g.report(cur, "symbolic link segment detected")
			return fmt.Errorf("%w: %s", ErrSymlinkBlocked, cur)
		}
	}
	return nil
}

func (g *Guard) report(path, reason string) {
	if g.OnViolation != nil {
		g.OnViolation(path, reason)
	}
}

func isSubpathOrEqual(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
