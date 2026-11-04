package fsguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestTC02_SymlinkAndTraversalEscapeBlocked verifies Acceptance Test Case TC-02:
// Symlinks pointing outside /home/<user>/domains/ (or traversal paths) are blocked and logged.
func TestTC02_SymlinkAndTraversalEscapeBlocked(t *testing.T) {
	tmp := t.TempDir()
	allowedRoot := filepath.Join(tmp, "home", "reno26", "domains")
	docRoot := filepath.Join(allowedRoot, "renolabs-audio.com", "public_html")
	outsideSecret := filepath.Join(tmp, "etc_shadow_mock")

	if err := os.MkdirAll(docRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideSecret, []byte("root:$6$secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	violations := 0
	g, err := New(allowedRoot, func(_, _ string) {
		violations++
	})
	if err != nil {
		t.Fatalf("New guard error: %v", err)
	}

	// 1. Legitimate file inside docRoot succeeds
	legitFile := filepath.Join(docRoot, "wp-config.php")
	if err := os.WriteFile(legitFile, []byte("<?php define('DB_NAME', 'reno26_wp1');"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := g.ReadRegularFileSafe(legitFile, 4096)
	if err != nil || len(data) == 0 {
		t.Fatalf("expected legitimate file read to succeed, got err=%v", err)
	}

	// 2. Traversal outside allowedRoot must be blocked immediately
	if _, err := g.ReadRegularFileSafe(outsideSecret, 4096); !errors.Is(err, ErrOutsideRoot) {
		t.Fatalf("TC-02 FAILED: expected ErrOutsideRoot on external path, got %v", err)
	}

	// 3. Symlink inside public_html pointing to /etc/shadow (if OS permits creating symlink in test)
	symPath := filepath.Join(docRoot, "evil-wp-config.php")
	if symErr := os.Symlink(outsideSecret, symPath); symErr == nil {
		if _, err := g.ReadRegularFileSafe(symPath, 4096); !errors.Is(err, ErrSymlinkBlocked) {
			t.Fatalf("TC-02 FAILED: expected ErrSymlinkBlocked on symlinked wp-config.php, got %v", err)
		}
	}

	if violations == 0 {
		t.Fatal("expected security violation callback to be triggered")
	}
}
