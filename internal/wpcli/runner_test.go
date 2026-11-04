package wpcli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
)

func TestRunnerEnforcesUIDDropDomainPHPAndBlocksUnsafeFlags(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "reno26")
	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	if err := os.MkdirAll(docRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	var captured ExecSpec
	runner := NewRunner("/usr/local/bin/wp", "/var/cache/da-wptoolkit/wp-core")
	runner.NiceBin = ""
	runner.IoniceBin = ""
	runner.ExecCommand = func(_ context.Context, spec ExecSpec) (string, string, error) {
		captured = spec
		return `{"version":"6.7.1"}`, "", nil
	}

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}
	phpSel := daphp.Selection{Slot: 3, Version: "8.4", BinaryPath: "/usr/local/php84/bin/php"}

	// 1. Refuse root UID 0 or nobody 65534
	if _, err := runner.Run(context.Background(), CallOptions{
		Account: dausers.Account{Username: "root", UID: 0, HomeDir: homeDir},
		DocRoot: docRoot,
		Args:    []string{"core", "version"},
	}); err == nil {
		t.Fatal("expected UID 0 WP-CLI execution to be refused")
	}

	// 2. Refuse forbidden --allow-root or --exec flags
	if _, err := runner.Run(context.Background(), CallOptions{
		Account: acct,
		DocRoot: docRoot,
		PHP:     phpSel,
		Args:    []string{"core", "version", "--allow-root"},
	}); err == nil {
		t.Fatal("expected --allow-root flag to be blocked")
	}

	// 3. Valid call uses exact domain PHP binary, UID/GID 1005, and sanitized environment
	out, err := runner.Run(context.Background(), CallOptions{
		Account:     acct,
		DocRoot:     docRoot,
		PHP:         phpSel,
		SkipPlugins: true,
		Args:        []string{"option", "get", "siteurl"},
	})
	if err != nil || out == "" {
		t.Fatalf("expected valid Run to succeed, got err=%v out=%q", err, out)
	}
	if captured.Program != "/usr/local/php84/bin/php" || captured.UID != 1005 || captured.GID != 1005 {
		t.Fatalf("unexpected ExecSpec: %+v", captured)
	}
	joinedArgs := strings.Join(captured.Args, " ")
	if !strings.Contains(joinedArgs, "--skip-plugins") || !strings.Contains(joinedArgs, "disable_functions=") {
		t.Fatalf("missing expected WP-CLI sandbox flags: %s", joinedArgs)
	}
}
