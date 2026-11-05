package webserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

func TestDetectServerKindAndMarkerPreservation(t *testing.T) {
	tmp := t.TempDir()
	optConf := filepath.Join(tmp, "options.conf")
	if err := os.WriteFile(optConf, []byte("php1_release=8.3\nwebserver=openlitespeed\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ad := NewAdapter(optConf, filepath.Join(tmp, "nginx"))
	if got := ad.DetectKind(); got != KindOpenLiteSpeed {
		t.Fatalf("expected KindOpenLiteSpeed, got %s", got)
	}

	wpDefault := "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n"
	updated, changed := UpsertMarkerBlock(wpDefault, RuleDisableXMLRPC, "<Files \"xmlrpc.php\">\nRequire all denied\n</Files>", true)
	if !changed {
		t.Fatal("expected marker insertion to report changed=true")
	}
	if !strings.HasPrefix(updated, "# BEGIN DA-WPTK:disable_xmlrpc") {
		t.Fatalf("security marker must prepend above WordPress catch-all rewrite, got:\n%s", updated)
	}
	if !strings.Contains(updated, "# BEGIN WordPress") {
		t.Fatal("customer WordPress .htaccess block must be preserved")
	}

	reverted, removed := RemoveMarkerBlock(updated, RuleDisableXMLRPC)
	if !removed || HasMarkerBlock(reverted, RuleDisableXMLRPC) {
		t.Fatal("expected marker block to be cleanly removed")
	}
	if !strings.Contains(reverted, "# BEGIN WordPress") {
		t.Fatal("removing DA-WPTK block must keep WordPress block intact")
	}
}

func TestOpenLiteSpeedDebouncedReloadCoalescesBursts(t *testing.T) {
	tmp := t.TempDir()
	optConf := filepath.Join(tmp, "options.conf")
	_ = os.WriteFile(optConf, []byte("webserver=openlitespeed\n"), 0o644)

	homeDir := filepath.Join(tmp, "home", "reno26")
	docRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "public_html")
	_ = os.MkdirAll(docRoot, 0o755)

	ad := NewAdapter(optConf, filepath.Join(tmp, "nginx"))
	ad.OLSReloadDebounce = 220 * time.Millisecond

	var reloadCalls atomic.Int32
	ad.ExecCommand = func(_ context.Context, bin string, args ...string) (string, error) {
		if strings.Contains(bin, "lswsctrl") && len(args) > 0 && args[0] == "reload" {
			reloadCalls.Add(1)
		}
		return "OK", nil
	}

	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}
	inst := store.InstanceRecord{ID: "wp_abc12345", Owner: "reno26", Domain: "renolabs-audio.com", DocRoot: docRoot}

	// Trigger 4 rapid rule mutations within the debounce window
	for _, r := range []string{RuleBlockUploadsPHP, RuleDisableXMLRPC, RuleBlockSensitiveFiles, RuleSecurityHeaders} {
		if err := ad.ApplyRule(context.Background(), acct, inst, r); err != nil {
			t.Fatalf("ApplyRule(%s): %v", r, err)
		}
	}

	time.Sleep(360 * time.Millisecond)
	if got := reloadCalls.Load(); got != 1 {
		t.Fatalf("expected 4 rapid OLS mutations to coalesce into exactly 1 graceful reload, got %d", got)
	}

	req := httptest.NewRequest(http.MethodGet, "http://renolabs-audio.com/wp-content/uploads/shell.php", nil)
	rec := httptest.NewRecorder()
	if !ad.EvaluateHTTPRequest(acct, inst, rec, req) || rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden after OLS graceful reload, got %d", rec.Code)
	}
}

func TestNginxSyntaxFailureAutoRollsBackSnippet(t *testing.T) {
	tmp := t.TempDir()
	optConf := filepath.Join(tmp, "options.conf")
	_ = os.WriteFile(optConf, []byte("webserver=nginx\n"), 0o644)

	ad := NewAdapter(optConf, filepath.Join(tmp, "nginx"))
	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005}
	inst := store.InstanceRecord{ID: "wp_nginx01", Owner: "reno26", Domain: "renolabs-audio.com"}

	failNextTest := false
	ad.ExecCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if len(args) > 0 && args[0] == "-t" && failNextTest {
			return "nginx: [emerg] invalid directive", errors.New("exit status 1")
		}
		return "syntax is ok", nil
	}

	if err := ad.ApplyRule(context.Background(), acct, inst, RuleBlockUploadsPHP); err != nil {
		t.Fatalf("initial Nginx rule failed: %v", err)
	}
	if !ad.IsRuleApplied(acct, inst, RuleBlockUploadsPHP) {
		t.Fatal("expected RuleBlockUploadsPHP to be active in Nginx snippet")
	}

	// Simulate nginx -t failing on next edit: previous working config MUST remain intact!
	failNextTest = true
	if err := ad.ApplyRule(context.Background(), acct, inst, RuleDisableXMLRPC); err == nil {
		t.Fatal("expected error when nginx -t fails")
	}
	if !ad.IsRuleApplied(acct, inst, RuleBlockUploadsPHP) {
		t.Fatal("previous working rule must be preserved after rollback")
	}
	if ad.IsRuleApplied(acct, inst, RuleDisableXMLRPC) {
		t.Fatal("failed rule must be rolled back from Nginx snippet")
	}
}

func TestSymlinkedHTAccessBlockedByFSGuard(t *testing.T) {
	tmp := t.TempDir()
	optConf := filepath.Join(tmp, "options.conf")
	_ = os.WriteFile(optConf, []byte("webserver=apache\n"), 0o644)

	homeDir := filepath.Join(tmp, "home", "reno26")
	docRoot := filepath.Join(homeDir, "domains", "evil.test", "public_html")
	_ = os.MkdirAll(docRoot, 0o755)
	outsideSecret := filepath.Join(tmp, "outside_target.conf")
	_ = os.WriteFile(outsideSecret, []byte("SENSITIVE\n"), 0o600)

	if err := os.Symlink(outsideSecret, filepath.Join(docRoot, ".htaccess")); err != nil {
		t.Skipf("symlink creation requires privilege on this host: %v", err)
	}

	ad := NewAdapter(optConf, filepath.Join(tmp, "nginx"))
	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}
	inst := store.InstanceRecord{ID: "wp_sym01", Owner: "reno26", Domain: "evil.test", DocRoot: docRoot}

	err := ad.ApplyRule(context.Background(), acct, inst, RuleDisableXMLRPC)
	if !errors.Is(err, fsguard.ErrSymlinkBlocked) {
		t.Fatalf("expected ErrSymlinkBlocked on symlinked .htaccess, got: %v", err)
	}
}
