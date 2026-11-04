package dadomains

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
)

func TestListTargetsResolvesMainAddonClassicAndOverrideSubdomains(t *testing.T) {
	tmp := t.TempDir()
	daRoot := filepath.Join(tmp, "da_data")
	homeDir := filepath.Join(tmp, "home", "reno26")
	optPath := filepath.Join(tmp, "options.conf")

	_ = os.WriteFile(optPath, []byte("php1_release=8.3\nphp2_release=8.1\nphp3_release=8.4\n"), 0o644)

	userDir := filepath.Join(daRoot, "users", "reno26")
	domDir := filepath.Join(userDir, "domains")
	_ = os.MkdirAll(domDir, 0o755)

	_ = os.WriteFile(filepath.Join(userDir, "user.conf"), []byte("domain=renolabs-audio.com\n"), 0o600)
	_ = os.WriteFile(filepath.Join(userDir, "domains.list"), []byte("renolabs-audio.com\nbrand2.vn\n"), 0o600)

	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.conf"), []byte("ssl=ON\nphp1_select=3\n"), 0o600)
	_ = os.WriteFile(filepath.Join(domDir, "renolabs-audio.com.subdomains"), []byte("shop\nstaging\napp\n"), 0o600)
	// Override docroot and php1_select for 'app' subdomain
	_ = os.WriteFile(
		filepath.Join(domDir, "renolabs-audio.com.subdomains.docroot.override"),
		[]byte("app=documentroot%3D%2Fdomains%2Frenolabs-audio.com%2Fsubdomains%2Fapp%26php1_select%3D2\n"),
		0o600,
	)

	_ = os.WriteFile(filepath.Join(domDir, "brand2.vn.conf"), []byte("ssl=OFF\nphp1_select=1\n"), 0o600)

	// Create separated modern docroot on disk for 'staging.renolabs-audio.com'
	_ = os.MkdirAll(filepath.Join(homeDir, "domains", "staging.renolabs-audio.com", "public_html"), 0o755)

	res := NewResolver(daRoot, daphp.NewResolver(optPath, filepath.Join(tmp, "usr_local")))
	acct := dausers.Account{Username: "reno26", UID: 1005, GID: 1005, HomeDir: homeDir}

	targets, err := res.ListTargets(acct)
	if err != nil {
		t.Fatalf("ListTargets error: %v", err)
	}
	if len(targets) != 5 {
		t.Fatalf("expected 5 targets (1 main, 1 addon, 3 subdomains), got %d", len(targets))
	}

	byDom := make(map[string]DomainTarget)
	for _, tgt := range targets {
		byDom[tgt.Domain] = tgt
	}

	mainTgt := byDom["renolabs-audio.com"]
	if mainTgt.DomainType != DomainTypeMain || mainTgt.PHP.Version != "8.4" || !mainTgt.SSLActive {
		t.Fatalf("main target mismatch: %+v", mainTgt)
	}
	// Classic 'shop' subdomain lives under main public_html/shop -> MUST be in mainTgt.ExcludedRelPaths!
	if ownerSub, ok := mainTgt.ExcludedRelPaths["shop"]; !ok || ownerSub != "shop.renolabs-audio.com" {
		t.Fatalf("expected 'shop' to be excluded from main domain subdir scan, got: %+v", mainTgt.ExcludedRelPaths)
	}

	appTgt := byDom["app.renolabs-audio.com"]
	wantAppRoot := filepath.Join(homeDir, "domains", "renolabs-audio.com", "subdomains", "app")
	if appTgt.DocRoot != wantAppRoot || appTgt.PHP.Version != "8.1" {
		t.Fatalf("override subdomain 'app' mismatch: got root=%s php=%s", appTgt.DocRoot, appTgt.PHP.Version)
	}

	stagingTgt := byDom["staging.renolabs-audio.com"]
	wantStagingRoot := filepath.Join(homeDir, "domains", "staging.renolabs-audio.com", "public_html")
	if stagingTgt.DocRoot != wantStagingRoot {
		t.Fatalf("separated subdomain 'staging' docroot mismatch: %s", stagingTgt.DocRoot)
	}
}
