package clonesync

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/database"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
)

var reservedSubdomainLabels = map[string]struct{}{
	"www":          {},
	"mail":         {},
	"ftp":          {},
	"smtp":         {},
	"pop":          {},
	"imap":         {},
	"webmail":      {},
	"cpanel":       {},
	"whm":          {},
	"autodiscover": {},
}

// EnsureTargetSubdomain resolves targetDomain if it already exists on the account, or auto-provisions
// `<subLabel>.<parentDomain>` when allowCreate is true and `<parentDomain>` is an owned Main/Addon domain.
func (e *Engine) EnsureTargetSubdomain(ctx context.Context, acct dausers.Account, targetDomain string, allowCreate bool) (dadomains.DomainTarget, bool, error) {
	if e.Domains == nil {
		return dadomains.DomainTarget{}, false, errors.New("domain resolver is not configured")
	}
	want := strings.ToLower(strings.TrimSpace(targetDomain))
	if err := config.ValidateDomainName(want); err != nil {
		return dadomains.DomainTarget{}, false, err
	}

	if existing, err := e.Domains.FindTarget(acct, want); err == nil {
		return existing, false, nil
	}
	if !allowCreate {
		return dadomains.DomainTarget{}, false, fmt.Errorf("domain or subdomain %q does not exist on account %s", want, acct.Username)
	}

	dotIdx := strings.IndexByte(want, '.')
	if dotIdx <= 0 || dotIdx >= len(want)-1 {
		return dadomains.DomainTarget{}, false, fmt.Errorf("cannot auto-create top-level domain %q", want)
	}
	subLabel := want[:dotIdx]
	parentDomain := want[dotIdx+1:]

	if _, reserved := reservedSubdomainLabels[subLabel]; reserved {
		return dadomains.DomainTarget{}, false, fmt.Errorf("subdomain label %q is reserved by system services", subLabel)
	}
	if strings.Contains(subLabel, ".") {
		return dadomains.DomainTarget{}, false, errors.New("multi-level nested subdomain labels are not supported")
	}

	parentTarget, pErr := e.Domains.FindTarget(acct, parentDomain)
	if pErr != nil || parentTarget.DomainType == dadomains.DomainTypeSubdomain {
		return dadomains.DomainTarget{}, false, fmt.Errorf("parent domain %q is not an active main/addon domain on account %s", parentDomain, acct.Username)
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return dadomains.DomainTarget{}, false, err
	}
	prospectiveDocRoot := filepath.Join(parentTarget.DocRoot, subLabel)
	verifiedSubDocRoot, err := guard.VerifyProspectivePath(prospectiveDocRoot)
	if err != nil {
		return dadomains.DomainTarget{}, false, err
	}

	// 1. Prefer DirectAdmin Local API (`CMD_API_SUBDOMAINS`) when Admin Login Key is configured
	apiUsed, apiErr := e.tryCreateSubdomainViaDAAPI(ctx, acct.Username, parentDomain, subLabel)
	if apiUsed && apiErr != nil {
		return dadomains.DomainTarget{}, false, apiErr
	}

	// 2. Fallback: register in DirectAdmin `<parentDomain>.subdomains` & create owned directory
	if !apiUsed {
		subListPath := filepath.Join(e.Domains.DADataRoot, "users", acct.Username, "domains", parentDomain+".subdomains")
		if err := appendSubdomainEntryAtomic(subListPath, subLabel); err != nil {
			return dadomains.DomainTarget{}, false, fmt.Errorf("register DirectAdmin subdomain metadata: %w", err)
		}
		if err := os.MkdirAll(verifiedSubDocRoot, 0o755); err != nil {
			return dadomains.DomainTarget{}, false, err
		}
		chownCustomerIfRoot(verifiedSubDocRoot, acct.UID, acct.GID)
		e.fireSubdomainCreateHooks(ctx, acct.Username, parentDomain, subLabel)
	}

	resolved, err := e.Domains.FindTarget(acct, want)
	if err != nil {
		return dadomains.DomainTarget{}, false, err
	}
	return resolved, true, nil
}

func (e *Engine) tryCreateSubdomainViaDAAPI(ctx context.Context, username, parentDomain, subLabel string) (configured bool, err error) {
	apiConf := e.DAAPIConfPath
	if apiConf == "" {
		apiConf = database.DefaultDAAPIConfPath
	}
	kv, err := readSimpleKV(apiConf)
	if err != nil || kv["login_key"] == "" {
		return false, nil
	}
	daURL := strings.TrimRight(kv["url"], "/")
	if daURL == "" {
		daURL = "https://127.0.0.1:2222"
	}
	adminUser := kv["admin_user"]
	if adminUser == "" {
		adminUser = "admin"
	}

	form := url.Values{}
	form.Set("action", "create")
	form.Set("domain", parentDomain)
	form.Set("subdomain", subLabel)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true},
	}
	cli := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, daURL+"/CMD_API_SUBDOMAINS", strings.NewReader(form.Encode()))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(adminUser+"|"+username, kv["login_key"])

	resp, err := cli.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return true, err
	}
	if resp.StatusCode >= 400 {
		return true, fmt.Errorf("DirectAdmin CMD_API_SUBDOMAINS HTTP %d", resp.StatusCode)
	}
	parsed, _ := url.ParseQuery(string(raw))
	if parsed.Get("error") != "0" {
		return true, fmt.Errorf("DirectAdmin CMD_API_SUBDOMAINS error: %s (%s)", parsed.Get("text"), parsed.Get("details"))
	}
	return true, nil
}

func (e *Engine) fireSubdomainCreateHooks(ctx context.Context, username, domain, sub string) {
	hooksRoot := e.DAHooksDir
	if hooksRoot == "" {
		hooksRoot = database.DefaultDAHooksDir
	}
	hookDir := filepath.Join(hooksRoot, "subdomain_create_post")
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".sh") {
			continue
		}
		hCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cmd := exec.CommandContext(hCtx, filepath.Join(hookDir, ent.Name()))
		cmd.Env = append(os.Environ(),
			"username="+username,
			"domain="+domain,
			"subdomain="+sub,
		)
		_ = cmd.Run()
		cancel()
	}
}

func appendSubdomainEntryAtomic(path, subLabel string) error {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked DirectAdmin subdomains file %s", path)
	}
	var lines []string
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			t := strings.ToLower(strings.TrimSpace(sc.Text()))
			if t != "" {
				if t == subLabel {
					_ = f.Close()
					return nil
				}
				lines = append(lines, t)
			}
		}
		_ = f.Close()
	}
	lines = append(lines, subLabel)
	content := strings.Join(lines, "\n") + "\n"

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".subs-*")
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
	if _, err := tmp.WriteString(content); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func readSimpleKV(path string) (map[string]string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fsguard.ErrSymlinkBlocked
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			out[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
		}
	}
	return out, sc.Err()
}
