package dadomains

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
)

const (
	DomainTypeMain      = "main"
	DomainTypeAddon     = "addon"
	DomainTypeSubdomain = "subdomain"
)

// DomainTarget describes a single DirectAdmin domain or subdomain mapped to its exact DocumentRoot and PHP runtime.
type DomainTarget struct {
	Domain           string            `json:"domain"`
	ParentDomain     string            `json:"parent_domain,omitempty"`
	DomainType       string            `json:"domain_type"` // main | addon | subdomain
	DocRoot          string            `json:"doc_root"`
	SSLActive        bool              `json:"ssl_active"`
	PHP              daphp.Selection   `json:"php"`
	ExcludedRelPaths map[string]string `json:"-"` // relative child dir -> owning subdomain FQDN
}

// Resolver maps DirectAdmin user domain/subdomain metadata to exact filesystem document roots.
type Resolver struct {
	DADataRoot string
	PHP        *daphp.Resolver
}

func NewResolver(daDataRoot string, phpResolver *daphp.Resolver) *Resolver {
	if daDataRoot == "" {
		daDataRoot = "/usr/local/directadmin/data"
	}
	if phpResolver == nil {
		phpResolver = daphp.NewResolver("", "")
	}
	return &Resolver{
		DADataRoot: daDataRoot,
		PHP:        phpResolver,
	}
}

// ListTargets builds the complete, deduplicated Domain/Subdomain topology for a DirectAdmin account (TC-03).
func (r *Resolver) ListTargets(acct dausers.Account) ([]DomainTarget, error) {
	if err := config.ValidateIdentifier(acct.Username); err != nil {
		return nil, err
	}
	if acct.HomeDir == "" {
		return nil, fmt.Errorf("account %s has empty HomeDir", acct.Username)
	}

	userDir := filepath.Join(r.DADataRoot, "users", acct.Username)
	userConf := readKV(filepath.Join(userDir, "user.conf"))
	primaryDomain := strings.ToLower(strings.TrimSpace(userConf["domain"]))

	rawDomains := readNonEmptyLines(filepath.Join(userDir, "domains.list"))
	seenDomains := make(map[string]struct{}, len(rawDomains)+1)
	var domainNames []string
	for _, d := range rawDomains {
		dl := strings.ToLower(strings.TrimSpace(d))
		if config.ValidateDomainName(dl) != nil {
			continue
		}
		if _, dup := seenDomains[dl]; !dup {
			seenDomains[dl] = struct{}{}
			domainNames = append(domainNames, dl)
		}
	}
	if primaryDomain != "" && config.ValidateDomainName(primaryDomain) == nil {
		if _, dup := seenDomains[primaryDomain]; !dup {
			domainNames = append([]string{primaryDomain}, domainNames...)
		}
	}

	domainsDir := filepath.Join(userDir, "domains")
	var targets []DomainTarget
	phpMemo := make(map[string]daphp.Selection, 4)
	resolvePHPCached := func(slot string) daphp.Selection {
		key := strings.TrimSpace(slot)
		if sel, ok := phpMemo[key]; ok {
			return sel
		}
		sel := r.PHP.Resolve(key)
		phpMemo[key] = sel
		return sel
	}

	for _, dom := range domainNames {
		domConf := readKV(filepath.Join(domainsDir, dom+".conf"))
		dtype := DomainTypeAddon
		if dom == primaryDomain || (primaryDomain == "" && len(targets) == 0) {
			dtype = DomainTypeMain
		}

		sslActive := isTruthy(domConf["ssl"])
		phpSel := resolvePHPCached(domConf["php1_select"])
		docRoot := resolveDomainDocRoot(acct.HomeDir, dom, domConf["documentroot"])

		targets = append(targets, DomainTarget{
			Domain:           dom,
			DomainType:       dtype,
			DocRoot:          docRoot,
			SSLActive:        sslActive,
			PHP:              phpSel,
			ExcludedRelPaths: make(map[string]string),
		})

		subOverrides := readSubdomainOverrides(filepath.Join(domainsDir, dom+".subdomains.docroot.override"))
		subs := readNonEmptyLines(filepath.Join(domainsDir, dom+".subdomains"))

		for _, subPrefix := range subs {
			subClean := strings.ToLower(strings.TrimSpace(subPrefix))
			if subClean == "" {
				continue
			}
			fqdn := subClean + "." + dom
			if config.ValidateDomainName(fqdn) != nil {
				continue
			}

			ov := subOverrides[subClean]
			subPHPSlot := domConf["php1_select"]
			if ov["php1_select"] != "" {
				subPHPSlot = ov["php1_select"]
			}
			subDocRoot := resolveSubdomainDocRoot(acct.HomeDir, dom, subClean, docRoot, ov["documentroot"])

			targets = append(targets, DomainTarget{
				Domain:           fqdn,
				ParentDomain:     dom,
				DomainType:       DomainTypeSubdomain,
				DocRoot:          subDocRoot,
				SSLActive:        sslActive,
				PHP:              resolvePHPCached(subPHPSlot),
				ExcludedRelPaths: make(map[string]string),
			})
		}
	}

	// Populate ExcludedRelPaths whenever one target's DocRoot sits inside another target's DocRoot (e.g., public_html/sub)
	for i := range targets {
		for j := range targets {
			if i == j {
				continue
			}
			rel, err := filepath.Rel(targets[i].DocRoot, targets[j].DocRoot)
			if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			relSlash := filepath.ToSlash(rel)
			targets[i].ExcludedRelPaths[relSlash] = targets[j].Domain
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].DomainType != targets[j].DomainType {
			order := map[string]int{DomainTypeMain: 0, DomainTypeAddon: 1, DomainTypeSubdomain: 2}
			return order[targets[i].DomainType] < order[targets[j].DomainType]
		}
		return targets[i].Domain < targets[j].Domain
	})

	return targets, nil
}

// FindTarget locates a single DomainTarget by exact FQDN for an account.
func (r *Resolver) FindTarget(acct dausers.Account, domain string) (DomainTarget, error) {
	want := strings.ToLower(strings.TrimSpace(domain))
	list, err := r.ListTargets(acct)
	if err != nil {
		return DomainTarget{}, err
	}
	for _, t := range list {
		if t.Domain == want {
			return t, nil
		}
	}
	return DomainTarget{}, fmt.Errorf("domain or subdomain %q does not belong to account %s", domain, acct.Username)
}

func resolveDomainDocRoot(homeDir, domain, customOverride string) string {
	cleanHome := filepath.Clean(homeDir)
	domainsBase := filepath.Join(cleanHome, "domains")
	if ov := strings.TrimSpace(customOverride); ov != "" {
		cand := expandUserDocRoot(cleanHome, ov)
		if isInsideDir(domainsBase, cand) {
			return cand
		}
	}
	return filepath.Join(domainsBase, domain, "public_html")
}

func resolveSubdomainDocRoot(homeDir, parentDomain, subPrefix, parentDocRoot, customOverride string) string {
	cleanHome := filepath.Clean(homeDir)
	domainsBase := filepath.Join(cleanHome, "domains")
	if ov := strings.TrimSpace(customOverride); ov != "" {
		cand := expandUserDocRoot(cleanHome, ov)
		if isInsideDir(domainsBase, cand) {
			return cand
		}
	}
	// Check DirectAdmin separated subdomain docroot (/home/<user>/domains/<sub.domain>/public_html)
	separated := filepath.Join(domainsBase, subPrefix+"."+parentDomain, "public_html")
	if st, err := os.Stat(separated); err == nil && st.IsDir() {
		return separated
	}
	// Classic DirectAdmin subdomain docroot (/home/<user>/domains/<domain>/public_html/<sub>)
	return filepath.Join(parentDocRoot, subPrefix)
}

func expandUserDocRoot(cleanHome, raw string) string {
	slashed := filepath.FromSlash(strings.TrimSpace(raw))
	if isInsideDir(cleanHome, slashed) {
		return filepath.Clean(slashed)
	}
	return filepath.Clean(filepath.Join(cleanHome, strings.TrimLeft(slashed, `/\`)))
}

func isInsideDir(base, candidate string) bool {
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func readSubdomainOverrides(path string) map[string]map[string]string {
	out := make(map[string]map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		sub := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if !strings.Contains(val, "=") && strings.Contains(strings.ToUpper(val), "%3D") {
			if unescaped, uErr := url.QueryUnescape(val); uErr == nil {
				val = unescaped
			}
		}
		parsed, pErr := url.ParseQuery(val)
		if pErr != nil {
			continue
		}
		m := make(map[string]string, len(parsed))
		for k, vals := range parsed {
			if len(vals) > 0 {
				m[k] = vals[0]
			}
		}
		out[sub] = m
	}
	return out
}

func readKV(path string) map[string]string {
	out := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		out[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}
	return out
}

func readNonEmptyLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		s := strings.TrimSpace(sc.Text())
		if s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	return out
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "yes", "1", "true":
		return true
	default:
		return false
	}
}
