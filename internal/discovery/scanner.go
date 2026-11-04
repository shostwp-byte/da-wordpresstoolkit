package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dadomains"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
	"github.com/shostwp-byte/da-wptoolkits/internal/vulndb"
)

const (
	MaxSubdirScanDepth = 2
	scanWorkerCount    = 16
)

var ignoredDirectories = map[string]struct{}{
	"wp-admin":     {},
	"wp-content":   {},
	"wp-includes":  {},
	"cgi-bin":      {},
	".well-known":  {},
	".git":         {},
	".svn":         {},
	"node_modules": {},
	"vendor":       {},
	"cache":        {},
	"logs":         {},
	"stats":        {},
}

// Scanner discovers WordPress installations across all domains, subdomains, and subdirectories of DirectAdmin users.
type Scanner struct {
	Domains  *dadomains.Resolver
	Store    *store.Store
	Policies *config.PolicyStore
	Vulns    *vulndb.DB
}

func NewScanner(domains *dadomains.Resolver, st *store.Store, policies *config.PolicyStore) *Scanner {
	return &Scanner{
		Domains:  domains,
		Store:    st,
		Policies: policies,
	}
}

// ScanResult summarizes a completed discovery pass for one or more users.
type ScanResult struct {
	ScannedTargets  int                    `json:"scanned_targets"`
	DiscoveredTotal int                    `json:"discovered_total"`
	AddedCount      int                    `json:"added_count"`
	UpdatedCount    int                    `json:"updated_count"`
	Instances       []store.InstanceRecord `json:"instances"`
}

// ScanAccount discovers and reconciles all WordPress instances belonging to a single DirectAdmin user.
func (s *Scanner) ScanAccount(acct dausers.Account, reattachDetached bool) (ScanResult, error) {
	var res ScanResult

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, func(targetPath, reason string) {
		if s.Store != nil {
			s.Store.RecordSecurityEvent(store.SecurityAuditEvent{
				Severity: "warning",
				Category: "symlink_guard",
				Owner:    acct.Username,
				Message:  reason + " (" + targetPath + ")",
			})
		}
	})
	if err != nil {
		return res, err
	}

	targets, err := s.Domains.ListTargets(acct)
	if err != nil {
		return res, err
	}
	res.ScannedTargets = len(targets)

	pol := config.DefaultPackagePolicy()
	if s.Policies != nil {
		if p, pErr := s.Policies.ResolvePackagePolicy(acct.Package); pErr == nil {
			pol = p
		}
	}

	// Build lookup map of existing instances by clean DocRoot for this owner (including detached)
	existingByRoot := make(map[string]store.InstanceRecord)
	if s.Store != nil {
		for _, inst := range s.Store.ListAllInstances(true) {
			if inst.Owner == acct.Username {
				existingByRoot[filepath.Clean(inst.DocRoot)] = inst
			}
		}
	}

	type inspectedSite struct {
		cleanRoot  string
		subPath    string
		meta       StaticWPMetadata
		pluginCnt  int
		themeCnt   int
		vulnCnt    int
		strictPerm bool
	}

	perTarget := make([][]inspectedSite, len(targets))
	if len(targets) > 0 {
		workers := scanWorkerCount
		if len(targets) < workers {
			workers = len(targets)
		}
		jobsCh := make(chan int, len(targets))
		for idx := range targets {
			jobsCh <- idx
		}
		close(jobsCh)

		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func() {
				defer wg.Done()
				for idx := range jobsCh {
					tgt := targets[idx]
					candidates := s.collectTargetCandidates(guard, tgt)
					var found []inspectedSite
					for _, cand := range candidates {
						cleanRoot := filepath.Clean(cand.docRoot)
						meta, ok := inspectWordPressDir(guard, cleanRoot)
						if !ok {
							continue
						}
						pCnt, tCnt, vCnt := countExtensionsAndStaticVulns(guard, cleanRoot, meta.WPVersion, s.Vulns)
						strictPerm, _ := checkWPConfigStrictPerms(cleanRoot)
						found = append(found, inspectedSite{
							cleanRoot:  cleanRoot,
							subPath:    cand.subPath,
							meta:       meta,
							pluginCnt:  pCnt,
							themeCnt:   tCnt,
							vulnCnt:    vCnt,
							strictPerm: strictPerm,
						})
					}
					perTarget[idx] = found
				}
			}()
		}
		wg.Wait()
	}

	seenDocRoots := make(map[string]struct{})
	now := time.Now().UTC()

	for idx, tgt := range targets {
		for _, item := range perTarget[idx] {
			cleanRoot := item.cleanRoot
			if _, dup := seenDocRoots[cleanRoot]; dup {
				continue
			}
			seenDocRoots[cleanRoot] = struct{}{}

			scheme := "http://"
			if tgt.SSLActive {
				scheme = "https://"
			}
			siteURL := scheme + tgt.Domain + item.subPath

			existing, existed := existingByRoot[cleanRoot]
			if existed && existing.Detached && !reattachDetached {
				continue
			}

			rec := existing
			if !existed {
				rec = store.InstanceRecord{
					Owner:              acct.Username,
					OwnerUID:           acct.UID,
					SiteTitle:          tgt.Domain + item.subPath,
					SearchIndexing:     true,
					CoreShieldMode:     pol.DefaultCoreShieldMode,
					CoreIntegrityClean: true,
					SecurityTotal:      12,
					EnvironmentTag:     inferEnvironmentTag(tgt.Domain, item.subPath),
				}
			} else if reattachDetached {
				rec.Detached = false
			}

			meta := item.meta
			rec.Owner = acct.Username
			rec.OwnerUID = acct.UID
			rec.Domain = tgt.Domain
			rec.DomainType = tgt.DomainType
			rec.SubPath = item.subPath
			rec.DocRoot = cleanRoot
			if rec.SiteURL == "" || !existed {
				rec.SiteURL = siteURL
			}
			rec.WPVersion = meta.WPVersion
			rec.Locale = meta.Locale
			rec.PHPVersion = tgt.PHP.Version
			rec.MemoryLimit = meta.MemoryLimit
			if meta.DBName != "" {
				rec.DBName = meta.DBName
			}
			if meta.DBUser != "" {
				rec.DBUser = meta.DBUser
			}
			if meta.TablePrefix != "" {
				rec.TablePrefix = meta.TablePrefix
			}
			rec.SSLActive = tgt.SSLActive
			rec.DebugMode = meta.DebugMode
			rec.DisableWPCron = meta.DisableWPCron
			rec.CacheEnabled = meta.CacheEnabled
			rec.PluginCount = item.pluginCnt
			rec.ThemeCount = item.themeCnt
			if s.Vulns != nil {
				rec.VulnCount = item.vulnCnt
			}
			rec.LastScannedAt = now

			if item.strictPerm && rec.SecurityScore < 1 {
				rec.SecurityScore = 1
			}

			if existed {
				res.UpdatedCount++
			} else {
				res.AddedCount++
			}
			res.DiscoveredTotal++
			res.Instances = append(res.Instances, rec)
		}
	}

	if s.Store != nil && len(res.Instances) > 0 {
		saved, uErr := s.Store.UpsertInstancesBatch(res.Instances)
		if uErr != nil {
			return res, uErr
		}
		res.Instances = saved
	}

	return res, nil
}

type dirCandidate struct {
	docRoot string
	subPath string // "" or "/blog"
}

func (s *Scanner) collectTargetCandidates(guard *fsguard.Guard, tgt dadomains.DomainTarget) []dirCandidate {
	var baseRoot string
	var err error
	if rel, rErr := filepath.Rel(guard.AllowedRoot, filepath.Clean(tgt.DocRoot)); rErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		baseRoot, err = guard.VerifyChildUnderVerifiedRoot(guard.AllowedRoot, false, strings.Split(rel, string(filepath.Separator))...)
	} else {
		baseRoot, err = guard.VerifyExistingPath(tgt.DocRoot)
	}
	if err != nil {
		return nil
	}

	out := []dirCandidate{{docRoot: baseRoot, subPath: ""}}
	s.walkSubdirs(guard, baseRoot, "", 1, tgt.ExcludedRelPaths, &out)
	return out
}

func (s *Scanner) walkSubdirs(
	guard *fsguard.Guard,
	baseRoot string,
	relSlash string,
	depth int,
	excluded map[string]string,
	out *[]dirCandidate,
) {
	if depth > MaxSubdirScanDepth {
		return
	}
	curDir := baseRoot
	if relSlash != "" {
		curDir = filepath.Join(baseRoot, filepath.FromSlash(relSlash))
	}

	entries, err := os.ReadDir(curDir)
	if err != nil {
		return
	}

	for _, ent := range entries {
		if !ent.IsDir() || ent.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := ent.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if _, skip := ignoredDirectories[strings.ToLower(name)]; skip {
			continue
		}

		childRel := name
		if relSlash != "" {
			childRel = relSlash + "/" + name
		}
		// Skip child directories that are actually another subdomain's DocumentRoot (TC-03)
		if _, isSubdomainRoot := excluded[childRel]; isSubdomainRoot {
			continue
		}

		var childSegs []string
		if relSlash != "" {
			childSegs = append(strings.Split(relSlash, "/"), name)
		} else {
			childSegs = []string{name}
		}
		childAbs, vErr := guard.VerifyChildUnderVerifiedRoot(baseRoot, false, childSegs...)
		if vErr != nil {
			continue
		}

		*out = append(*out, dirCandidate{
			docRoot: childAbs,
			subPath: "/" + childRel,
		})

		s.walkSubdirs(guard, baseRoot, childRel, depth+1, excluded, out)
	}
}

func inspectWordPressDir(guard *fsguard.Guard, docRoot string) (StaticWPMetadata, bool) {
	verBytes, err := guard.ReadRegularFileUnderVerifiedRoot(docRoot, 64*1024, "wp-includes", "version.php")
	if err != nil {
		return StaticWPMetadata{}, false
	}
	wpVer, locale := ParseVersionPHP(verBytes)
	if wpVer == "" {
		return StaticWPMetadata{}, false
	}

	// WordPress loads wp-config.php from docRoot or 1 directory above docRoot (only if no wp-settings.php exists above)
	var meta StaticWPMetadata
	cfgBytes, cfgErr := guard.ReadRegularFileUnderVerifiedRoot(docRoot, 128*1024, "wp-config.php")
	if cfgErr != nil {
		parentDir := filepath.Dir(docRoot)
		if _, pSettingsErr := os.Lstat(filepath.Join(parentDir, "wp-settings.php")); os.IsNotExist(pSettingsErr) {
			cfgBytes, cfgErr = guard.ReadRegularFileSafe(filepath.Join(parentDir, "wp-config.php"), 128*1024)
		}
	}
	if cfgErr != nil {
		// Unconfigured tarball without wp-config.php is not an installed WordPress instance yet
		return StaticWPMetadata{}, false
	}

	meta = ParseWPConfig(cfgBytes)
	meta.WPVersion = wpVer
	meta.Locale = locale
	return meta, true
}

func countExtensionsAndStaticVulns(guard *fsguard.Guard, docRoot, wpVer string, vdb *vulndb.DB) (plugins int, themes int, vulns int) {
	if vdb != nil && wpVer != "" {
		vulns += len(vdb.MatchCore(wpVer))
	}

	if verified, err := guard.VerifyChildUnderVerifiedRoot(docRoot, false, "wp-content", "plugins"); err == nil {
		if entries, rErr := os.ReadDir(verified); rErr == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, ".") || name == "index.php" {
					continue
				}
				if e.IsDir() || strings.HasSuffix(strings.ToLower(name), ".php") {
					plugins++
					slug := strings.TrimSuffix(name, ".php")
					if vdb != nil && vdb.HasSlugRules(vulndb.SoftwarePlugin, slug) {
						if ver := extractHeaderVersionQuick(guard, verified, name, e.IsDir(), false); ver != "" {
							vulns += len(vdb.MatchPlugin(slug, ver))
						}
					}
				}
			}
		}
	}

	if verified, err := guard.VerifyChildUnderVerifiedRoot(docRoot, false, "wp-content", "themes"); err == nil {
		if entries, rErr := os.ReadDir(verified); rErr == nil {
			for _, e := range entries {
				if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
					themes++
					slug := e.Name()
					if vdb != nil && vdb.HasSlugRules(vulndb.SoftwareTheme, slug) {
						if ver := extractHeaderVersionQuick(guard, verified, slug, true, true); ver != "" {
							vulns += len(vdb.MatchTheme(slug, ver))
						}
					}
				}
			}
		}
	}
	return plugins, themes, vulns
}

func extractHeaderVersionQuick(guard *fsguard.Guard, parentVerified, entryName string, isDir, isTheme bool) string {
	if isTheme {
		raw, err := guard.ReadRegularFileUnderVerifiedRoot(parentVerified, 4096, entryName, "style.css")
		if err != nil {
			return ""
		}
		return findHeaderVersionValue(string(raw))
	}
	if !isDir {
		raw, err := guard.ReadRegularFileUnderVerifiedRoot(parentVerified, 4096, entryName)
		if err != nil {
			return ""
		}
		return findHeaderVersionValue(string(raw))
	}
	if raw, err := guard.ReadRegularFileUnderVerifiedRoot(parentVerified, 4096, entryName, entryName+".php"); err == nil {
		if v := findHeaderVersionValue(string(raw)); v != "" {
			return v
		}
	}
	subDir, err := guard.VerifyChildUnderVerifiedRoot(parentVerified, false, entryName)
	if err != nil {
		return ""
	}
	files, _ := os.ReadDir(subDir)
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(strings.ToLower(f.Name()), ".php") {
			continue
		}
		if raw, rErr := guard.ReadRegularFileUnderVerifiedRoot(subDir, 4096, f.Name()); rErr == nil {
			if v := findHeaderVersionValue(string(raw)); v != "" {
				return v
			}
		}
	}
	return ""
}

func findHeaderVersionValue(head string) string {
	for _, rawLine := range strings.Split(head, "\n") {
		line := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(rawLine), "/*#"))
		if len(line) > 8 && strings.EqualFold(line[:8], "version:") {
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[8:]), "*/"))
		}
	}
	return ""
}

func checkWPConfigStrictPerms(docRoot string) (bool, error) {
	st, err := os.Lstat(filepath.Join(docRoot, "wp-config.php"))
	if err != nil {
		return false, err
	}
	return (st.Mode().Perm() & 0o077) == 0, nil
}

func inferEnvironmentTag(domain, subPath string) string {
	lower := strings.ToLower(domain + subPath)
	if strings.HasPrefix(lower, "staging.") || strings.Contains(lower, "/staging") || strings.HasPrefix(lower, "stage.") {
		return "staging"
	}
	if strings.HasPrefix(lower, "dev.") || strings.Contains(lower, "/dev") {
		return "development"
	}
	return "production"
}
