package extensions

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
)

// StaticHeader holds metadata extracted safely from the first 8 KB of a plugin PHP file or theme style.css.
type StaticHeader struct {
	Slug        string
	Title       string
	Version     string
	Author      string
	Description string
}

// ScanStaticPlugins inspects wp-content/plugins without executing PHP.
func ScanStaticPlugins(guard *fsguard.Guard, verifiedDocRoot string) map[string]StaticHeader {
	out := make(map[string]StaticHeader)
	plugDir, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, "wp-content", "plugins")
	if err != nil {
		return out
	}
	entries, err := os.ReadDir(plugDir)
	if err != nil {
		return out
	}

	for _, ent := range entries {
		name := ent.Name()
		if strings.HasPrefix(name, ".") || name == "index.php" || ent.Type()&os.ModeSymlink != 0 {
			continue
		}
		if ent.IsDir() {
			slug := name
			subPath, vErr := guard.VerifyChildUnderVerifiedRoot(plugDir, false, slug)
			if vErr != nil {
				continue
			}
			// Prefer <slug>/<slug>.php first, then scan top-level .php files inside <slug>/
			if raw, rErr := guard.ReadRegularFileUnderVerifiedRoot(subPath, 8192, slug+".php"); rErr == nil {
				if hdr := parseWPHeaderBlock(string(raw), "Plugin Name"); hdr.Title != "" || hdr.Version != "" {
					hdr.Slug = slug
					if hdr.Title == "" {
						hdr.Title = slug
					}
					out[slug] = hdr
					continue
				}
			}
			subEntries, _ := os.ReadDir(subPath)
			for _, se := range subEntries {
				if se.IsDir() || !strings.HasSuffix(strings.ToLower(se.Name()), ".php") {
					continue
				}
				raw, rErr := guard.ReadRegularFileUnderVerifiedRoot(subPath, 8192, se.Name())
				if rErr != nil {
					continue
				}
				if hdr := parseWPHeaderBlock(string(raw), "Plugin Name"); hdr.Title != "" {
					hdr.Slug = slug
					out[slug] = hdr
					break
				}
			}
		} else if strings.HasSuffix(strings.ToLower(name), ".php") {
			slug := strings.TrimSuffix(name, filepath.Ext(name))
			raw, rErr := guard.ReadRegularFileUnderVerifiedRoot(plugDir, 8192, name)
			if rErr != nil {
				continue
			}
			hdr := parseWPHeaderBlock(string(raw), "Plugin Name")
			hdr.Slug = slug
			if hdr.Title == "" {
				hdr.Title = slug
			}
			out[slug] = hdr
		}
	}
	return out
}

// ScanStaticThemes inspects wp-content/themes/*/style.css without executing PHP.
func ScanStaticThemes(guard *fsguard.Guard, verifiedDocRoot string) map[string]StaticHeader {
	out := make(map[string]StaticHeader)
	themeDir, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, "wp-content", "themes")
	if err != nil {
		return out
	}
	entries, err := os.ReadDir(themeDir)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		if !ent.IsDir() || strings.HasPrefix(ent.Name(), ".") || ent.Type()&os.ModeSymlink != 0 {
			continue
		}
		slug := ent.Name()
		raw, rErr := guard.ReadRegularFileUnderVerifiedRoot(themeDir, 8192, slug, "style.css")
		if rErr != nil {
			continue
		}
		hdr := parseWPHeaderBlock(string(raw), "Theme Name")
		hdr.Slug = slug
		if hdr.Title == "" {
			hdr.Title = slug
		}
		out[slug] = hdr
	}
	return out
}

func parseWPHeaderBlock(head string, primaryKey string) StaticHeader {
	var h StaticHeader
	lines := strings.Split(head, "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(rawLine), "/*#"))
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:idx]))
		v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[idx+1:]), "*/"))
		if v == "" {
			continue
		}
		switch k {
		case strings.ToLower(primaryKey):
			if h.Title == "" {
				h.Title = v
			}
		case "version":
			if h.Version == "" {
				h.Version = v
			}
		case "author":
			if h.Author == "" {
				h.Author = v
			}
		case "description":
			if h.Description == "" {
				h.Description = v
			}
		}
	}
	return h
}
