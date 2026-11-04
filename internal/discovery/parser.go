package discovery

import (
	"regexp"
	"strings"
)

// StaticWPMetadata holds WordPress version and wp-config settings extracted without executing PHP.
type StaticWPMetadata struct {
	WPVersion     string
	Locale        string
	DBName        string
	DBUser        string
	DBHost        string
	TablePrefix   string
	DebugMode     bool
	DisableWPCron bool
	MemoryLimit   string
	CacheEnabled  bool
}

var (
	reWPVersion     = regexp.MustCompile(`\$wp_version\s*=\s*['"]([^'"]+)['"]`)
	reWPLocale      = regexp.MustCompile(`\$wp_local_package\s*=\s*['"]([^'"]+)['"]`)
	reTablePrefix   = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([^'"]+)['"]`)
	reDefineString  = regexp.MustCompile(`(?i)\bdefine\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)`)
	reDefineBoolean = regexp.MustCompile(`(?i)\bdefine\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*(true|false|1|0)\s*\)`)
)

// ParseVersionPHP extracts $wp_version and $wp_local_package safely from wp-includes/version.php.
func ParseVersionPHP(raw []byte) (version string, locale string) {
	clean := stripPHPComments(string(raw))
	if m := reWPVersion.FindStringSubmatch(clean); len(m) == 2 {
		version = strings.TrimSpace(m[1])
	}
	if m := reWPLocale.FindStringSubmatch(clean); len(m) == 2 {
		locale = strings.TrimSpace(m[1])
	}
	if locale == "" {
		locale = "en_US"
	}
	return version, locale
}

// ParseWPConfig extracts non-secret operational parameters from wp-config.php (DB_PASSWORD is never stored).
func ParseWPConfig(raw []byte) StaticWPMetadata {
	clean := stripPHPComments(string(raw))
	meta := StaticWPMetadata{
		TablePrefix: "wp_",
		MemoryLimit: "128M",
	}

	if m := reTablePrefix.FindStringSubmatch(clean); len(m) == 2 && strings.TrimSpace(m[1]) != "" {
		meta.TablePrefix = strings.TrimSpace(m[1])
	}

	strDefines := make(map[string]string)
	for _, m := range reDefineString.FindAllStringSubmatch(clean, -1) {
		if len(m) == 3 {
			strDefines[strings.ToUpper(m[1])] = m[2]
		}
	}
	boolDefines := make(map[string]bool)
	for _, m := range reDefineBoolean.FindAllStringSubmatch(clean, -1) {
		if len(m) == 3 {
			val := strings.ToLower(m[2])
			boolDefines[strings.ToUpper(m[1])] = (val == "true" || val == "1")
		}
	}

	meta.DBName = strings.TrimSpace(strDefines["DB_NAME"])
	meta.DBUser = strings.TrimSpace(strDefines["DB_USER"])
	meta.DBHost = strings.TrimSpace(strDefines["DB_HOST"])
	if mem := strings.TrimSpace(strDefines["WP_MEMORY_LIMIT"]); mem != "" {
		meta.MemoryLimit = mem
	}
	meta.DebugMode = boolDefines["WP_DEBUG"]
	meta.DisableWPCron = boolDefines["DISABLE_WP_CRON"]
	meta.CacheEnabled = boolDefines["WP_CACHE"]

	return meta
}

// stripPHPComments removes //, #, and /* ... */ comments while preserving quoted string literals.
func stripPHPComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))

	n := len(src)
	inSingle := false
	inDouble := false

	for i := 0; i < n; i++ {
		c := src[i]

		if inSingle {
			out.WriteByte(c)
			if c == '\\' && i+1 < n {
				i++
				out.WriteByte(src[i])
			} else if c == '\'' {
				inSingle = false
			}
			continue
		}

		if inDouble {
			out.WriteByte(c)
			if c == '\\' && i+1 < n {
				i++
				out.WriteByte(src[i])
			} else if c == '"' {
				inDouble = false
			}
			continue
		}

		if c == '\'' {
			inSingle = true
			out.WriteByte(c)
			continue
		}
		if c == '"' {
			inDouble = true
			out.WriteByte(c)
			continue
		}

		// Block comment /* ... */
		if c == '/' && i+1 < n && src[i+1] == '*' {
			i += 2
			for i < n {
				if src[i] == '*' && i+1 < n && src[i+1] == '/' {
					i++
					break
				}
				if src[i] == '\n' {
					out.WriteByte('\n')
				}
				i++
			}
			continue
		}

		// Single-line // or # comment
		if (c == '/' && i+1 < n && src[i+1] == '/') || c == '#' {
			for i < n && src[i] != '\n' {
				i++
			}
			if i < n && src[i] == '\n' {
				out.WriteByte('\n')
			}
			continue
		}

		out.WriteByte(c)
	}
	return out.String()
}
