package hardening

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const saltsMarkerComment = "/* DA-WPTK-SALTS-REFRESHED */"

var wpSaltKeys = []string{
	"AUTH_KEY",
	"SECURE_AUTH_KEY",
	"LOGGED_IN_KEY",
	"NONCE_KEY",
	"AUTH_SALT",
	"SECURE_AUTH_SALT",
	"LOGGED_IN_SALT",
	"NONCE_SALT",
}

var (
	reStopEditing = regexp.MustCompile(`(?m)^.*That's all, stop editing!.*$`)
	reWPSettings  = regexp.MustCompile(`(?m)^.*wp-settings\.php.*$`)
	reTablePfx    = regexp.MustCompile(`(?m)^\s*\$table_prefix\s*=\s*['"]([^'"]+)['"]\s*;`)
)

// GetDefinedBool inspects wp-config.php for `define('NAME', true|false)`.
func GetDefinedBool(content, name string) (bool, bool) {
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*(true|false|1|0)\s*\)\s*;`)
	m := re.FindStringSubmatch(content)
	if len(m) != 2 {
		return false, false
	}
	v := strings.ToLower(strings.TrimSpace(m[1]))
	return v == "true" || v == "1", true
}

// SetDefinedBool updates or inserts `define( 'NAME', true|false );` safely before wp-settings.php.
func SetDefinedBool(content, name string, val bool) (string, bool) {
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	boolLit := "false"
	if val {
		boolLit = "true"
	}
	desiredLine := fmt.Sprintf("define( '%s', %s );", name, boolLit)

	re := regexp.MustCompile(`(?im)^(\s*)define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*(?:true|false|1|0)\s*\)\s*;[^\n]*`)
	if loc := re.FindStringIndex(norm); loc != nil {
		existing := norm[loc[0]:loc[1]]
		if strings.TrimSpace(existing) == desiredLine {
			return norm, false
		}
		return norm[:loc[0]] + desiredLine + norm[loc[1]:], true
	}

	return insertBeforeBootstrap(norm, desiredLine), true
}

// GetDefinedString inspects wp-config.php for `define('NAME', 'VALUE')`.
func GetDefinedString(content, name string) (string, bool) {
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*['"]([^'"\r\n]*)['"]\s*\)\s*;`)
	m := re.FindStringSubmatch(content)
	if len(m) != 2 {
		return "", false
	}
	return m[1], true
}

// SetDefinedString updates or inserts `define( 'NAME', 'VALUE' );` safely before wp-settings.php.
func SetDefinedString(content, name, val string) (string, error) {
	if strings.ContainsAny(val, "'\"\\\r\n\x00") {
		return "", fmt.Errorf("constant %s value contains forbidden quote/control characters", name)
	}
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	desiredLine := fmt.Sprintf("define( '%s', '%s' );", name, val)

	re := regexp.MustCompile(`(?im)^(\s*)define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*['"][^'"\r\n]*['"]\s*\)\s*;[^\n]*`)
	if loc := re.FindStringIndex(norm); loc != nil {
		existing := norm[loc[0]:loc[1]]
		if strings.TrimSpace(existing) == desiredLine {
			return norm, nil
		}
		return norm[:loc[0]] + desiredLine + norm[loc[1]:], nil
	}
	return insertBeforeBootstrap(norm, desiredLine), nil
}

// GetDefinedInt inspects wp-config.php for `define('NAME', 123)` (or boolean false=0 for WP_POST_REVISIONS).
func GetDefinedInt(content, name string) (int, bool) {
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*(-?[0-9]+)\s*\)\s*;`)
	m := re.FindStringSubmatch(content)
	if len(m) != 2 {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(m[1]))
	if err != nil {
		return 0, false
	}
	return n, true
}

// SetDefinedInt updates or inserts `define( 'NAME', 123 );` safely before wp-settings.php.
func SetDefinedInt(content, name string, val int) (string, bool) {
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	desiredLine := fmt.Sprintf("define( '%s', %d );", name, val)

	re := regexp.MustCompile(`(?im)^(\s*)define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*(?:-?[0-9]+|true|false)\s*\)\s*;[^\n]*`)
	if loc := re.FindStringIndex(norm); loc != nil {
		existing := norm[loc[0]:loc[1]]
		if strings.TrimSpace(existing) == desiredLine {
			return norm, false
		}
		return norm[:loc[0]] + desiredLine + norm[loc[1]:], true
	}
	return insertBeforeBootstrap(norm, desiredLine), true
}

// RemoveDefinedConstant removes a standalone `define( 'NAME', ... );` line from wp-config.php.
func RemoveDefinedConstant(content, name string) (string, bool) {
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(name) + `['"]\s*,\s*[^)]+\)\s*;[ \t]*\n?`)
	if !re.MatchString(norm) {
		return norm, false
	}
	return re.ReplaceAllString(norm, ""), true
}

// SetTablePrefix updates `$table_prefix = '...';` in wp-config.php.
func SetTablePrefix(content, newPrefix string) (string, bool) {
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	desired := fmt.Sprintf("$table_prefix = '%s';", newPrefix)
	if loc := reTablePfx.FindStringIndex(norm); loc != nil {
		if strings.TrimSpace(norm[loc[0]:loc[1]]) == desired {
			return norm, false
		}
		return norm[:loc[0]] + desired + norm[loc[1]:], true
	}
	return insertBeforeBootstrap(norm, desired), true
}

// HasRefreshedSalts checks whether all 8 WordPress security keys/salts are strong (>= 32 chars, non-placeholder)
// and contain the toolkit refresh marker or strong non-default entropy.
func HasRefreshedSalts(content string) bool {
	if strings.Contains(content, saltsMarkerComment) {
		return true
	}
	for _, key := range wpSaltKeys {
		re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(key) + `['"]\s*,\s*['"]([^'"]*)['"]\s*\)`)
		m := re.FindStringSubmatch(content)
		if len(m) != 2 {
			return false
		}
		val := strings.TrimSpace(m[1])
		if len(val) < 48 || strings.Contains(strings.ToLower(val), "unique phrase") {
			return false
		}
	}
	return true
}

// RegenerateSalts generates 8 fresh 64-character cryptographic salts in wp-config.php.
func RegenerateSalts(content string) (string, error) {
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	// Remove old salt definitions and old marker
	norm = strings.ReplaceAll(norm, saltsMarkerComment+"\n", "")
	for _, key := range wpSaltKeys {
		re := regexp.MustCompile(`(?im)^\s*define\s*\(\s*['"]` + regexp.QuoteMeta(key) + `['"]\s*,\s*['"][^'"]*['"]\s*\)\s*;[ \t]*\n?`)
		norm = re.ReplaceAllString(norm, "")
	}

	var block strings.Builder
	block.WriteString(saltsMarkerComment + "\n")
	for _, key := range wpSaltKeys {
		secret, err := randomSaltString(64)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&block, "define( '%s', '%s' );\n", key, secret)
	}

	return insertBeforeBootstrap(norm, strings.TrimSuffix(block.String(), "\n")), nil
}

// UnmarkSalts removes the toolkit salt marker comment while keeping the strong keys intact.
func UnmarkSalts(content string) (string, bool) {
	norm := strings.ReplaceAll(content, "\r\n", "\n")
	if !strings.Contains(norm, saltsMarkerComment) {
		return norm, false
	}
	updated := strings.ReplaceAll(norm, saltsMarkerComment+"\n", "")
	updated = strings.ReplaceAll(updated, saltsMarkerComment, "")
	return updated, true
}

func insertBeforeBootstrap(norm, snippet string) string {
	if loc := reStopEditing.FindStringIndex(norm); loc != nil {
		return norm[:loc[0]] + snippet + "\n\n" + norm[loc[0]:]
	}
	if loc := reWPSettings.FindStringIndex(norm); loc != nil {
		return norm[:loc[0]] + snippet + "\n\n" + norm[loc[0]:]
	}
	trimmed := strings.TrimRight(norm, "\n")
	return trimmed + "\n\n" + snippet + "\n"
}

func randomSaltString(length int) (string, error) {
	// Safe ASCII printable alphabet excluding single-quote and backslash so PHP single-quoted strings never escape.
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~"
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}
