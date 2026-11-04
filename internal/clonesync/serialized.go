package clonesync

import (
	"strconv"
	"strings"
)

// ReplacePHPSerializedSafe replaces all (old -> new) pairs in input while recalculating exact byte lengths
// for PHP serialized strings (`s:<byte_len>:"...";`, including nested serialized payloads and JSON-escaped `\/` URLs).
func ReplacePHPSerializedSafe(input string, pairs [][2]string) (string, int) {
	expanded := expandReplacementPairs(pairs)
	if len(expanded) == 0 || input == "" {
		return input, 0
	}
	return replacePHPSerializedRecursive(input, expanded, 0)
}

// ReplaceSQLDumpSafe rewrites a MariaDB/MySQL dump (`wp db export`) safely:
// 1. Unescapes single-quoted SQL string literals, updates PHP serialized byte lengths & Elementor JSON `\/` URLs, and re-escapes modified literals.
// 2. Optionally renames table prefixes on backtick-quoted SQL identifiers and WordPress `*_user_roles` / `*_capabilities` meta keys.
func ReplaceSQLDumpSafe(sqlDump string, pairs [][2]string, oldPrefix, newPrefix string) (string, int) {
	expanded := expandReplacementPairs(pairs)
	renamePrefix := oldPrefix != "" && newPrefix != "" && oldPrefix != newPrefix
	if len(expanded) == 0 && !renamePrefix {
		return sqlDump, 0
	}

	var out strings.Builder
	out.Grow(len(sqlDump) + len(sqlDump)/20)
	totalReplacements := 0

	n := len(sqlDump)
	i := 0
	for i < n {
		c := sqlDump[i]

		// Line comment `-- ...` or `# ...`
		if c == '#' || (c == '-' && i+2 < n && sqlDump[i+1] == '-' && (sqlDump[i+2] == ' ' || sqlDump[i+2] == '\t' || sqlDump[i+2] == '\r' || sqlDump[i+2] == '\n')) {
			nl := strings.IndexByte(sqlDump[i:], '\n')
			if nl < 0 {
				out.WriteString(sqlDump[i:])
				break
			}
			out.WriteString(sqlDump[i : i+nl+1])
			i += nl + 1
			continue
		}

		// Backtick identifier `` `wp_options` ``
		if c == '`' {
			endRel := strings.IndexByte(sqlDump[i+1:], '`')
			if endRel < 0 {
				out.WriteString(sqlDump[i:])
				break
			}
			ident := sqlDump[i+1 : i+1+endRel]
			if renamePrefix && strings.HasPrefix(ident, oldPrefix) {
				out.WriteByte('`')
				out.WriteString(newPrefix)
				out.WriteString(ident[len(oldPrefix):])
				out.WriteByte('`')
				totalReplacements++
			} else {
				out.WriteString(sqlDump[i : i+2+endRel])
			}
			i += 2 + endRel
			continue
		}

		// Single-quoted MySQL string literal `'...'`
		if c == '\'' {
			litStart := i
			unescaped, nextIdx, ok := consumeMySQLSingleQuotedLiteral(sqlDump, i)
			if !ok {
				out.WriteString(sqlDump[i:])
				break
			}
			modified := unescaped
			localHits := 0

			if renamePrefix && isWPRoleOrCapKey(modified, oldPrefix) {
				modified = newPrefix + modified[len(oldPrefix):]
				localHits++
			}

			if len(expanded) > 0 && containsAnyNeedle(modified, expanded) {
				var hits int
				modified, hits = replacePHPSerializedRecursive(modified, expanded, 0)
				localHits += hits
			}

			if localHits > 0 {
				out.WriteString(encodeMySQLSingleQuotedLiteral(modified))
				totalReplacements += localHits
			} else {
				out.WriteString(sqlDump[litStart:nextIdx])
			}
			i = nextIdx
			continue
		}

		out.WriteByte(c)
		i++
	}

	return out.String(), totalReplacements
}

func expandReplacementPairs(pairs [][2]string) [][2]string {
	if len(pairs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(pairs)*2)
	out := make([][2]string, 0, len(pairs)*2)
	addPair := func(oldVal, newVal string) {
		if oldVal == "" || oldVal == newVal {
			return
		}
		if _, exists := seen[oldVal]; exists {
			return
		}
		seen[oldVal] = struct{}{}
		out = append(out, [2]string{oldVal, newVal})
	}

	for _, p := range pairs {
		addPair(p[0], p[1])
		// Elementor & Gutenberg store JSON-escaped forward slashes (`https:\/\/domain.com\/...`)
		if strings.Contains(p[0], "/") {
			addPair(strings.ReplaceAll(p[0], "/", `\/`), strings.ReplaceAll(p[1], "/", `\/`))
		}
	}
	return out
}

func replacePHPSerializedRecursive(s string, pairs [][2]string, depth int) (string, int) {
	if s == "" || !containsAnyNeedle(s, pairs) {
		return s, 0
	}

	var out strings.Builder
	out.Grow(len(s) + 64)
	totalHits := 0
	plainStart := 0
	n := len(s)
	i := 0

	for i < n {
		if s[i] == 's' && i+4 < n && s[i+1] == ':' && isPHPSerializedBoundary(s, i) {
			byteLen, openQuoteIdx, ok := parseSerializedLengthPrefix(s, i+2)
			if ok {
				closeQuoteIdx := openQuoteIdx + 1 + byteLen
				if closeQuoteIdx+1 < n && s[closeQuoteIdx] == '"' && (s[closeQuoteIdx+1] == ';' || s[closeQuoteIdx+1] == '}') {
					// Flush preceding plain segment
					if i > plainStart {
						replacedPlain, pHits := replacePlainPairs(s[plainStart:i], pairs)
						out.WriteString(replacedPlain)
						totalHits += pHits
					}

					inner := s[openQuoteIdx+1 : closeQuoteIdx]
					var updatedInner string
					var innerHits int
					if depth < 6 && strings.Contains(inner, "s:") {
						updatedInner, innerHits = replacePHPSerializedRecursive(inner, pairs, depth+1)
					} else {
						updatedInner, innerHits = replacePlainPairs(inner, pairs)
					}
					totalHits += innerHits

					out.WriteString("s:")
					out.WriteString(strconv.Itoa(len(updatedInner)))
					out.WriteString(`:"`)
					out.WriteString(updatedInner)
					out.WriteByte('"')
					out.WriteByte(s[closeQuoteIdx+1])

					i = closeQuoteIdx + 2
					plainStart = i
					continue
				}
			}
		}
		i++
	}

	if plainStart < n {
		replacedTail, tHits := replacePlainPairs(s[plainStart:], pairs)
		out.WriteString(replacedTail)
		totalHits += tHits
	}

	return out.String(), totalHits
}

func isPHPSerializedBoundary(s string, pos int) bool {
	if pos == 0 {
		return true
	}
	switch s[pos-1] {
	case '{', ';', ':', '"', '\n', '\r', ' ':
		return true
	default:
		return false
	}
}

func parseSerializedLengthPrefix(s string, start int) (length int, openQuoteIdx int, ok bool) {
	j := start
	n := len(s)
	if j >= n || s[j] < '0' || s[j] > '9' {
		return 0, 0, false
	}
	val := 0
	for j < n && s[j] >= '0' && s[j] <= '9' {
		val = val*10 + int(s[j]-'0')
		if val > 64*1024*1024 {
			return 0, 0, false
		}
		j++
	}
	if j+1 >= n || s[j] != ':' || s[j+1] != '"' {
		return 0, 0, false
	}
	return val, j + 1, true
}

func replacePlainPairs(segment string, pairs [][2]string) (string, int) {
	cur := segment
	hits := 0
	for _, p := range pairs {
		cnt := strings.Count(cur, p[0])
		if cnt > 0 {
			cur = strings.ReplaceAll(cur, p[0], p[1])
			hits += cnt
		}
	}
	return cur, hits
}

func containsAnyNeedle(s string, pairs [][2]string) bool {
	for _, p := range pairs {
		if strings.Contains(s, p[0]) {
			return true
		}
	}
	return false
}

func consumeMySQLSingleQuotedLiteral(sql string, openQuoteIdx int) (unescaped string, nextIdx int, ok bool) {
	var b strings.Builder
	n := len(sql)
	i := openQuoteIdx + 1
	for i < n {
		ch := sql[i]
		if ch == '\\' {
			if i+1 >= n {
				return "", n, false
			}
			esc := sql[i+1]
			switch esc {
			case '0':
				b.WriteByte(0)
			case 'b':
				b.WriteByte('\b')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'Z':
				b.WriteByte(26)
			case '\\', '\'', '"':
				b.WriteByte(esc)
			default:
				b.WriteByte(esc)
			}
			i += 2
			continue
		}
		if ch == '\'' {
			// Doubled single quote `''` escape
			if i+1 < n && sql[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			return b.String(), i + 1, true
		}
		b.WriteByte(ch)
		i++
	}
	return "", n, false
}

func encodeMySQLSingleQuotedLiteral(raw string) string {
	var b strings.Builder
	b.Grow(len(raw) + 8)
	b.WriteByte('\'')
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case 0:
			b.WriteString(`\0`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case 26:
			b.WriteString(`\Z`)
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		default:
			b.WriteByte(raw[i])
		}
	}
	b.WriteByte('\'')
	return b.String()
}

func isWPRoleOrCapKey(val, oldPrefix string) bool {
	if !strings.HasPrefix(val, oldPrefix) {
		return false
	}
	rest := val[len(oldPrefix):]
	switch rest {
	case "user_roles", "capabilities", "user_level", "user-settings", "user-settings-time", "dashboard_quick_press_last_post_id":
		return true
	default:
		return false
	}
}
