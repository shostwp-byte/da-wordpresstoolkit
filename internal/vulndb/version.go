package vulndb

import (
	"strconv"
	"strings"
	"unicode"
)

// VersionRange represents a Wordfence affected_versions interval.
type VersionRange struct {
	FromVersion   string `json:"from_version"`
	FromInclusive bool   `json:"from_inclusive"`
	ToVersion     string `json:"to_version"`
	ToInclusive   bool   `json:"to_inclusive"`
}

// InAffectedRange evaluates whether installedVersion falls inside r using WordPress/PHP version_compare semantics.
func InAffectedRange(installedVersion string, r VersionRange) bool {
	ver := strings.TrimSpace(installedVersion)
	if ver == "" {
		return false
	}

	from := strings.TrimSpace(r.FromVersion)
	if from != "" && from != "*" {
		cmp := CompareVersions(ver, from)
		if r.FromInclusive {
			if cmp < 0 {
				return false
			}
		} else if cmp <= 0 {
			return false
		}
	}

	to := strings.TrimSpace(r.ToVersion)
	if to != "" && to != "*" {
		cmp := CompareVersions(ver, to)
		if r.ToInclusive {
			if cmp > 0 {
				return false
			}
		} else if cmp >= 0 {
			return false
		}
	}

	return true
}

type verToken struct {
	isNum bool
	num   int64
	stage int // pre-release rank: dev=1, alpha=2, beta=3, rc=4, pl/p=6, unknown text=0
	raw   string
}

// CompareVersions compares two WordPress/PHP version strings (returns -1 if a < b, 0 if a == b, +1 if a > b).
func CompareVersions(a, b string) int {
	ta := tokenizeVersion(a)
	tb := tokenizeVersion(b)

	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}

	for i := 0; i < n; i++ {
		var va, vb verToken
		hasA := i < len(ta)
		hasB := i < len(tb)
		if hasA {
			va = ta[i]
		} else {
			va = verToken{isNum: true, num: 0}
		}
		if hasB {
			vb = tb[i]
		} else {
			vb = verToken{isNum: true, num: 0}
		}

		// When one side ends and the other starts a pre-release tag (e.g. "1.2.0" vs "1.2.0-beta1"),
		// the stable version ("1.2.0") is GREATER than pre-release ("beta1"), and LESS than patch ("pl1").
		if !hasA && !vb.isNum {
			if vb.stage >= 6 {
				return -1
			}
			return 1
		}
		if !hasB && !va.isNum {
			if va.stage >= 6 {
				return 1
			}
			return -1
		}

		if va.isNum && vb.isNum {
			if va.num < vb.num {
				return -1
			}
			if va.num > vb.num {
				return 1
			}
			continue
		}

		if va.isNum != vb.isNum {
			// A numeric segment (e.g. 1.2.1) is newer than a pre-release tag at the same position (1.2-beta1)
			if va.isNum {
				if vb.stage >= 6 {
					return -1
				}
				return 1
			}
			if va.stage >= 6 {
				return 1
			}
			return -1
		}

		// Both non-numeric tokens
		if va.stage != vb.stage {
			if va.stage < vb.stage {
				return -1
			}
			return 1
		}
		if va.raw < vb.raw {
			return -1
		}
		if va.raw > vb.raw {
			return 1
		}
	}

	return 0
}

func tokenizeVersion(v string) []verToken {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return nil
	}

	var tokens []verToken
	i := 0
	for i < len(s) {
		ch := rune(s[i])
		if ch == '.' || ch == '-' || ch == '_' || ch == '+' || unicode.IsSpace(ch) {
			i++
			continue
		}
		if ch >= '0' && ch <= '9' {
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			n, _ := strconv.ParseInt(s[i:j], 10, 64)
			tokens = append(tokens, verToken{isNum: true, num: n, raw: s[i:j]})
			i = j
			continue
		}
		j := i
		for j < len(s) && ((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z')) {
			j++
		}
		if j == i {
			i++
			continue
		}
		word := s[i:j]
		tokens = append(tokens, verToken{
			isNum: false,
			stage: classifyStage(word),
			raw:   word,
		})
		i = j
	}
	return tokens
}

func classifyStage(word string) int {
	switch word {
	case "dev":
		return 1
	case "alpha", "a":
		return 2
	case "beta", "b":
		return 3
	case "rc":
		return 4
	case "pl", "p", "patch":
		return 6
	default:
		return 0
	}
}
