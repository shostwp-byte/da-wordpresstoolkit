package integrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	defaultMaxDiffBytes = 16 * 1024
	maxLCSMatrixLines   = 600
)

// ComputeSafeLineDiff produces a sanitized, read-only unified diff preview between cleanBytes and tamperedBytes
// for display in the End-User & Admin Quarantine Diff Viewer.
func ComputeSafeLineDiff(relPath string, cleanBytes, tamperedBytes []byte, maxOutBytes int) string {
	if maxOutBytes <= 0 {
		maxOutBytes = defaultMaxDiffBytes
	}

	var out strings.Builder
	if cleanBytes == nil {
		fmt.Fprintf(&out, "--- /dev/null\n+++ b/%s (quarantined unknown executable)\n", relPath)
		if isLikelyBinary(tamperedBytes) {
			sum := sha256.Sum256(tamperedBytes)
			fmt.Fprintf(&out, "@@ binary payload (%d bytes, sha256=%s) @@\n", len(tamperedBytes), hex.EncodeToString(sum[:]))
			return out.String()
		}
		lines := splitSanitizedLines(tamperedBytes)
		fmt.Fprintf(&out, "@@ -0,0 +1,%d @@\n", len(lines))
		for _, ln := range lines {
			if out.Len()+len(ln)+4 > maxOutBytes {
				out.WriteString("... [diff truncated at safety limit] ...\n")
				break
			}
			out.WriteByte('+')
			out.WriteString(ln)
			out.WriteByte('\n')
		}
		return out.String()
	}

	fmt.Fprintf(&out, "--- a/%s (verified WordPress core)\n+++ b/%s (tampered on disk)\n", relPath, relPath)
	if isLikelyBinary(cleanBytes) || isLikelyBinary(tamperedBytes) {
		sumA := sha256.Sum256(cleanBytes)
		sumB := sha256.Sum256(tamperedBytes)
		fmt.Fprintf(
			&out,
			"@@ binary modification: clean=%dB (%s) -> tampered=%dB (%s) @@\n",
			len(cleanBytes),
			hex.EncodeToString(sumA[:8]),
			len(tamperedBytes),
			hex.EncodeToString(sumB[:8]),
		)
		return out.String()
	}

	aLines := splitSanitizedLines(cleanBytes)
	bLines := splitSanitizedLines(tamperedBytes)

	// Trim identical prefix and suffix lines quickly so even 5,000-line wp-includes/functions.php diffs in < 1ms!
	prefix := 0
	for prefix < len(aLines) && prefix < len(bLines) && aLines[prefix] == bLines[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < (len(aLines)-prefix) && suffix < (len(bLines)-prefix) &&
		aLines[len(aLines)-1-suffix] == bLines[len(bLines)-1-suffix] {
		suffix++
	}

	midA := aLines[prefix : len(aLines)-suffix]
	midB := bLines[prefix : len(bLines)-suffix]

	ctxBeforeStart := prefix - 3
	if ctxBeforeStart < 0 {
		ctxBeforeStart = 0
	}
	ctxAfterEnd := len(aLines) - suffix + 3
	if ctxAfterEnd > len(aLines) {
		ctxAfterEnd = len(aLines)
	}

	fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", ctxBeforeStart+1, len(midA)+(prefix-ctxBeforeStart), ctxBeforeStart+1, len(midB)+(prefix-ctxBeforeStart))
	for i := ctxBeforeStart; i < prefix; i++ {
		if !appendDiffLine(&out, ' ', aLines[i], maxOutBytes) {
			return out.String()
		}
	}

	if len(midA) <= maxLCSMatrixLines && len(midB) <= maxLCSMatrixLines {
		ops := lcsEditOps(midA, midB)
		for _, op := range ops {
			if !appendDiffLine(&out, op.kind, op.text, maxOutBytes) {
				return out.String()
			}
		}
	} else {
		for _, ln := range midA {
			if !appendDiffLine(&out, '-', ln, maxOutBytes) {
				return out.String()
			}
		}
		for _, ln := range midB {
			if !appendDiffLine(&out, '+', ln, maxOutBytes) {
				return out.String()
			}
		}
	}

	for i := len(aLines) - suffix; i < ctxAfterEnd; i++ {
		if !appendDiffLine(&out, ' ', aLines[i], maxOutBytes) {
			return out.String()
		}
	}
	return out.String()
}

type diffOp struct {
	kind byte
	text string
}

func lcsEditOps(a, b []string) []diffOp {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < m && j < n {
		if a[i] == b[j] {
			ops = append(ops, diffOp{kind: ' ', text: a[i]})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			ops = append(ops, diffOp{kind: '-', text: a[i]})
			i++
		} else {
			ops = append(ops, diffOp{kind: '+', text: b[j]})
			j++
		}
	}
	for ; i < m; i++ {
		ops = append(ops, diffOp{kind: '-', text: a[i]})
	}
	for ; j < n; j++ {
		ops = append(ops, diffOp{kind: '+', text: b[j]})
	}
	return ops
}

func appendDiffLine(out *strings.Builder, prefix byte, text string, maxOut int) bool {
	if out.Len()+len(text)+4 > maxOut {
		out.WriteString("... [diff truncated at safety limit] ...\n")
		return false
	}
	out.WriteByte(prefix)
	out.WriteString(text)
	out.WriteByte('\n')
	return true
}

func isLikelyBinary(data []byte) bool {
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	return !utf8.Valid(sample)
}

func splitSanitizedLines(raw []byte) []string {
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	rawLines := strings.Split(s, "\n")
	out := make([]string, len(rawLines))
	for i, ln := range rawLines {
		var clean strings.Builder
		clean.Grow(len(ln))
		for _, r := range ln {
			if r == '\t' || (r >= 0x20 && r != 0x7f) {
				clean.WriteRune(r)
			}
		}
		out[i] = clean.String()
	}
	return out
}
