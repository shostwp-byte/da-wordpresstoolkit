package smartupdate

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

var wsodBodySignatures = []string{
	"there has been a critical error on this website",
	"fatal error:",
	"parse error:",
	"uncaught error:",
	"uncaught typeerror:",
}

// HealthResult captures the outcome of probing a WordPress site's live HTTP endpoints and PHP error logs.
type HealthResult struct {
	Healthy      bool   `json:"healthy"`
	StatusCode   int    `json:"status_code"`
	FaultReason  string `json:"fault_reason,omitempty"`
	DetectedSlug string `json:"detected_slug,omitempty"`
}

// ProberFunc checks live HTTP health of a WordPress instance.
type ProberFunc func(ctx context.Context, inst store.InstanceRecord) HealthResult

// DefaultLoopbackProber probes both the site homepage and /wp-login.php directly against local 127.0.0.1
// (bypassing external DNS / Cloudflare proxies while preserving Host & TLS SNI headers).
func DefaultLoopbackProber(ctx context.Context, inst store.InstanceRecord) HealthResult {
	rawBase := strings.TrimRight(strings.TrimSpace(inst.SiteURL), "/")
	if rawBase == "" {
		scheme := "http://"
		if inst.SSLActive {
			scheme = "https://"
		}
		rawBase = scheme + inst.Domain + inst.SubPath
	}

	parsed, err := url.Parse(rawBase)
	if err != nil || parsed.Host == "" {
		return HealthResult{Healthy: true, StatusCode: 0}
	}

	hostname := parsed.Hostname()
	explicitPort := parsed.Port()

	dialTarget := parsed.Host
	if explicitPort == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			dialTarget = "127.0.0.1:443"
		} else {
			dialTarget = "127.0.0.1:80"
		}
	}

	dialer := &net.Dialer{Timeout: 4 * time.Second}
	transport := &http.Transport{
		DialContext: func(dCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dCtx, network, dialTarget)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, // Local loopback vhost may use self-signed or mismatching cert before Let's Encrypt
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// Inspect immediate WordPress response without chasing external domain redirects
			return http.ErrUseLastResponse
		},
	}

	endpoints := []string{rawBase + "/", rawBase + "/wp-login.php"}
	lastCode := 200

	for _, ep := range endpoints {
		req, rErr := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if rErr != nil {
			continue
		}
		req.Host = parsed.Host
		req.Header.Set("User-Agent", "DA-WordPressManager-SmartHealth/1.0")
		req.Header.Set("Cache-Control", "no-cache, no-store")

		resp, doErr := client.Do(req)
		if doErr != nil {
			// If local web server isn't listening on 127.0.0.1 in an isolated CLI environment, report unreachable (StatusCode 0)
			return HealthResult{Healthy: true, StatusCode: 0}
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		_ = resp.Body.Close()

		lastCode = resp.StatusCode
		bodyStr := string(bodyBytes)
		lowerBody := strings.ToLower(bodyStr)

		if resp.StatusCode >= 500 {
			slug := extractExtensionSlugFromTrace(bodyStr)
			return HealthResult{
				Healthy:      false,
				StatusCode:   resp.StatusCode,
				FaultReason:  fmt.Sprintf("HTTP %d returned on %s", resp.StatusCode, ep),
				DetectedSlug: slug,
			}
		}

		for _, sig := range wsodBodySignatures {
			if strings.Contains(lowerBody, sig) {
				slug := extractExtensionSlugFromTrace(bodyStr)
				return HealthResult{
					Healthy:      false,
					StatusCode:   resp.StatusCode,
					FaultReason:  fmt.Sprintf("WordPress Fatal/WSOD signature (%q) detected on %s", sig, ep),
					DetectedSlug: slug,
				}
			}
		}
	}

	return HealthResult{Healthy: true, StatusCode: lastCode}
}

type logOffsets map[string]int64

func capturePreUpdateLogOffsets(guard *fsguard.Guard, verifiedDocRoot string) logOffsets {
	offsets := make(logOffsets, 3)
	candidates := [][]string{
		{"wp-content", "debug.log"},
		{"error_log"},
		{"wp-admin", "error_log"},
	}
	for _, rel := range candidates {
		p, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, rel...)
		if err != nil {
			continue
		}
		if st, sErr := os.Lstat(p); sErr == nil && st.Mode().IsRegular() {
			offsets[strings.Join(rel, "/")] = st.Size()
		} else {
			offsets[strings.Join(rel, "/")] = 0
		}
	}
	return offsets
}

func inspectNewFatalLogs(guard *fsguard.Guard, verifiedDocRoot string, before logOffsets) (faultReason string, culpritSlug string) {
	candidates := [][]string{
		{"wp-content", "debug.log"},
		{"error_log"},
		{"wp-admin", "error_log"},
	}
	for _, rel := range candidates {
		key := strings.Join(rel, "/")
		p, err := guard.VerifyChildUnderVerifiedRoot(verifiedDocRoot, false, rel...)
		if err != nil {
			continue
		}
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		prevSize := before[key]
		if st.Size() <= prevSize {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		startAt := prevSize
		if st.Size()-startAt > 64*1024 {
			startAt = st.Size() - 64*1024
		}
		_, _ = f.Seek(startAt, io.SeekStart)
		tailBytes, _ := io.ReadAll(io.LimitReader(f, 64*1024))
		_ = f.Close()

		tail := string(tailBytes)
		lower := strings.ToLower(tail)
		if strings.Contains(lower, "php fatal error") || strings.Contains(lower, "php parse error") || strings.Contains(lower, "uncaught error") {
			slug := extractExtensionSlugFromTrace(tail)
			return fmt.Sprintf("new PHP Fatal/Parse error appended in %s", key), slug
		}
	}
	return "", ""
}

func extractExtensionSlugFromTrace(text string) string {
	norm := strings.ReplaceAll(text, `\`, "/")
	for _, marker := range []string{"/wp-content/plugins/", "/wp-content/themes/"} {
		idx := strings.Index(norm, marker)
		if idx < 0 {
			continue
		}
		rest := norm[idx+len(marker):]
		slash := strings.IndexByte(rest, '/')
		if slash > 0 {
			cand := strings.TrimSpace(rest[:slash])
			if cand != "" {
				return strings.TrimSuffix(cand, ".php")
			}
		} else {
			// Single-file plugin like /wp-content/plugins/broken.php
			end := strings.IndexAny(rest, " :(\r\n\t'\"")
			if end > 0 {
				return filepath.Base(strings.TrimSuffix(rest[:end], ".php"))
			}
		}
	}
	return ""
}
