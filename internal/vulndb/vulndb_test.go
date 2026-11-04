package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCompareVersionsAndAffectedRanges(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.7", "6.7.0", 0},
		{"3.18.0", "3.18.1", -1},
		{"3.18.10", "3.18.2", 1},
		{"1.2.0-beta1", "1.2.0", -1},
		{"1.2.0-rc1", "1.2.0-beta2", 1},
		{"2.0.0-pl1", "2.0.0", 1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}

	rng := VersionRange{
		FromVersion:   "3.0.0",
		FromInclusive: true,
		ToVersion:     "3.18.2",
		ToInclusive:   false,
	}
	if !InAffectedRange("3.0.0", rng) || !InAffectedRange("3.18.1", rng) {
		t.Fatal("expected 3.0.0 and 3.18.1 to be inside [3.0.0, 3.18.2)")
	}
	if InAffectedRange("2.9.9", rng) || InAffectedRange("3.18.2", rng) {
		t.Fatal("expected 2.9.9 and 3.18.2 to be outside [3.0.0, 3.18.2)")
	}
}

func TestStreamingWordfenceFeedSyncGzipPersistenceAndMatching(t *testing.T) {
	sampleFeed := `{
		"wf-uuid-1001": {
			"id": "wf-uuid-1001",
			"title": "Elementor <= 3.18.2 - Authenticated Arbitrary File Upload",
			"cve": "CVE-2024-10001",
			"cve_link": "https://www.cve.org/CVERecord?id=CVE-2024-10001",
			"references": ["https://www.wordfence.com/threat-intel/vulnerabilities/id/wf-uuid-1001"],
			"published": "2024-03-15 00:00:00",
			"cvss": {"score": 8.8, "rating": "High"},
			"software": [{
				"type": "plugin",
				"name": "Elementor",
				"slug": "elementor",
				"patched": true,
				"patched_versions": ["3.18.3", "3.19.1"],
				"affected_versions": {
					"* - 3.18.2": {
						"from_version": "*",
						"from_inclusive": true,
						"to_version": "3.18.2",
						"to_inclusive": true
					}
				}
			}]
		},
		"wf-uuid-1002": {
			"id": "wf-uuid-1002",
			"title": "Abandoned Slider <= 1.4.0 - Unauthenticated SQL Injection",
			"cve": "CVE-2025-20002",
			"cvss": {"score": 9.8, "rating": "Critical"},
			"software": [{
				"type": "plugin",
				"slug": "abandoned-slider",
				"patched": false,
				"patched_versions": [],
				"affected_versions": {
					"<= 1.4.0": {
						"from_version": "*",
						"from_inclusive": true,
						"to_version": "1.4.0",
						"to_inclusive": true
					}
				}
			}]
		},
		"wf-uuid-1003": {
			"id": "wf-uuid-1003",
			"title": "WordPress Core < 6.7.1 - Reflected XSS",
			"cve": "CVE-2025-30003",
			"cvss": {"score": 6.1, "rating": "Medium"},
			"software": [{
				"type": "core",
				"slug": "wordpress",
				"patched": true,
				"patched_versions": ["6.7.1"],
				"affected_versions": {
					"6.7.0": {
						"from_version": "6.7.0",
						"from_inclusive": true,
						"to_version": "6.7.1",
						"to_inclusive": false
					}
				}
			}]
		}
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(sampleFeed))
		_ = gz.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	stateDir := t.TempDir()
	db, err := Open(stateDir, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	st, err := db.Sync(context.Background(), "")
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if st.TotalRules != 3 || st.IndexedPlugins != 2 || st.CoreRules != 1 {
		t.Fatalf("unexpected feed status: %+v", st)
	}

	// Verify reload from persisted vulndb_index.json without network
	reloaded, err := Open(stateDir, "http://127.0.0.1:1/offline")
	if err != nil {
		t.Fatal(err)
	}
	hits := reloaded.MatchPlugin("elementor", "3.18.1")
	if len(hits) != 1 || hits[0].CVE != "CVE-2024-10001" || hits[0].FixedIn != "3.18.3" {
		t.Fatalf("expected Elementor 3.18.1 CVE match fixed in 3.18.3, got: %+v", hits)
	}
	if clean := reloaded.MatchPlugin("elementor", "3.18.3"); len(clean) != 0 {
		t.Fatalf("expected Elementor 3.18.3 to be clean, got: %+v", clean)
	}

	unpatched := reloaded.MatchPlugin("abandoned-slider", "1.2.0")
	if len(unpatched) != 1 || !unpatched[0].Unpatched || unpatched[0].Severity != "critical" {
		t.Fatalf("expected unpatched critical alert, got: %+v", unpatched)
	}

	if coreHits := reloaded.MatchCore("6.7.0"); len(coreHits) != 1 {
		t.Fatalf("expected WP 6.7.0 core CVE match, got: %+v", coreHits)
	}
	if coreClean := reloaded.MatchCore("6.7.1"); len(coreClean) != 0 {
		t.Fatalf("expected WP 6.7.1 core to be clean, got: %+v", coreClean)
	}
}
