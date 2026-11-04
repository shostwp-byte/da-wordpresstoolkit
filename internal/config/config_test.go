package config

import "testing"

func TestValidators(t *testing.T) {
	validIDs := []string{"reno26", "vina_host", "pkg-pro.v2", "user1"}
	for _, id := range validIDs {
		if err := ValidateIdentifier(id); err != nil {
			t.Errorf("expected %q to be valid identifier, got: %v", id, err)
		}
	}

	invalidIDs := []string{"", "..", ".", "../etc", "-flag", "user;id", "a/b"}
	for _, id := range invalidIDs {
		if err := ValidateIdentifier(id); err == nil {
			t.Errorf("expected %q to be rejected as invalid identifier", id)
		}
	}

	if err := ValidateSessionID("abc123XYZ_session-998877"); err != nil {
		t.Fatalf("unexpected session ID error: %v", err)
	}
	for _, bad := range []string{"short", "../da_sess_root", "abc/def12345", "abc def12345"} {
		if err := ValidateSessionID(bad); err == nil {
			t.Errorf("expected session ID %q to be rejected", bad)
		}
	}

	if err := ValidateDomainName("staging.renolabs-audio.com"); err != nil {
		t.Fatalf("unexpected domain validation error: %v", err)
	}
	for _, badDom := range []string{"localhost", "-bad.com", "bad-.com", "sub..example.com", "bad/path.com"} {
		if err := ValidateDomainName(badDom); err == nil {
			t.Errorf("expected domain %q to be rejected", badDom)
		}
	}
}

func TestPolicyStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ps := NewPolicyStore(dir, "")

	def, err := ps.LoadDefaultPolicy()
	if err != nil {
		t.Fatalf("LoadDefaultPolicy error: %v", err)
	}
	if def.DefaultCoreShieldMode != ShieldModeAutoHeal || !def.Enabled {
		t.Fatalf("unexpected defaults: %+v", def)
	}

	custom := DefaultPackagePolicy()
	custom.MaxInstances = 10
	custom.MaxSnapshotsPerSite = 3
	custom.DefaultCoreShieldMode = ShieldModeFortressLock
	if err := ps.SavePackagePolicy("business_vip", custom); err != nil {
		t.Fatalf("SavePackagePolicy error: %v", err)
	}

	resolved, err := ps.ResolvePackagePolicy("business_vip")
	if err != nil {
		t.Fatalf("ResolvePackagePolicy error: %v", err)
	}
	if resolved.MaxInstances != 10 || resolved.MaxSnapshotsPerSite != 3 || resolved.DefaultCoreShieldMode != ShieldModeFortressLock {
		t.Fatalf("resolved policy mismatch: %+v", resolved)
	}
}
