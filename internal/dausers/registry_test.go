package dausers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryLoadsValidAccountsAndBlocksSystemUIDs(t *testing.T) {
	tmp := t.TempDir()
	passwd := filepath.Join(tmp, "passwd")
	daRoot := filepath.Join(tmp, "da_data")

	passwdContent := "" +
		"root:x:0:0:root:/root:/bin/bash\n" +
		"diradmin:x:991:991:DirectAdmin:/usr/local/directadmin:/bin/false\n" +
		"admin:x:1000:1000:Admin:/home/admin:/bin/bash\n" +
		"reno26:x:1005:1005::/home/reno26:/bin/bash\n" +
		"nobody:x:65534:65534:Kernel Overflow:/:/sbin/nologin\n"
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(daRoot, "admin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(daRoot, "admin", "admin.list"), []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, pkg := range map[string]string{"reno26": "pro_wp", "nobody": "hack"} {
		udir := filepath.Join(daRoot, "users", name)
		if err := os.MkdirAll(udir, 0o755); err != nil {
			t.Fatal(err)
		}
		conf := "package=" + pkg + "\ncreator=admin\nemail=test@example.com\nsuspended=no\n"
		if err := os.WriteFile(filepath.Join(udir, "user.conf"), []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	reg := NewRegistry(daRoot, passwd)
	if err := reg.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	acct, ok := reg.LookupByUID(1005)
	if !ok || acct.Username != "reno26" || acct.Package != "pro_wp" {
		t.Fatalf("expected reno26 on UID 1005, got ok=%v acct=%+v", ok, acct)
	}

	if _, ok := reg.LookupByUID(65534); ok {
		t.Fatal("nobody (65534) must never be indexed as a hosting account")
	}

	if adminName, ok := reg.IsAuthorizedAdminUID(1000); !ok || adminName != "admin" {
		t.Fatalf("expected UID 1000 to be authorized admin, got %q/%v", adminName, ok)
	}
	if !reg.IsRootOrDiradminUID(991) || reg.IsRootOrDiradminUID(1000) {
		t.Fatal("IsRootOrDiradminUID must allow diradmin(991) and reject secondary admin(1000)")
	}
}
