package daphp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCustomBuildPHPSlots(t *testing.T) {
	tmp := t.TempDir()
	optPath := filepath.Join(tmp, "options.conf")
	usrLocal := filepath.Join(tmp, "usr_local")

	optContent := "" +
		"php1_release=8.3\n" +
		"php2_release=8.1\n" +
		"php3_release=7.4\n" +
		"php4_release=8.4\n"
	if err := os.WriteFile(optPath, []byte(optContent), 0o644); err != nil {
		t.Fatal(err)
	}

	php81Bin := filepath.Join(usrLocal, "php81", "bin", "php")
	if err := os.MkdirAll(filepath.Dir(php81Bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(php81Bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	res := NewResolver(optPath, usrLocal)
	sel2 := res.Resolve("2")
	if sel2.Version != "8.1" || sel2.BinaryPath != php81Bin {
		t.Fatalf("slot 2 mismatch: %+v", sel2)
	}

	sel4 := res.Resolve("4")
	if sel4.Version != "8.4" || !strings.Contains(filepath.ToSlash(sel4.BinaryPath), "php84/bin/php") {
		t.Fatalf("slot 4 mismatch: %+v", sel4)
	}
}
