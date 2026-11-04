package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
)

func TestCreateAndDropDatabaseOwnershipAndSecretIsolation(t *testing.T) {
	tmp := t.TempDir()
	mysqlConf := filepath.Join(tmp, "mysql.conf")
	if err := os.WriteFile(mysqlConf, []byte("user=da_admin\npasswd=SuperSecretRootPass\nsocket=/var/lib/mysql/mysql.sock\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var executedSQL string
	mgr := NewManager(mysqlConf, filepath.Join(tmp, "no_api.conf"), filepath.Join(tmp, "hooks"))
	mgr.TempSecretDir = tmp
	mgr.ExecSQL = func(_ context.Context, defaultsFile string, sqlStdin string) error {
		// Ensure temporary defaults file exists during call and contains da_admin credentials
		raw, err := os.ReadFile(defaultsFile)
		if err != nil || !strings.Contains(string(raw), "da_admin") {
			t.Fatalf("expected temporary defaults-extra-file with da_admin, err=%v", err)
		}
		executedSQL = sqlStdin
		return nil
	}

	acct := dausers.Account{Username: "vina_host", UID: 1008, GID: 1008}
	creds, err := mgr.CreateDatabase(context.Background(), acct, "shop")
	if err != nil {
		t.Fatalf("CreateDatabase failed: %v", err)
	}
	if !strings.HasPrefix(creds.DBName, "vina_host_shop") || len(creds.Password) != 24 {
		t.Fatalf("unexpected credentials: %+v", creds)
	}
	if !strings.Contains(executedSQL, "CREATE DATABASE IF NOT EXISTS `"+creds.DBName+"`") {
		t.Fatalf("missing CREATE DATABASE statement: %s", executedSQL)
	}

	// Refuse dropping a database belonging to another user!
	if err := mgr.DropDatabase(context.Background(), acct, "reno26_wp1234", "reno26_wp1234"); err == nil {
		t.Fatal("expected cross-tenant DropDatabase to be blocked")
	}

	// Allow dropping own database
	if err := mgr.DropDatabase(context.Background(), acct, creds.DBName, creds.DBUser); err != nil {
		t.Fatalf("expected own DropDatabase to succeed, got: %v", err)
	}
}
