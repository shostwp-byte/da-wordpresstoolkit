package database

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
)

const (
	DefaultDAMySQLConfPath = "/usr/local/directadmin/conf/mysql.conf"
	DefaultDAAPIConfPath   = "/etc/da-wptoolkit/da_api.conf"
	DefaultDAHooksDir      = "/usr/local/directadmin/scripts/custom"
)

// Credentials holds newly provisioned MariaDB database credentials for a WordPress installation.
type Credentials struct {
	DBName   string `json:"db_name"`
	DBUser   string `json:"db_user"`
	Password string `json:"-"` // Never serialized into persistent JSON logs
	Host     string `json:"host"`
}

// Provisioner abstracts DirectAdmin-compatible database creation and removal.
type Provisioner interface {
	CreateDatabase(ctx context.Context, acct dausers.Account, suffixHint string) (Credentials, error)
	DropDatabase(ctx context.Context, acct dausers.Account, dbName, dbUser string) error
}

// SQLExecutor executes root MariaDB statements via --defaults-extra-file with SQL passed over STDIN.
type SQLExecutor func(ctx context.Context, defaultsFile string, sqlStdin string) error

// Manager provisions MariaDB databases via DirectAdmin Local API (CMD_API_DATABASES) when configured,
// falling back seamlessly to DirectAdmin's mysql.conf (da_admin) + firing DA custom post-hooks.
type Manager struct {
	DAMySQLConfPath string
	DAAPIConfPath   string
	DAHooksDir      string
	TempSecretDir   string
	ExecSQL         SQLExecutor
}

func NewManager(daMySQLConfPath, daAPIConfPath, daHooksDir string) *Manager {
	if daMySQLConfPath == "" {
		daMySQLConfPath = DefaultDAMySQLConfPath
	}
	if daAPIConfPath == "" {
		daAPIConfPath = DefaultDAAPIConfPath
	}
	if daHooksDir == "" {
		daHooksDir = DefaultDAHooksDir
	}
	m := &Manager{
		DAMySQLConfPath: daMySQLConfPath,
		DAAPIConfPath:   daAPIConfPath,
		DAHooksDir:      daHooksDir,
		TempSecretDir:   "/run/da-wptoolkit",
	}
	m.ExecSQL = defaultMariaDBCLIExecutor
	return m
}

// CreateDatabase creates `<username>_<suffix>` DB and DB user safely and triggers DirectAdmin DB hooks.
func (m *Manager) CreateDatabase(ctx context.Context, acct dausers.Account, suffixHint string) (Credentials, error) {
	if err := config.ValidateIdentifier(acct.Username); err != nil {
		return Credentials{}, err
	}

	suffix, err := buildSafeDBSuffix(acct.Username, suffixHint)
	if err != nil {
		return Credentials{}, err
	}
	fullName := acct.Username + "_" + suffix
	password, err := generateStrongAlnumPassword(24)
	if err != nil {
		return Credentials{}, err
	}

	creds := Credentials{
		DBName:   fullName,
		DBUser:   fullName,
		Password: password,
		Host:     "localhost",
	}

	// 1. Prefer DirectAdmin Local API (CMD_API_DATABASES) if Admin Login Key is configured
	if apiOK, apiErr := m.tryCreateViaDirectAdminAPI(ctx, acct.Username, suffix, password); apiOK {
		if apiErr != nil {
			return Credentials{}, apiErr
		}
		return creds, nil
	}

	// 2. Fallback to DirectAdmin mysql.conf (da_admin) via temporary 0600 defaults-extra-file + STDIN SQL
	if err := m.createViaMySQLConf(ctx, creds); err != nil {
		return Credentials{}, err
	}

	m.triggerDatabasePostHooks(ctx, acct.Username, creds.DBName, creds.DBUser)
	return creds, nil
}

// DropDatabase drops `<username>_*` database and user after verifying strict ownership prefix!
func (m *Manager) DropDatabase(ctx context.Context, acct dausers.Account, dbName, dbUser string) error {
	if err := config.ValidateIdentifier(acct.Username); err != nil {
		return err
	}
	prefix := acct.Username + "_"
	if dbName != "" {
		if err := config.ValidateIdentifier(dbName); err != nil || !strings.HasPrefix(dbName, prefix) {
			return fmt.Errorf("refusing to drop database %q not owned by %s", dbName, acct.Username)
		}
	}
	if dbUser != "" {
		if err := config.ValidateIdentifier(dbUser); err != nil || !strings.HasPrefix(dbUser, prefix) {
			return fmt.Errorf("refusing to drop database user %q not owned by %s", dbUser, acct.Username)
		}
	}

	if apiOK, apiErr := m.tryDeleteViaDirectAdminAPI(ctx, acct.Username, dbName); apiOK && apiErr == nil {
		return nil
	}

	var sqlBuilder strings.Builder
	if dbName != "" {
		fmt.Fprintf(&sqlBuilder, "DROP DATABASE IF EXISTS `%s`;\n", dbName)
	}
	if dbUser != "" {
		fmt.Fprintf(&sqlBuilder, "DROP USER IF EXISTS '%s'@'localhost';\n", dbUser)
		fmt.Fprintf(&sqlBuilder, "DROP USER IF EXISTS '%s'@'127.0.0.1';\n", dbUser)
	}
	if sqlBuilder.Len() == 0 {
		return nil
	}
	return m.runAdminSQL(ctx, sqlBuilder.String())
}

func (m *Manager) createViaMySQLConf(ctx context.Context, creds Credentials) error {
	// Password contains strictly [a-zA-Z0-9] from generateStrongAlnumPassword, and DBName/DBUser pass ValidateIdentifier
	sql := fmt.Sprintf(
		"CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"+
			"CREATE USER IF NOT EXISTS '%s'@'localhost' IDENTIFIED BY '%s';\n"+
			"ALTER USER '%s'@'localhost' IDENTIFIED BY '%s';\n"+
			"GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost';\n"+
			"FLUSH PRIVILEGES;\n",
		creds.DBName,
		creds.DBUser, creds.Password,
		creds.DBUser, creds.Password,
		creds.DBName, creds.DBUser,
	)
	return m.runAdminSQL(ctx, sql)
}

func (m *Manager) runAdminSQL(ctx context.Context, sqlStatements string) error {
	kv, err := parseMySQLConf(m.DAMySQLConfPath)
	if err != nil {
		return fmt.Errorf("read DirectAdmin mysql.conf: %w", err)
	}
	adminUser := kv["user"]
	adminPass := kv["passwd"]
	if adminUser == "" || adminPass == "" {
		return errors.New("DirectAdmin mysql.conf is missing user or passwd")
	}

	secretDir := m.TempSecretDir
	if secretDir == "" {
		secretDir = os.TempDir()
	}
	if mkErr := os.MkdirAll(secretDir, 0o700); mkErr != nil {
		secretDir = os.TempDir()
	}

	tmp, err := os.CreateTemp(secretDir, ".mycnf-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}

	var cnf strings.Builder
	cnf.WriteString("[client]\n")
	fmt.Fprintf(&cnf, "user=%s\n", adminUser)
	fmt.Fprintf(&cnf, "password=\"%s\"\n", strings.ReplaceAll(adminPass, `"`, `\"`))
	if sock := kv["socket"]; sock != "" {
		fmt.Fprintf(&cnf, "socket=%s\n", sock)
	} else if host := kv["host"]; host != "" {
		fmt.Fprintf(&cnf, "host=%s\n", host)
	}
	cnf.WriteString("default-character-set=utf8mb4\n")

	if _, err := tmp.WriteString(cnf.String()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return m.ExecSQL(ctx, tmpPath, sqlStatements)
}

func (m *Manager) tryCreateViaDirectAdminAPI(ctx context.Context, username, suffix, password string) (configured bool, err error) {
	apiCfg, cfgErr := parseMySQLConf(m.DAAPIConfPath)
	if cfgErr != nil || apiCfg["login_key"] == "" {
		return false, nil
	}
	daURL := strings.TrimRight(apiCfg["url"], "/")
	if daURL == "" {
		daURL = "https://127.0.0.1:2222"
	}
	adminUser := apiCfg["admin_user"]
	if adminUser == "" {
		adminUser = "admin"
	}

	form := url.Values{}
	form.Set("action", "create")
	form.Set("name", suffix)
	form.Set("user", suffix)
	form.Set("passwd", password)
	form.Set("passwd2", password)

	body, postErr := sendDirectAdminAPI(ctx, daURL+"/CMD_API_DATABASES", adminUser+"|"+username, apiCfg["login_key"], form)
	if postErr != nil {
		return true, postErr
	}
	parsed, _ := url.ParseQuery(body)
	if parsed.Get("error") != "0" {
		return true, fmt.Errorf("DirectAdmin CMD_API_DATABASES error: %s (%s)", parsed.Get("text"), parsed.Get("details"))
	}
	return true, nil
}

func (m *Manager) tryDeleteViaDirectAdminAPI(ctx context.Context, username, fullDBName string) (configured bool, err error) {
	if fullDBName == "" {
		return false, nil
	}
	apiCfg, cfgErr := parseMySQLConf(m.DAAPIConfPath)
	if cfgErr != nil || apiCfg["login_key"] == "" {
		return false, nil
	}
	daURL := strings.TrimRight(apiCfg["url"], "/")
	if daURL == "" {
		daURL = "https://127.0.0.1:2222"
	}
	adminUser := apiCfg["admin_user"]
	if adminUser == "" {
		adminUser = "admin"
	}

	form := url.Values{}
	form.Set("action", "delete")
	form.Set("select0", fullDBName)

	body, postErr := sendDirectAdminAPI(ctx, daURL+"/CMD_API_DATABASES", adminUser+"|"+username, apiCfg["login_key"], form)
	if postErr != nil {
		return true, postErr
	}
	parsed, _ := url.ParseQuery(body)
	if parsed.Get("error") != "0" {
		return true, fmt.Errorf("DirectAdmin CMD_API_DATABASES delete error: %s", parsed.Get("text"))
	}
	return true, nil
}

func (m *Manager) triggerDatabasePostHooks(ctx context.Context, username, dbName, dbUser string) {
	hookSubdir := filepath.Join(m.DAHooksDir, "database_user_create_post")
	entries, err := os.ReadDir(hookSubdir)
	if err != nil {
		return
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".sh") {
			continue
		}
		scriptPath := filepath.Join(hookSubdir, ent.Name())
		hCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		cmd := exec.CommandContext(hCtx, scriptPath)
		cmd.Env = append(os.Environ(),
			"username="+username,
			"database="+dbName,
			"user="+dbUser,
		)
		_ = cmd.Run()
		cancel()
	}
}

func sendDirectAdminAPI(ctx context.Context, endpoint, loginUser, loginKey string, form url.Values) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // Local loopback 127.0.0.1:2222 self-signed cert
	}
	cli := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(loginUser, loginKey)

	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("DirectAdmin API HTTP %d", resp.StatusCode)
	}
	return string(raw), nil
}

func defaultMariaDBCLIExecutor(ctx context.Context, defaultsFile string, sqlStdin string) error {
	mysqlBin := "/usr/bin/mysql"
	for _, cand := range []string{"/usr/local/mysql/bin/mysql", "/usr/local/bin/mysql", "/usr/bin/mariadb", "/usr/bin/mysql"} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			mysqlBin = cand
			break
		}
	}
	tCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(tCtx, mysqlBin, "--defaults-extra-file="+defaultsFile, "--batch", "--silent")
	cmd.Stdin = strings.NewReader(sqlStdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mariadb command failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func buildSafeDBSuffix(username, hint string) (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	randHex := hex.EncodeToString(b[:]) // 6 hex chars

	cleanHint := strings.Builder{}
	for i := 0; i < len(hint) && cleanHint.Len() < 6; i++ {
		c := hint[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			cleanHint.WriteByte(c)
		} else if c >= 'A' && c <= 'Z' {
			cleanHint.WriteByte(c + ('a' - 'A'))
		}
	}
	prefix := cleanHint.String()
	if prefix == "" {
		prefix = "wp"
	}
	suffix := prefix + randHex

	// MariaDB usernames max 32..48 chars on DirectAdmin; cap total `<username>_<suffix>` <= 31 chars
	maxSuffix := 31 - (len(username) + 1)
	if maxSuffix < 6 {
		return "", fmt.Errorf("username %q is too long to construct MariaDB user", username)
	}
	if len(suffix) > maxSuffix {
		suffix = suffix[:maxSuffix]
	}
	return suffix, nil
}

func generateStrongAlnumPassword(length int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, v := range buf {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out), nil
}

func parseMySQLConf(path string) (map[string]string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlinked secret file %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		out[strings.TrimSpace(line[:idx])] = strings.TrimSpace(line[idx+1:])
	}
	return out, sc.Err()
}
