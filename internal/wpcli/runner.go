package wpcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/daphp"
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
)

const (
	DefaultWPCLIBinPath = "/usr/local/bin/wp"
	DefaultTimeout      = 120 * time.Second
	maxOutputBytes      = 4 * 1024 * 1024 // 4 MB cap against runaway plugin output
)

// ExecSpec captures the fully resolved, privilege-dropped process specification for execution or unit testing.
type ExecSpec struct {
	Program string
	Args    []string
	Dir     string
	Env     []string
	UID     uint32
	GID     uint32
	Stdin   string
}

// CommandExecutor abstracts OS process execution so unit tests can inspect privilege drop & CLI flags safely.
type CommandExecutor func(ctx context.Context, spec ExecSpec) (stdout string, stderr string, err error)

// CallOptions configures a single WP-CLI invocation for a customer's WordPress site.
type CallOptions struct {
	Account     dausers.Account
	DocRoot     string
	PHP         daphp.Selection
	Args        []string
	SkipPlugins bool
	SkipThemes  bool
	Stdin       string
	ExtraEnv    map[string]string
	Timeout     time.Duration
}

// Runner executes WP-CLI commands strictly under the customer's UID/GID, matching the domain's PHP binary.
type Runner struct {
	WPCLIPath   string
	NiceBin     string
	IoniceBin   string
	CoreCache   string
	ExecCommand CommandExecutor
}

func NewRunner(wpcliPath, coreCacheDir string) *Runner {
	if wpcliPath == "" {
		wpcliPath = DefaultWPCLIBinPath
	}
	if coreCacheDir == "" {
		coreCacheDir = "/var/cache/da-wptoolkit/wp-core"
	}
	r := &Runner{
		WPCLIPath: wpcliPath,
		CoreCache: coreCacheDir,
	}
	if isFile("/usr/bin/nice") {
		r.NiceBin = "/usr/bin/nice"
	}
	if isFile("/usr/bin/ionice") {
		r.IoniceBin = "/usr/bin/ionice"
	}
	r.ExecCommand = defaultOSExecutor
	return r
}

// Run validates DocRoot against symlink escape, drops privileges to Account.UID/GID, and executes WP-CLI.
func (r *Runner) Run(ctx context.Context, opts CallOptions) (string, error) {
	if opts.Account.UID < 1000 || opts.Account.UID >= 65534 {
		return "", fmt.Errorf("refusing to run WP-CLI under unsafe UID %d", opts.Account.UID)
	}
	if opts.Account.HomeDir == "" {
		return "", errors.New("account HomeDir is required for WP-CLI execution")
	}

	domainsRoot := filepath.Join(filepath.Clean(opts.Account.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return "", err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(opts.DocRoot)
	if err != nil {
		return "", err
	}

	for _, a := range opts.Args {
		lower := strings.ToLower(strings.TrimSpace(a))
		if lower == "--allow-root" || strings.HasPrefix(lower, "--require=") || strings.HasPrefix(lower, "--exec=") {
			return "", fmt.Errorf("forbidden WP-CLI flag %q blocked", a)
		}
	}

	phpBin := opts.PHP.BinaryPath
	if phpBin == "" {
		phpBin = "/usr/local/bin/php"
	}

	openBaseDir := strings.Join([]string{
		filepath.Clean(opts.Account.HomeDir),
		"/tmp",
		"/var/lib/mysql",
		"/run/mysqld",
		r.WPCLIPath,
		r.CoreCache,
		"/usr/local",
		"/usr/share",
	}, ":")

	phpAndWPArgs := []string{
		phpBin,
		"-d", "disable_functions=",
		"-d", "memory_limit=512M",
		"-d", "max_execution_time=300",
		"-d", "open_basedir=" + openBaseDir,
		r.WPCLIPath,
		"--path=" + verifiedDocRoot,
		"--no-color",
	}
	if opts.SkipPlugins {
		phpAndWPArgs = append(phpAndWPArgs, "--skip-plugins")
	}
	if opts.SkipThemes {
		phpAndWPArgs = append(phpAndWPArgs, "--skip-themes")
	}
	phpAndWPArgs = append(phpAndWPArgs, opts.Args...)

	var fullCmd []string
	if r.IoniceBin != "" {
		fullCmd = append(fullCmd, r.IoniceBin, "-c2", "-n7")
	}
	if r.NiceBin != "" {
		fullCmd = append(fullCmd, r.NiceBin, "-n", "10")
	}
	fullCmd = append(fullCmd, phpAndWPArgs...)

	cleanHome := filepath.Clean(opts.Account.HomeDir)
	env := []string{
		"HOME=" + cleanHome,
		"USER=" + opts.Account.Username,
		"LOGNAME=" + opts.Account.Username,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=en_US.UTF-8",
		"WP_CLI_CACHE_DIR=" + filepath.Join(cleanHome, ".wp-cli", "cache"),
		"WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
	}
	for k, v := range opts.ExtraEnv {
		if k != "" && !strings.Contains(k, "=") {
			env = append(env, k+"="+v)
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	spec := ExecSpec{
		Program: fullCmd[0],
		Args:    fullCmd[1:],
		Dir:     verifiedDocRoot,
		Env:     env,
		UID:     opts.Account.UID,
		GID:     opts.Account.GID,
		Stdin:   opts.Stdin,
	}

	stdout, stderr, execErr := r.ExecCommand(runCtx, spec)
	if execErr != nil {
		errMsg := strings.TrimSpace(stderr)
		if errMsg == "" {
			errMsg = strings.TrimSpace(stdout)
		}
		if errMsg != "" {
			return stdout, fmt.Errorf("wp-cli failed: %s (%w)", errMsg, execErr)
		}
		return stdout, fmt.Errorf("wp-cli failed: %w", execErr)
	}
	return strings.TrimSpace(stdout), nil
}

func defaultOSExecutor(ctx context.Context, spec ExecSpec) (string, string, error) {
	cmd := exec.CommandContext(ctx, spec.Program, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	applyPrivilegeDrop(cmd, spec.UID, spec.GID)

	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}

	var outBuf, errBuf limitedBuffer
	outBuf.max = maxOutputBytes
	errBuf.max = maxOutputBytes
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	return outBuf.buf.String(), errBuf.buf.String(), err
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	origLen := len(p)
	rem := l.max - l.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			p = p[:rem]
		}
		_, _ = l.buf.Write(p)
	}
	return origLen, nil
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
