package quicktools

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
)

// CronInstaller applies a rendered Vixie/Cronie user crontab via `crontab -u <user> -` on Linux hosts.
type CronInstaller func(ctx context.Context, username string, crontabBody string) error

type daCronEntry struct {
	Minute     string
	Hour       string
	DayOfMonth string
	Month      string
	DayOfWeek  string
	Command    string
}

// DACronManager synchronizes WordPress system cron jobs with DirectAdmin's per-user `crontab.conf`
// while preserving 100% of customer-created cron jobs and environment headers (`MAILTO`, `PATH`).
type DACronManager struct {
	DADataRoot     string
	CrontabBin     string
	InstallCrontab CronInstaller

	mu sync.Mutex
}

func NewDACronManager(daDataRoot string) *DACronManager {
	if strings.TrimSpace(daDataRoot) == "" {
		daDataRoot = "/usr/local/directadmin/data"
	}
	m := &DACronManager{
		DADataRoot: daDataRoot,
		CrontabBin: "/usr/bin/crontab",
	}
	m.InstallCrontab = m.defaultInstallCrontab
	return m
}

// NormalizeCronInterval validates and normalizes a wp-cron replacement schedule (5, 10, 15, 30, or 60 minutes).
func NormalizeCronInterval(minutes int) int {
	switch minutes {
	case 5, 10, 15, 30, 60:
		return minutes
	case 0:
		return 15
	default:
		if minutes < 5 {
			return 5
		}
		if minutes > 60 {
			return 60
		}
		return 15
	}
}

func cronMarkerTag(instanceID string) string {
	return "# da-wptk:" + instanceID
}

// BuildWPCronCommand constructs the DirectAdmin CLI PHP command for an instance's wp-cron.php.
func BuildWPCronCommand(phpBinary, verifiedDocRoot, instanceID string) string {
	phpBin := strings.TrimSpace(phpBinary)
	if phpBin == "" {
		phpBin = "/usr/local/bin/php"
	}
	cronScript := filepath.ToSlash(filepath.Join(verifiedDocRoot, "wp-cron.php"))
	return fmt.Sprintf(`%s -q "%s" >/dev/null 2>&1 %s`, phpBin, cronScript, cronMarkerTag(instanceID))
}

func (m *DACronManager) userCrontabConfPath(username string) (string, error) {
	if err := config.ValidateIdentifier(username); err != nil {
		return "", err
	}
	return filepath.Join(m.DADataRoot, "users", username, "crontab.conf"), nil
}

// SyncInstanceCron adds, updates, or removes the DirectAdmin cron entry for a WordPress instance.
func (m *DACronManager) SyncInstanceCron(
	ctx context.Context,
	username string,
	instanceID string,
	enable bool,
	intervalMinutes int,
	phpBinary string,
	verifiedDocRoot string,
) (string, error) {
	if err := config.ValidateInstanceID(instanceID); err != nil {
		return "", err
	}
	confPath, err := m.userCrontabConfPath(username)
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	headers, entries, err := readDACrontabConf(confPath)
	if err != nil {
		return "", err
	}

	tag := cronMarkerTag(instanceID)
	kept := make([]daCronEntry, 0, len(entries)+1)
	for _, e := range entries {
		if strings.Contains(e.Command, tag) {
			continue
		}
		kept = append(kept, e)
	}

	var renderedCmd string
	if enable {
		iv := NormalizeCronInterval(intervalMinutes)
		minuteField := fmt.Sprintf("*/%d", iv)
		if iv == 60 {
			minuteField = "0"
		}
		renderedCmd = BuildWPCronCommand(phpBinary, verifiedDocRoot, instanceID)
		kept = append(kept, daCronEntry{
			Minute:     minuteField,
			Hour:       "*",
			DayOfMonth: "*",
			Month:      "*",
			DayOfWeek:  "*",
			Command:    renderedCmd,
		})
	}

	if err := writeDACrontabConfAtomic(confPath, headers, kept); err != nil {
		return "", err
	}

	if m.InstallCrontab != nil {
		vixie := renderVixieCrontab(headers, kept)
		if err := m.InstallCrontab(ctx, username, vixie); err != nil {
			return "", err
		}
	}

	return renderedCmd, nil
}

func (m *DACronManager) defaultInstallCrontab(ctx context.Context, username, crontabBody string) error {
	if _, err := os.Stat(m.CrontabBin); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, m.CrontabBin, "-u", username, "-")
	cmd.Stdin = strings.NewReader(crontabBody)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab -u %s failed: %w (%s)", username, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func readDACrontabConf(confPath string) ([]string, []daCronEntry, error) {
	raw, err := os.ReadFile(confPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	type indexedEntry struct {
		idx   int
		entry daCronEntry
	}
	var headers []string
	var indexed []indexedEntry

	for _, rawLine := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			headers = append(headers, line)
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := line[eq+1:]
		n, nErr := strconv.Atoi(key)
		if nErr != nil {
			headers = append(headers, line)
			continue
		}
		parsed, ok := parseDACronValue(val)
		if !ok {
			headers = append(headers, line)
			continue
		}
		indexed = append(indexed, indexedEntry{idx: n, entry: parsed})
	}

	sort.SliceStable(indexed, func(i, j int) bool {
		return indexed[i].idx < indexed[j].idx
	})
	out := make([]daCronEntry, 0, len(indexed))
	for _, it := range indexed {
		out = append(out, it.entry)
	}
	return headers, out, nil
}

func parseDACronValue(encoded string) (daCronEntry, bool) {
	vals, err := url.ParseQuery(encoded)
	if err != nil {
		return daCronEntry{}, false
	}
	cmd := vals.Get("command")
	if cmd == "" {
		return daCronEntry{}, false
	}
	return daCronEntry{
		Minute:     defaultIfEmpty(vals.Get("minute"), "*"),
		Hour:       defaultIfEmpty(vals.Get("hour"), "*"),
		DayOfMonth: defaultIfEmpty(vals.Get("day_of_month"), "*"),
		Month:      defaultIfEmpty(vals.Get("month"), "*"),
		DayOfWeek:  defaultIfEmpty(vals.Get("day_of_week"), "*"),
		Command:    cmd,
	}, true
}

func encodeDACronValue(e daCronEntry) string {
	// DirectAdmin expects deterministic key order: minute, hour, day_of_month, month, day_of_week, command
	return "minute=" + url.QueryEscape(defaultIfEmpty(e.Minute, "*")) +
		"&hour=" + url.QueryEscape(defaultIfEmpty(e.Hour, "*")) +
		"&day_of_month=" + url.QueryEscape(defaultIfEmpty(e.DayOfMonth, "*")) +
		"&month=" + url.QueryEscape(defaultIfEmpty(e.Month, "*")) +
		"&day_of_week=" + url.QueryEscape(defaultIfEmpty(e.DayOfWeek, "*")) +
		"&command=" + url.QueryEscape(e.Command)
}

func writeDACrontabConfAtomic(confPath string, headers []string, entries []daCronEntry) error {
	if err := os.MkdirAll(filepath.Dir(confPath), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	for idx, e := range entries {
		fmt.Fprintf(&b, "%d=%s\n", idx, encodeDACronValue(e))
	}
	tmp := confPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, confPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func renderVixieCrontab(headers []string, entries []daCronEntry) string {
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h)
		b.WriteByte('\n')
	}
	for _, e := range entries {
		fmt.Fprintf(&b, "%s %s %s %s %s %s\n", e.Minute, e.Hour, e.DayOfMonth, e.Month, e.DayOfWeek, e.Command)
	}
	return b.String()
}

func defaultIfEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.TrimSpace(s)
}
