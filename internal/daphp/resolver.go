package daphp

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultOptionsConfPath = "/usr/local/directadmin/custombuild/options.conf"
	DefaultUsrLocalRoot    = "/usr/local"
)

// Selection represents the resolved PHP version and CLI binary for a specific DirectAdmin domain/subdomain.
type Selection struct {
	Slot       int    `json:"slot"`        // 1..4
	Version    string `json:"version"`     // e.g., "8.3"
	BinaryPath string `json:"binary_path"` // e.g., "/usr/local/php83/bin/php"
}

// Resolver maps DirectAdmin php1_select slots (1..4) to installed CustomBuild PHP CLI binaries.
type Resolver struct {
	OptionsConfPath string
	UsrLocalRoot    string
	FallbackBins    []string
}

func NewResolver(optionsConfPath, usrLocalRoot string) *Resolver {
	customRoot := usrLocalRoot != ""
	if optionsConfPath == "" {
		optionsConfPath = DefaultOptionsConfPath
	}
	if usrLocalRoot == "" {
		usrLocalRoot = DefaultUsrLocalRoot
	}
	fallbacks := []string{
		filepath.Join(usrLocalRoot, "bin", "php"),
	}
	if !customRoot {
		fallbacks = append(fallbacks, "/usr/bin/php")
	}
	return &Resolver{
		OptionsConfPath: optionsConfPath,
		UsrLocalRoot:    usrLocalRoot,
		FallbackBins:    fallbacks,
	}
}

// Resolve maps a DirectAdmin php1_select value ("1", "2", "3", "4" or "") to a PHP CLI Selection.
func (r *Resolver) Resolve(phpSelect string) Selection {
	slot := 1
	if n, err := strconv.Atoi(strings.TrimSpace(phpSelect)); err == nil && n >= 1 && n <= 4 {
		slot = n
	}

	releases := r.readSlotReleases()
	ver := releases[slot]
	if ver == "" {
		ver = releases[1]
	}
	if ver == "" {
		ver = "8.3"
	}

	compact := strings.ReplaceAll(ver, ".", "")
	primaryBin := filepath.Join(r.UsrLocalRoot, "php"+compact, "bin", "php")
	if isExecutableFile(primaryBin) {
		return Selection{Slot: slot, Version: ver, BinaryPath: primaryBin}
	}
	if r.UsrLocalRoot == DefaultUsrLocalRoot {
		altBin := filepath.Join("/opt/alt", "php"+compact, "usr", "bin", "php")
		if isExecutableFile(altBin) {
			return Selection{Slot: slot, Version: ver, BinaryPath: altBin}
		}
	}

	// Fallback if options.conf slot binary is not yet compiled or in test environment
	for _, fb := range r.FallbackBins {
		if isExecutableFile(fb) {
			return Selection{Slot: slot, Version: ver, BinaryPath: fb}
		}
	}

	// Return canonical expected path even when running unit tests without real Linux binaries on disk
	return Selection{Slot: slot, Version: ver, BinaryPath: primaryBin}
}

func (r *Resolver) readSlotReleases() map[int]string {
	out := make(map[int]string, 4)
	f, err := os.Open(r.OptionsConfPath)
	if err != nil {
		return out
	}
	defer f.Close()

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
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if val == "" || strings.EqualFold(val, "no") {
			continue
		}
		for s := 1; s <= 4; s++ {
			if key == fmt.Sprintf("php%d_release", s) {
				out[s] = val
			}
		}
	}
	return out
}

func isExecutableFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return false
	}
	return true
}
