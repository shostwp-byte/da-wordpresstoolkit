package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shostwp-byte/da-wptoolkits/internal/config"
)

const (
	DefaultStateDir          = "/var/lib/da-wptoolkit/state"
	DefaultMaxSecurityEvents = 500
)

var (
	ErrNotFound         = errors.New("record not found")
	ErrInstanceBusy     = errors.New("another background task is currently running on this WordPress instance")
	ErrDuplicateDocRoot = errors.New("a WordPress instance at this document root is already registered")
)

// InstanceRecord represents a managed WordPress installation (main domain, addon, subdomain, or subdirectory).
type InstanceRecord struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	OwnerUID    uint32 `json:"owner_uid"`
	Domain      string `json:"domain"`
	DomainType  string `json:"domain_type"` // main | addon | subdomain
	SubPath     string `json:"sub_path"`    // "" or "/blog"
	DocRoot     string `json:"doc_root"`
	SiteURL     string `json:"site_url"`
	SiteTitle   string `json:"site_title"`
	AdminUser   string `json:"admin_user"`
	AdminEmail  string `json:"admin_email"`
	WPVersion   string `json:"wp_version"`
	Locale      string `json:"locale"`
	PHPVersion  string `json:"php_version"`
	MemoryLimit string `json:"memory_limit"`
	DBName      string `json:"db_name"`
	DBUser      string `json:"db_user"`
	TablePrefix string `json:"table_prefix"`
	ActiveTheme string `json:"active_theme"`
	SSLActive   bool   `json:"ssl_active"`

	SearchIndexing    bool `json:"search_indexing"`
	MaintenanceMode   bool `json:"maintenance_mode"`
	DebugMode         bool `json:"debug_mode"`
	PasswordProtected bool `json:"password_protected"`
	DisableWPCron     bool `json:"disable_wp_cron"`
	CronIntervalMin   int  `json:"cron_interval_min"`
	CacheEnabled      bool `json:"cache_enabled"`

	CoreShieldMode     string `json:"core_shield_mode"` // monitor | auto_heal | fortress_lock
	CoreIntegrityClean bool   `json:"core_integrity_clean"`
	SecurityScore      int    `json:"security_score"`
	SecurityTotal      int    `json:"security_total"`

	PluginCount   int `json:"plugin_count"`
	ThemeCount    int `json:"theme_count"`
	UpdateCount   int `json:"update_count"`
	VulnCount     int `json:"vuln_count"`
	SnapshotCount int `json:"snapshot_count"`

	EnvironmentTag   string `json:"environment_tag"` // production | staging | development
	ParentInstanceID string `json:"parent_instance_id,omitempty"`
	Detached         bool   `json:"detached"`
	UpdatingFlag     bool   `json:"updating_flag"`

	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastScannedAt time.Time `json:"last_scanned_at"`
}

// PluginSet represents a reusable bundle of plugins & themes (Global Built-in Set or Custom User Set).
type PluginSet struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Owner       string    `json:"owner"` // "" = global system set
	BuiltIn     bool      `json:"built_in"`
	Plugins     []string  `json:"plugins"`
	Themes      []string  `json:"themes"`
	ActiveTheme string    `json:"active_theme,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// SecurityAuditEvent records security-relevant events (socket spoofing attempts, symlink blocks, core auto-heals).
type SecurityAuditEvent struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Severity   string    `json:"severity"` // info | warning | critical
	Category   string    `json:"category"` // ipc_auth | symlink_guard | core_auto_heal | core_thrash_lock
	Owner      string    `json:"owner,omitempty"`
	InstanceID string    `json:"instance_id,omitempty"`
	PeerUID    uint32    `json:"peer_uid,omitempty"`
	PeerPID    int32     `json:"peer_pid,omitempty"`
	Message    string    `json:"message"`
}

type persistedRegistry struct {
	SchemaVersion int                       `json:"schema_version"`
	Instances     map[string]InstanceRecord `json:"instances"`
	Sets          map[string]PluginSet      `json:"sets"`
}

// Store provides crash-safe atomic persistence and O(1) indexed lookups with zero external C/Go dependencies.
type Store struct {
	StateDir string

	mu             sync.RWMutex
	instances      map[string]InstanceRecord
	sets           map[string]PluginSet
	securityEvents []SecurityAuditEvent
}

// Open initializes or loads the persistent ACID bucket store from StateDir.
func Open(stateDir string) (*Store, error) {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = DefaultStateDir
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir %s: %w", stateDir, err)
	}

	s := &Store{
		StateDir:  stateDir,
		instances: make(map[string]InstanceRecord),
		sets:      make(map[string]PluginSet),
	}
	if err := s.loadFromDisk(); err != nil {
		return nil, err
	}
	if err := s.seedDefaultSetsIfNeeded(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) registryPath() string {
	return filepath.Join(s.StateDir, "registry.json")
}

func (s *Store) securityEventsPath() string {
	return filepath.Join(s.StateDir, "security_events.jsonl")
}

func (s *Store) loadFromDisk() error {
	p := s.registryPath()
	info, err := os.Lstat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to open symlinked state file %s", p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var snap persistedRegistry
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("corrupt state registry %s: %w", p, err)
	}
	if snap.Instances != nil {
		s.instances = snap.Instances
	}
	if snap.Sets != nil {
		s.sets = snap.Sets
	}
	return nil
}

func (s *Store) flushRegistryLocked() error {
	snap := persistedRegistry{
		SchemaVersion: 1,
		Instances:     s.instances,
		Sets:          s.sets,
	}
	payload, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return atomicWriteRootFile(s.registryPath(), payload, 0o600)
}

func (s *Store) seedDefaultSetsIfNeeded() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sets) > 0 {
		return nil
	}
	now := time.Now().UTC()
	defaults := []PluginSet{
		{
			ID:          "set_lscache_speed",
			Name:        "Speed & LSCache Essentials",
			Description: "Bộ tối ưu tốc độ chuẩn Hosting: LiteSpeed Cache + bảo mật cơ bản.",
			BuiltIn:     true,
			Plugins:     []string{"litespeed-cache"},
			CreatedAt:   now,
		},
		{
			ID:          "set_woocommerce_starter",
			Name:        "WooCommerce Starter",
			Description: "Bộ khởi tạo cửa hàng Thương mại điện tử: WooCommerce + LiteSpeed Cache.",
			BuiltIn:     true,
			Plugins:     []string{"woocommerce", "litespeed-cache"},
			Themes:      []string{"storefront"},
			ActiveTheme: "storefront",
			CreatedAt:   now,
		},
		{
			ID:          "set_blog_seo",
			Name:        "Blog & SEO Standard",
			Description: "Bộ tối ưu bài viết & SEO: SEO by Rank Math + Classic Editor + LiteSpeed Cache.",
			BuiltIn:     true,
			Plugins:     []string{"seo-by-rank-math", "classic-editor", "litespeed-cache"},
			CreatedAt:   now,
		},
	}
	for _, item := range defaults {
		s.sets[item.ID] = item
	}
	return s.flushRegistryLocked()
}

// NewInstanceID generates a collision-resistant identifier (e.g., "wp_9f8a7b6c5d4e3f21").
func NewInstanceID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "wp_" + hex.EncodeToString(b[:]), nil
}

// UpsertInstance inserts or updates a WordPress instance atomically.
func (s *Store) UpsertInstance(inst InstanceRecord) (InstanceRecord, error) {
	saved, err := s.UpsertInstancesBatch([]InstanceRecord{inst})
	if err != nil {
		return InstanceRecord{}, err
	}
	return saved[0], nil
}

// UpsertInstancesBatch validates and persists multiple WordPress instances in a single atomic disk flush.
func (s *Store) UpsertInstancesBatch(records []InstanceRecord) ([]InstanceRecord, error) {
	if len(records) == 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	prepared := make([]InstanceRecord, 0, len(records))
	batchRoots := make(map[string]string, len(records))

	for _, inst := range records {
		if err := config.ValidateIdentifier(inst.Owner); err != nil {
			return nil, fmt.Errorf("invalid owner: %w", err)
		}
		if inst.DocRoot == "" {
			return nil, errors.New("doc_root is required")
		}
		cleanDocRoot := filepath.Clean(inst.DocRoot)
		inst.DocRoot = cleanDocRoot

		if inst.CoreShieldMode == "" {
			inst.CoreShieldMode = config.ShieldModeAutoHeal
		}
		if inst.SecurityTotal <= 0 {
			inst.SecurityTotal = 12
		}
		if inst.EnvironmentTag == "" {
			inst.EnvironmentTag = "production"
		}

		if inst.ID == "" {
			id, err := NewInstanceID()
			if err != nil {
				return nil, err
			}
			inst.ID = id
			inst.CreatedAt = now
		} else if err := config.ValidateInstanceID(inst.ID); err != nil {
			return nil, err
		} else if existing, ok := s.instances[inst.ID]; ok {
			inst.CreatedAt = existing.CreatedAt
		} else if inst.CreatedAt.IsZero() {
			inst.CreatedAt = now
		}

		for existingID, existing := range s.instances {
			if existingID != inst.ID && existing.DocRoot == cleanDocRoot {
				return nil, ErrDuplicateDocRoot
			}
		}
		if prevID, dupInBatch := batchRoots[cleanDocRoot]; dupInBatch && prevID != inst.ID {
			return nil, ErrDuplicateDocRoot
		}
		batchRoots[cleanDocRoot] = inst.ID

		inst.UpdatedAt = now
		prepared = append(prepared, inst)
	}

	for _, inst := range prepared {
		s.instances[inst.ID] = inst
	}
	if err := s.flushRegistryLocked(); err != nil {
		return nil, err
	}
	return prepared, nil
}

// GetInstance returns an instance by ID (for internal/Admin callers).
func (s *Store) GetInstance(id string) (InstanceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst, ok := s.instances[id]
	if !ok {
		return InstanceRecord{}, ErrNotFound
	}
	return inst, nil
}

// GetInstanceForOwner enforces strict tenant isolation: returns ErrNotFound if ID belongs to another user.
func (s *Store) GetInstanceForOwner(id, owner string) (InstanceRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst, ok := s.instances[id]
	if !ok || inst.Owner != owner || inst.Detached {
		return InstanceRecord{}, ErrNotFound
	}
	return inst, nil
}

// ListInstancesByOwner returns all active (non-detached) instances owned by username, sorted by domain + subpath.
func (s *Store) ListInstancesByOwner(owner string) []InstanceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []InstanceRecord
	for _, inst := range s.instances {
		if inst.Owner == owner && !inst.Detached {
			out = append(out, inst)
		}
	}
	sortInstances(out)
	return out
}

// ListAllInstances returns all instances across the server for Admin overview.
func (s *Store) ListAllInstances(includeDetached bool) []InstanceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]InstanceRecord, 0, len(s.instances))
	for _, inst := range s.instances {
		if !includeDetached && inst.Detached {
			continue
		}
		out = append(out, inst)
	}
	sortInstances(out)
	return out
}

// DeleteInstance permanently removes an instance record from the registry.
func (s *Store) DeleteInstance(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.instances[id]; !ok {
		return ErrNotFound
	}
	delete(s.instances, id)
	return s.flushRegistryLocked()
}

// DeleteInstancesByOwner removes all instance records belonging to a destroyed DirectAdmin user.
func (s *Store) DeleteInstancesByOwner(owner string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, inst := range s.instances {
		if inst.Owner == owner {
			delete(s.instances, id)
			removed++
		}
	}
	if removed == 0 {
		return 0, nil
	}
	return removed, s.flushRegistryLocked()
}

// ListSetsForOwner returns global built-in sets plus custom sets created by owner.
func (s *Store) ListSetsForOwner(owner string) []PluginSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []PluginSet
	for _, ps := range s.sets {
		if ps.Owner == "" || ps.Owner == owner {
			out = append(out, ps)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BuiltIn != out[j].BuiltIn {
			return out[i].BuiltIn
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// GetSetForOwner returns a global or owner-created PluginSet by ID.
func (s *Store) GetSetForOwner(id, owner string) (PluginSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps, ok := s.sets[strings.TrimSpace(id)]
	if !ok {
		return PluginSet{}, ErrNotFound
	}
	if ps.Owner != "" && ps.Owner != owner {
		return PluginSet{}, ErrNotFound
	}
	return ps, nil
}

// UpsertSet creates or updates a custom user PluginSet (or global set when isAdmin is true).
func (s *Store) UpsertSet(ps PluginSet, callerOwner string, isAdmin bool) (PluginSet, error) {
	ps.Name = strings.TrimSpace(ps.Name)
	ps.Description = strings.TrimSpace(ps.Description)
	if ps.Name == "" || len(ps.Name) > 80 {
		return PluginSet{}, errors.New("set name must be 1..80 characters")
	}

	cleanSlugs := func(items []string) ([]string, error) {
		seen := make(map[string]struct{}, len(items))
		var out []string
		for _, raw := range items {
			slug := strings.ToLower(strings.TrimSpace(raw))
			if slug == "" {
				continue
			}
			if err := config.ValidateIdentifier(slug); err != nil {
				return nil, fmt.Errorf("invalid plugin/theme slug %q: %w", slug, err)
			}
			if _, dup := seen[slug]; !dup {
				seen[slug] = struct{}{}
				out = append(out, slug)
			}
		}
		return out, nil
	}

	var err error
	if ps.Plugins, err = cleanSlugs(ps.Plugins); err != nil {
		return PluginSet{}, err
	}
	if ps.Themes, err = cleanSlugs(ps.Themes); err != nil {
		return PluginSet{}, err
	}
	ps.ActiveTheme = strings.ToLower(strings.TrimSpace(ps.ActiveTheme))
	if ps.ActiveTheme != "" {
		if err := config.ValidateIdentifier(ps.ActiveTheme); err != nil {
			return PluginSet{}, fmt.Errorf("invalid active_theme %q: %w", ps.ActiveTheme, err)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	id := strings.TrimSpace(ps.ID)
	if id == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		id = "set_" + hex.EncodeToString(b[:])
		ps.ID = id
		ps.CreatedAt = time.Now().UTC()
	} else {
		if err := config.ValidateIdentifier(id); err != nil {
			return PluginSet{}, fmt.Errorf("invalid set ID: %w", err)
		}
		if existing, exists := s.sets[id]; exists {
			if existing.BuiltIn && !isAdmin {
				return PluginSet{}, errors.New("built-in system sets cannot be modified by end users")
			}
			if !isAdmin && existing.Owner != callerOwner {
				return PluginSet{}, ErrNotFound
			}
			ps.CreatedAt = existing.CreatedAt
			ps.BuiltIn = existing.BuiltIn
		} else {
			ps.CreatedAt = time.Now().UTC()
		}
	}

	if isAdmin {
		ps.Owner = strings.TrimSpace(ps.Owner)
	} else {
		ps.Owner = callerOwner
		ps.BuiltIn = false
	}

	s.sets[ps.ID] = ps
	if err := s.flushRegistryLocked(); err != nil {
		return PluginSet{}, err
	}
	return ps, nil
}

// DeleteSet deletes a custom PluginSet while protecting built-in presets and enforcing tenant ownership.
func (s *Store) DeleteSet(id, callerOwner string, isAdmin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.sets[strings.TrimSpace(id)]
	if !exists {
		return ErrNotFound
	}
	if existing.BuiltIn {
		return errors.New("built-in system sets cannot be deleted")
	}
	if !isAdmin && existing.Owner != callerOwner {
		return ErrNotFound
	}
	delete(s.sets, strings.TrimSpace(id))
	return s.flushRegistryLocked()
}

// RecordSecurityEvent appends an audit event in memory and to security_events.jsonl.
func (s *Store) RecordSecurityEvent(ev SecurityAuditEvent) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.ID == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		ev.ID = "sec_" + hex.EncodeToString(b[:])
	}

	s.mu.Lock()
	s.securityEvents = append(s.securityEvents, ev)
	if len(s.securityEvents) > DefaultMaxSecurityEvents {
		s.securityEvents = append([]SecurityAuditEvent(nil), s.securityEvents[len(s.securityEvents)-DefaultMaxSecurityEvents:]...)
	}
	p := s.securityEventsPath()
	s.mu.Unlock()

	if line, err := json.Marshal(ev); err == nil {
		line = append(line, '\n')
		f, openErr := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr == nil {
			_, _ = f.Write(line)
			_ = f.Close()
		}
	}
}

// RecentSecurityEvents returns up to limit most recent security events (newest first).
func (s *Store) RecentSecurityEvents(limit int) []SecurityAuditEvent {
	if limit <= 0 || limit > DefaultMaxSecurityEvents {
		limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.securityEvents)
	if n == 0 {
		return nil
	}
	if limit > n {
		limit = n
	}
	out := make([]SecurityAuditEvent, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, s.securityEvents[i])
	}
	return out
}

func sortInstances(list []InstanceRecord) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Domain != list[j].Domain {
			return list[i].Domain < list[j].Domain
		}
		return list[i].SubPath < list[j].SubPath
	})
}

func atomicWriteRootFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlink %s", path)
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
