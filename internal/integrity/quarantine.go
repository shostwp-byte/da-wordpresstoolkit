package integrity

import (
	"crypto/rand"
	"crypto/sha256"
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
	"github.com/shostwp-byte/da-wptoolkits/internal/dausers"
	"github.com/shostwp-byte/da-wptoolkits/internal/fsguard"
	"github.com/shostwp-byte/da-wptoolkits/internal/store"
)

const (
	DefaultQuarantineDir     = "/var/lib/da-wptoolkit/quarantine"
	ReasonModifiedCoreFile   = "modified_core_file"
	ReasonUnknownExecutable  = "unknown_core_executable"
	ActionAutoHealed         = "auto_healed"
	ActionQuarantinedRemoved = "quarantined"
)

// QuarantineItem represents an isolated tampered Core file or unknown backdoor inside the Root Quarantine Vault.
type QuarantineItem struct {
	ID             string     `json:"id"`
	InstanceID     string     `json:"instance_id"`
	Owner          string     `json:"owner"`
	Domain         string     `json:"domain"`
	RelPath        string     `json:"rel_path"`
	Reason         string     `json:"reason"`       // modified_core_file | unknown_core_executable
	ActionTaken    string     `json:"action_taken"` // auto_healed | quarantined
	CleanSHA256    string     `json:"clean_sha256,omitempty"`
	TamperedSHA256 string     `json:"tampered_sha256"`
	SizeBytes      int64      `json:"size_bytes"`
	DiffPreview    string     `json:"diff_preview,omitempty"`
	VaultPath      string     `json:"-"`
	Restored       bool       `json:"restored"`
	RestoredAt     *time.Time `json:"restored_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type persistedQuarantineState struct {
	Items     map[string]QuarantineItem `json:"items"`
	Whitelist map[string][]string       `json:"whitelist"` // instanceID -> sorted POSIX relPaths
}

// QuarantineVault manages root-protected malware storage (0700/0600), read-only Diff previews, and Core Whitelists.
type QuarantineVault struct {
	StateDir     string
	VaultBaseDir string

	mu        sync.RWMutex
	items     map[string]QuarantineItem
	whitelist map[string]map[string]bool
}

// NewQuarantineVault initializes or loads the Root Quarantine Vault and per-instance Whitelist index.
func NewQuarantineVault(stateDir, vaultBaseDir string) (*QuarantineVault, error) {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = store.DefaultStateDir
	}
	if strings.TrimSpace(vaultBaseDir) == "" {
		vaultBaseDir = DefaultQuarantineDir
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(vaultBaseDir, 0o700); err != nil {
		return nil, err
	}

	v := &QuarantineVault{
		StateDir:     stateDir,
		VaultBaseDir: vaultBaseDir,
		items:        make(map[string]QuarantineItem),
		whitelist:    make(map[string]map[string]bool),
	}
	v.loadFromDisk()
	return v, nil
}

func (v *QuarantineVault) indexPath() string {
	return filepath.Join(v.StateDir, "quarantine.json")
}

func (v *QuarantineVault) loadFromDisk() {
	raw, err := os.ReadFile(v.indexPath())
	if err != nil {
		return
	}
	var snap persistedQuarantineState
	if json.Unmarshal(raw, &snap) != nil {
		return
	}
	for id, it := range snap.Items {
		it.VaultPath = v.vaultBlobPath(it.Owner, it.InstanceID, it.ID)
		v.items[id] = it
	}
	for instID, paths := range snap.Whitelist {
		m := make(map[string]bool, len(paths))
		for _, p := range paths {
			if norm, err := normalizeCoreRelPath(p); err == nil {
				m[norm] = true
			}
		}
		v.whitelist[instID] = m
	}
}

func (v *QuarantineVault) saveLocked() error {
	wlOut := make(map[string][]string, len(v.whitelist))
	for instID, m := range v.whitelist {
		if len(m) == 0 {
			continue
		}
		list := make([]string, 0, len(m))
		for p := range m {
			list = append(list, p)
		}
		sort.Strings(list)
		wlOut[instID] = list
	}
	snap := persistedQuarantineState{
		Items:     v.items,
		Whitelist: wlOut,
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := v.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.indexPath())
}

func (v *QuarantineVault) vaultBlobPath(owner, instanceID, qID string) string {
	return filepath.Join(v.VaultBaseDir, owner, instanceID, qID+".bin")
}

// StoreTamperedFile archives tamperedBytes into the Root-Only Vault (0600) and computes a sanitized Diff preview.
func (v *QuarantineVault) StoreTamperedFile(
	inst store.InstanceRecord,
	relPath string,
	reason string,
	actionTaken string,
	cleanBytes []byte,
	tamperedBytes []byte,
) (QuarantineItem, error) {
	normRel, err := normalizeCoreRelPath(relPath)
	if err != nil {
		return QuarantineItem{}, err
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return QuarantineItem{}, err
	}
	qID := "qrt_" + hex.EncodeToString(rnd[:])

	blobPath := v.vaultBlobPath(inst.Owner, inst.ID, qID)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o700); err != nil {
		return QuarantineItem{}, err
	}
	if err := os.WriteFile(blobPath, tamperedBytes, 0o600); err != nil {
		return QuarantineItem{}, err
	}

	tamperedSum := sha256.Sum256(tamperedBytes)
	cleanHex := ""
	if cleanBytes != nil {
		cleanSum := sha256.Sum256(cleanBytes)
		cleanHex = hex.EncodeToString(cleanSum[:])
	}

	item := QuarantineItem{
		ID:             qID,
		InstanceID:     inst.ID,
		Owner:          inst.Owner,
		Domain:         inst.Domain + inst.SubPath,
		RelPath:        normRel,
		Reason:         reason,
		ActionTaken:    actionTaken,
		CleanSHA256:    cleanHex,
		TamperedSHA256: hex.EncodeToString(tamperedSum[:]),
		SizeBytes:      int64(len(tamperedBytes)),
		DiffPreview:    ComputeSafeLineDiff(normRel, cleanBytes, tamperedBytes, defaultMaxDiffBytes),
		VaultPath:      blobPath,
		CreatedAt:      time.Now().UTC(),
	}

	v.mu.Lock()
	v.items[qID] = item
	err = v.saveLocked()
	v.mu.Unlock()
	return item, err
}

// List returns quarantine items filtered by owner (empty owner allowed only when isAdmin == true) and optional instanceID.
func (v *QuarantineVault) List(owner, instanceID string, isAdmin bool, includeDiff bool) []QuarantineItem {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var out []QuarantineItem
	for _, it := range v.items {
		if !isAdmin && it.Owner != owner {
			continue
		}
		if isAdmin && owner != "" && it.Owner != owner {
			continue
		}
		if instanceID != "" && it.InstanceID != instanceID {
			continue
		}
		cloned := it
		if !includeDiff {
			cloned.DiffPreview = ""
		}
		out = append(out, cloned)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

// GetItem returns a single QuarantineItem including its full sanitized DiffPreview, enforcing tenant isolation.
func (v *QuarantineVault) GetItem(quarantineID, owner string, isAdmin bool) (QuarantineItem, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	it, ok := v.items[strings.TrimSpace(quarantineID)]
	if !ok {
		return QuarantineItem{}, store.ErrNotFound
	}
	if !isAdmin && it.Owner != owner {
		return QuarantineItem{}, store.ErrNotFound
	}
	return it, nil
}

// DeleteItem permanently deletes a quarantined payload from disk and index.
func (v *QuarantineVault) DeleteItem(quarantineID, owner string, isAdmin bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	id := strings.TrimSpace(quarantineID)
	it, ok := v.items[id]
	if !ok || (!isAdmin && it.Owner != owner) {
		return store.ErrNotFound
	}
	_ = os.Remove(v.vaultBlobPath(it.Owner, it.InstanceID, it.ID))
	delete(v.items, id)
	return v.saveLocked()
}

// RestoreItem writes a quarantined file back to the customer's WordPress DocRoot via fsguard
// and optionally adds its relative path to the instance's Core Whitelist.
func (v *QuarantineVault) RestoreItem(
	acct dausers.Account,
	inst store.InstanceRecord,
	quarantineID string,
	addWhitelist bool,
	isAdmin bool,
) (QuarantineItem, error) {
	it, err := v.GetItem(quarantineID, acct.Username, isAdmin)
	if err != nil {
		return QuarantineItem{}, err
	}
	if it.InstanceID != inst.ID {
		return QuarantineItem{}, errors.New("quarantine item does not belong to target instance")
	}

	raw, err := os.ReadFile(v.vaultBlobPath(it.Owner, it.InstanceID, it.ID))
	if err != nil {
		return QuarantineItem{}, fmt.Errorf("read quarantined payload: %w", err)
	}

	domainsRoot := filepath.Join(filepath.Clean(acct.HomeDir), "domains")
	guard, err := fsguard.New(domainsRoot, nil)
	if err != nil {
		return QuarantineItem{}, err
	}
	verifiedDocRoot, err := guard.VerifyExistingPath(inst.DocRoot)
	if err != nil {
		return QuarantineItem{}, err
	}

	if addWhitelist {
		if err := v.AddWhitelist(inst.ID, it.RelPath); err != nil {
			return QuarantineItem{}, err
		}
	}

	destPath := filepath.Join(verifiedDocRoot, filepath.FromSlash(it.RelPath))
	if err := writeGuardedCoreFile(guard, acct, destPath, raw, 0o644); err != nil {
		return QuarantineItem{}, err
	}

	now := time.Now().UTC()
	v.mu.Lock()
	if cur, ok := v.items[it.ID]; ok {
		cur.Restored = true
		cur.RestoredAt = &now
		v.items[it.ID] = cur
		it = cur
		_ = v.saveLocked()
	}
	v.mu.Unlock()
	return it, nil
}

// IsWhitelisted reports whether relPath is exempted from Core Auto-Heal/Quarantine on instanceID.
func (v *QuarantineVault) IsWhitelisted(instanceID, relPath string) bool {
	norm, err := normalizeCoreRelPath(relPath)
	if err != nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.whitelist[instanceID][norm]
}

// ListWhitelist returns sorted relative paths exempted on instanceID.
func (v *QuarantineVault) ListWhitelist(instanceID string) []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := v.whitelist[instanceID]
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// AddWhitelist adds a normalized relative path to instanceID's Core exception list.
func (v *QuarantineVault) AddWhitelist(instanceID, relPath string) error {
	if err := config.ValidateInstanceID(instanceID); err != nil {
		return err
	}
	norm, err := normalizeCoreRelPath(relPath)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.whitelist[instanceID] == nil {
		v.whitelist[instanceID] = make(map[string]bool)
	}
	v.whitelist[instanceID][norm] = true
	return v.saveLocked()
}

// RemoveWhitelist removes a relative path from instanceID's Core exception list.
func (v *QuarantineVault) RemoveWhitelist(instanceID, relPath string) error {
	norm, err := normalizeCoreRelPath(relPath)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.whitelist[instanceID] != nil {
		delete(v.whitelist[instanceID], norm)
	}
	return v.saveLocked()
}

// PurgeInstance removes all quarantine files and whitelist entries for an uninstalled instance.
func (v *QuarantineVault) PurgeInstance(owner, instanceID string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, it := range v.items {
		if it.InstanceID == instanceID {
			delete(v.items, id)
		}
	}
	delete(v.whitelist, instanceID)
	if owner != "" && instanceID != "" {
		_ = os.RemoveAll(filepath.Join(v.VaultBaseDir, owner, instanceID))
	}
	return v.saveLocked()
}

// PurgeOwner removes all quarantine artifacts belonging to a destroyed DirectAdmin user (user_destroy_post.sh).
func (v *QuarantineVault) PurgeOwner(owner string) error {
	if err := config.ValidateIdentifier(owner); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, it := range v.items {
		if it.Owner == owner {
			delete(v.items, id)
		}
	}
	_ = os.RemoveAll(filepath.Join(v.VaultBaseDir, owner))
	return v.saveLocked()
}
