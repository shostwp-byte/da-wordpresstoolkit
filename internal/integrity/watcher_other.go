//go:build !linux

package integrity

import (
	"context"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type fileSig struct {
	size      int64
	mtime     int64 // set only when file exceeds 2MB and digest is skipped
	hasDigest bool
	digest    uint64
}

type polledInstance struct {
	docRoot string
	files   map[string]fileSig
}

type coreWatcher struct {
	MaxWatches   int
	PollInterval time.Duration

	mu        sync.Mutex
	wg        sync.WaitGroup
	watched   map[string]*polledInstance
	maxBudget int
}

func newCoreWatcher(maxWatches int, pollInterval time.Duration) *coreWatcher {
	if maxWatches <= 0 {
		maxWatches = 32768
	}
	if pollInterval <= 0 {
		pollInterval = 120 * time.Millisecond
	}
	return &coreWatcher{
		MaxWatches:   maxWatches,
		PollInterval: pollInterval,
		watched:      make(map[string]*polledInstance),
		maxBudget:    maxWatches,
	}
}

func (w *coreWatcher) Start(ctx context.Context, onEvent func(WatchEvent) WatchOutcome, _ func()) error {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(w.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				w.pollOnce(onEvent)
			}
		}
	}()
	return nil
}

func (w *coreWatcher) Wait() {
	w.wg.Wait()
}

func (w *coreWatcher) SyncInstance(instanceID, verifiedDocRoot string) error {
	snap := snapshotCoreFiles(verifiedDocRoot)
	w.mu.Lock()
	w.watched[instanceID] = &polledInstance{
		docRoot: verifiedDocRoot,
		files:   snap,
	}
	w.mu.Unlock()
	return nil
}

func (w *coreWatcher) UnwatchInstance(instanceID string) {
	w.mu.Lock()
	delete(w.watched, instanceID)
	w.mu.Unlock()
}

func (w *coreWatcher) Stats() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.watched), w.maxBudget
}

func (w *coreWatcher) pollOnce(onEvent func(WatchEvent) WatchOutcome) {
	if onEvent == nil {
		return
	}
	type target struct {
		id      string
		docRoot string
		prev    map[string]fileSig
	}

	w.mu.Lock()
	targets := make([]target, 0, len(w.watched))
	for id, pi := range w.watched {
		cp := make(map[string]fileSig, len(pi.files))
		for k, v := range pi.files {
			cp[k] = v
		}
		targets = append(targets, target{id: id, docRoot: pi.docRoot, prev: cp})
	}
	w.mu.Unlock()

	for _, t := range targets {
		cur := snapshotCoreFiles(t.docRoot)
		var changedPaths []string
		for abs, sig := range cur {
			if prevSig, existed := t.prev[abs]; !existed || prevSig != sig {
				changedPaths = append(changedPaths, abs)
			}
		}
		for abs := range t.prev {
			if _, stillThere := cur[abs]; !stillThere {
				changedPaths = append(changedPaths, abs)
			}
		}

		if len(changedPaths) > 0 {
			nextBaseline := t.prev
			for _, abs := range changedPaths {
				out := onEvent(WatchEvent{
					InstanceID: t.id,
					AbsPath:    abs,
					IsDir:      false,
				})
				if !out.Handled {
					// Transient file lock (e.g. mid-write handle on Windows): leave old baseline so next tick retries!
					continue
				}
				switch {
				case out.RemovedFile:
					delete(nextBaseline, abs)
				case out.RestoredBytes != nil:
					nextBaseline[abs] = sigFromBytes(out.RestoredBytes)
				default:
					if snapSig, ok := cur[abs]; ok {
						nextBaseline[abs] = snapSig
					} else {
						delete(nextBaseline, abs)
					}
				}
			}
			w.mu.Lock()
			if pi, ok := w.watched[t.id]; ok {
				pi.files = nextBaseline
			}
			w.mu.Unlock()
		}
	}
}

func sigFromBytes(raw []byte) fileSig {
	h := fnv.New64a()
	_, _ = h.Write(raw)
	return fileSig{
		size:      int64(len(raw)),
		hasDigest: true,
		digest:    h.Sum64(),
	}
}

func quickFileSig(abs string, st os.FileInfo) (fileSig, bool) {
	if st.Size() <= 2*1024*1024 {
		f, err := os.Open(abs)
		if err != nil {
			return fileSig{}, false
		}
		h := fnv.New64a()
		n, cErr := io.Copy(h, f)
		_ = f.Close()
		if cErr != nil {
			return fileSig{}, false
		}
		return fileSig{
			size:      n,
			hasDigest: true,
			digest:    h.Sum64(),
		}, true
	}
	return fileSig{
		size:  st.Size(),
		mtime: st.ModTime().UnixNano(),
	}, true
}

func snapshotCoreFiles(docRoot string) map[string]fileSig {
	out := make(map[string]fileSig, 64)
	entries, err := os.ReadDir(docRoot)
	if err != nil {
		return out
	}
	for _, ent := range entries {
		name := ent.Name()
		if name == "wp-content" || name == "wp-config.php" || name == ".htaccess" || strings.HasPrefix(name, ".da-wptk-") {
			continue
		}
		if ent.Type()&os.ModeSymlink != 0 {
			continue
		}
		abs := filepath.Join(docRoot, name)
		if !ent.IsDir() {
			if info, iErr := ent.Info(); iErr == nil && info.Mode().IsRegular() {
				if sig, ok := quickFileSig(abs, info); ok {
					out[abs] = sig
				}
			}
			continue
		}
		if name == "wp-admin" || name == "wp-includes" {
			_ = filepath.WalkDir(abs, func(cur string, d os.DirEntry, wErr error) error {
				if wErr != nil {
					return nil
				}
				if d.Type()&os.ModeSymlink != 0 {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if d.IsDir() || strings.HasPrefix(d.Name(), ".da-wptk-") {
					return nil
				}
				if info, iErr := d.Info(); iErr == nil && info.Mode().IsRegular() {
					if sig, ok := quickFileSig(cur, info); ok {
						out[cur] = sig
					}
				}
				return nil
			})
		}
	}
	return out
}
