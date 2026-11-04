//go:build linux

package integrity

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultMaxWatchCap = 32768
	inotifyWatchMask   = syscall.IN_CLOSE_WRITE |
		syscall.IN_MOVED_TO |
		syscall.IN_MOVED_FROM |
		syscall.IN_CREATE |
		syscall.IN_DELETE |
		syscall.IN_ATTRIB
)

type watchBinding struct {
	instanceID string
	dirPath    string
	recursive  bool
}

type coreWatcher struct {
	MaxWatches   int
	PollInterval time.Duration // unused on Linux kernel inotify, kept for API parity

	mu         sync.Mutex
	file       *os.File
	fd         int
	wdToBind   map[int]watchBinding
	instToWDs  map[string][]int
	dirToWD    map[string]int
	maxBudget  int
	onEvent    func(WatchEvent) WatchOutcome
	onOverflow func()
}

func newCoreWatcher(maxWatches int, pollInterval time.Duration) *coreWatcher {
	budget := computeLinuxWatchBudget(maxWatches)
	return &coreWatcher{
		MaxWatches:   maxWatches,
		PollInterval: pollInterval,
		fd:           -1,
		wdToBind:     make(map[int]watchBinding),
		instToWDs:    make(map[string][]int),
		dirToWD:      make(map[string]int),
		maxBudget:    budget,
	}
}

func computeLinuxWatchBudget(requested int) int {
	if requested <= 0 {
		requested = defaultMaxWatchCap
	}
	raw, err := os.ReadFile("/proc/sys/fs/inotify/max_user_watches")
	if err == nil {
		if sysMax, pErr := strconv.Atoi(strings.TrimSpace(string(raw))); pErr == nil && sysMax > 512 {
			half := sysMax / 2
			if half < requested {
				requested = half
			}
		}
	}
	if requested < 256 {
		requested = 256
	}
	return requested
}

func (w *coreWatcher) Start(ctx context.Context, onEvent func(WatchEvent) WatchOutcome, onOverflow func()) error {
	w.mu.Lock()
	if w.file != nil {
		w.mu.Unlock()
		return nil
	}
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	f := os.NewFile(uintptr(fd), "da-wptk-inotify")
	w.fd = fd
	w.file = f
	w.onEvent = onEvent
	w.onOverflow = onOverflow
	w.mu.Unlock()

	go func() {
		<-ctx.Done()
		w.mu.Lock()
		if w.file != nil {
			_ = w.file.Close()
			w.file = nil
			w.fd = -1
		}
		w.mu.Unlock()
	}()

	go w.readLoop(ctx, f)
	return nil
}

func (w *coreWatcher) readLoop(ctx context.Context, f *os.File) {
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			w.parseEvents(buf[:n])
		}
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
}

func (w *coreWatcher) parseEvents(chunk []byte) {
	offset := 0
	for offset+syscall.SizeofInotifyEvent <= len(chunk) {
		wd := int(int32(binary.NativeEndian.Uint32(chunk[offset : offset+4])))
		mask := binary.NativeEndian.Uint32(chunk[offset+4 : offset+8])
		nameLen := int(binary.NativeEndian.Uint32(chunk[offset+12 : offset+16]))
		offset += syscall.SizeofInotifyEvent

		if offset+nameLen > len(chunk) {
			break
		}
		rawName := chunk[offset : offset+nameLen]
		offset += nameLen

		if mask&syscall.IN_Q_OVERFLOW != 0 {
			w.mu.Lock()
			cb := w.onOverflow
			w.mu.Unlock()
			if cb != nil {
				go cb()
			}
			continue
		}

		if mask&syscall.IN_IGNORED != 0 {
			w.mu.Lock()
			if b, ok := w.wdToBind[wd]; ok {
				delete(w.wdToBind, wd)
				delete(w.dirToWD, b.dirPath)
			}
			w.mu.Unlock()
			continue
		}

		nulIdx := bytes.IndexByte(rawName, 0)
		name := ""
		if nulIdx >= 0 {
			name = string(rawName[:nulIdx])
		} else {
			name = string(rawName)
		}
		if name == "" || strings.HasPrefix(name, ".da-wptk-") {
			continue
		}

		w.mu.Lock()
		bind, ok := w.wdToBind[wd]
		cb := w.onEvent
		w.mu.Unlock()
		if !ok {
			continue
		}

		absPath := filepath.Join(bind.dirPath, name)
		isDir := mask&syscall.IN_ISDIR != 0

		// For root DocRoot (non-recursive watch), ignore wp-content, wp-config.php, and .htaccess noise
		if !bind.recursive {
			if name == "wp-content" || name == "wp-config.php" || name == ".htaccess" {
				continue
			}
		}

		// Automatically watch newly created subdirectories inside wp-admin/ or wp-includes/
		if isDir && bind.recursive && (mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0) {
			w.mu.Lock()
			_ = w.addTreeLocked(bind.instanceID, absPath, true)
			w.mu.Unlock()
		}

		if cb != nil {
			_ = cb(WatchEvent{
				InstanceID: bind.instanceID,
				AbsPath:    absPath,
				IsDir:      isDir,
			})
		}
	}
}

func (w *coreWatcher) SyncInstance(instanceID, verifiedDocRoot string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unwatchLocked(instanceID)
	if w.fd < 0 {
		return nil
	}
	if err := w.addWatchLocked(instanceID, verifiedDocRoot, false); err != nil {
		return err
	}
	for _, sub := range []string{"wp-admin", "wp-includes"} {
		p := filepath.Join(verifiedDocRoot, sub)
		if st, err := os.Lstat(p); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			_ = w.addTreeLocked(instanceID, p, true)
		}
	}
	return nil
}

func (w *coreWatcher) addTreeLocked(instanceID, rootDir string, recursive bool) error {
	return filepath.WalkDir(rootDir, func(cur string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		return w.addWatchLocked(instanceID, cur, recursive)
	})
}

func (w *coreWatcher) addWatchLocked(instanceID, dirPath string, recursive bool) error {
	if w.fd < 0 {
		return nil
	}
	if _, exists := w.dirToWD[dirPath]; exists {
		return nil
	}
	if len(w.wdToBind) >= w.maxBudget {
		return errors.New("inotify watch budget cap reached; relying on periodic core audit sweep")
	}
	wd, err := syscall.InotifyAddWatch(w.fd, dirPath, uint32(inotifyWatchMask))
	if err != nil {
		return err
	}
	w.wdToBind[wd] = watchBinding{
		instanceID: instanceID,
		dirPath:    dirPath,
		recursive:  recursive,
	}
	w.dirToWD[dirPath] = wd
	w.instToWDs[instanceID] = append(w.instToWDs[instanceID], wd)
	return nil
}

func (w *coreWatcher) UnwatchInstance(instanceID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.unwatchLocked(instanceID)
}

func (w *coreWatcher) unwatchLocked(instanceID string) {
	wds := w.instToWDs[instanceID]
	for _, wd := range wds {
		if b, ok := w.wdToBind[wd]; ok {
			delete(w.dirToWD, b.dirPath)
			delete(w.wdToBind, wd)
		}
		if w.fd >= 0 {
			_, _ = syscall.InotifyRmWatch(w.fd, uint32(wd))
		}
	}
	delete(w.instToWDs, instanceID)
}

func (w *coreWatcher) Stats() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.wdToBind), w.maxBudget
}
