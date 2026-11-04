package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	JobStatusQueued     = "queued"
	JobStatusRunning    = "running"
	JobStatusSucceeded  = "succeeded"
	JobStatusFailed     = "failed"
	JobStatusRolledBack = "rolled_back"

	DefaultWorkerCount    = 4
	DefaultMaxJobsHistory = 200
)

// JobRecord tracks an asynchronous background task (install, clone, sync, snapshot, bulk_update) for UI polling.
type JobRecord struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Owner       string    `json:"owner"`
	InstanceID  string    `json:"instance_id,omitempty"`
	Status      string    `json:"status"`
	Progress    int       `json:"progress"` // 0..100
	Step        string    `json:"step"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// ProgressReporter updates a running job's progress percentage and human-readable step label.
type ProgressReporter func(percent int, step string)

// JobFunc is executed asynchronously by the bounded worker pool.
type JobFunc func(ctx context.Context, report ProgressReporter) error

type queuedTask struct {
	id string
	fn JobFunc
}

// JobManager coordinates bounded background execution and per-instance concurrency locks.
type JobManager struct {
	stateDir   string
	maxHistory int
	workers    int

	mu            sync.RWMutex
	jobs          map[string]JobRecord
	instanceLocks map[string]string // instanceID -> active jobID
	queue         chan queuedTask
	wg            sync.WaitGroup
}

func NewJobManager(stateDir string, workers int) (*JobManager, error) {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	if workers <= 0 {
		workers = DefaultWorkerCount
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	jm := &JobManager{
		stateDir:      stateDir,
		maxHistory:    DefaultMaxJobsHistory,
		workers:       workers,
		jobs:          make(map[string]JobRecord),
		instanceLocks: make(map[string]string),
		queue:         make(chan queuedTask, 128),
	}
	_ = jm.loadJobsFromDisk()
	return jm, nil
}

func (jm *JobManager) jobsPath() string {
	return filepath.Join(jm.stateDir, "jobs.json")
}

func (jm *JobManager) loadJobsFromDisk() error {
	raw, err := os.ReadFile(jm.jobsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var list []JobRecord
	if err := json.Unmarshal(raw, &list); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, j := range list {
		if j.Status == JobStatusQueued || j.Status == JobStatusRunning {
			j.Status = JobStatusFailed
			j.Error = "interrupted by daemon restart"
			j.CompletedAt = now
		}
		jm.jobs[j.ID] = j
	}
	return nil
}

func (jm *JobManager) persistLocked() {
	list := make([]JobRecord, 0, len(jm.jobs))
	for _, j := range jm.jobs {
		list = append(list, j)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	if len(list) > jm.maxHistory {
		for _, stale := range list[jm.maxHistory:] {
			if stale.Status != JobStatusQueued && stale.Status != JobStatusRunning {
				delete(jm.jobs, stale.ID)
			}
		}
		list = list[:jm.maxHistory]
	}
	if data, err := json.MarshalIndent(list, "", "  "); err == nil {
		data = append(data, '\n')
		_ = atomicWriteRootFile(jm.jobsPath(), data, 0o600)
	}
}

// Start launches the background worker goroutines until ctx is cancelled.
func (jm *JobManager) Start(ctx context.Context) {
	for i := 0; i < jm.workers; i++ {
		jm.wg.Add(1)
		go func() {
			defer jm.wg.Done()
			jm.workerLoop(ctx)
		}()
	}
}

// Wait waits for all active workers to finish cleanly.
func (jm *JobManager) Wait() {
	jm.wg.Wait()
}

// Enqueue schedules a new background job, acquiring an exclusive per-instance lock if instanceID != "".
func (jm *JobManager) Enqueue(jobType, owner, instanceID, initialStep string, fn JobFunc) (JobRecord, error) {
	if fn == nil {
		return JobRecord{}, errors.New("job function is nil")
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return JobRecord{}, err
	}
	jobID := "job_" + hex.EncodeToString(b[:])
	now := time.Now().UTC()

	rec := JobRecord{
		ID:         jobID,
		Type:       jobType,
		Owner:      owner,
		InstanceID: instanceID,
		Status:     JobStatusQueued,
		Progress:   0,
		Step:       initialStep,
		CreatedAt:  now,
	}

	jm.mu.Lock()
	if instanceID != "" {
		if activeID, busy := jm.instanceLocks[instanceID]; busy && activeID != "" {
			jm.mu.Unlock()
			return JobRecord{}, ErrInstanceBusy
		}
		jm.instanceLocks[instanceID] = jobID
	}
	jm.jobs[jobID] = rec
	jm.persistLocked()
	jm.mu.Unlock()

	select {
	case jm.queue <- queuedTask{id: jobID, fn: fn}:
		return rec, nil
	default:
		jm.mu.Lock()
		if instanceID != "" && jm.instanceLocks[instanceID] == jobID {
			delete(jm.instanceLocks, instanceID)
		}
		delete(jm.jobs, jobID)
		jm.persistLocked()
		jm.mu.Unlock()
		return JobRecord{}, errors.New("job queue is full; please try again shortly")
	}
}

func (jm *JobManager) workerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-jm.queue:
			jm.runTask(ctx, task)
		}
	}
}

func (jm *JobManager) runTask(ctx context.Context, task queuedTask) {
	jm.mu.Lock()
	rec, ok := jm.jobs[task.id]
	if !ok {
		jm.mu.Unlock()
		return
	}
	rec.Status = JobStatusRunning
	rec.StartedAt = time.Now().UTC()
	jm.jobs[task.id] = rec
	jm.mu.Unlock()

	report := func(percent int, step string) {
		if percent < 0 {
			percent = 0
		} else if percent > 100 {
			percent = 100
		}
		jm.mu.Lock()
		if cur, exists := jm.jobs[task.id]; exists {
			cur.Progress = percent
			if step != "" {
				cur.Step = step
			}
			jm.jobs[task.id] = cur
		}
		jm.mu.Unlock()
	}

	err := task.fn(ctx, report)

	jm.mu.Lock()
	defer jm.mu.Unlock()
	cur, exists := jm.jobs[task.id]
	if !exists {
		return
	}
	if cur.InstanceID != "" && jm.instanceLocks[cur.InstanceID] == task.id {
		delete(jm.instanceLocks, cur.InstanceID)
	}
	cur.CompletedAt = time.Now().UTC()
	if err != nil {
		if cur.Status != JobStatusRolledBack {
			cur.Status = JobStatusFailed
		}
		cur.Error = err.Error()
	} else {
		cur.Status = JobStatusSucceeded
		cur.Progress = 100
	}
	jm.jobs[task.id] = cur
	jm.persistLocked()
}

// GetJobForOwner returns a job only if it belongs to owner (or if isAdmin is true).
func (jm *JobManager) GetJobForOwner(jobID, owner string, isAdmin bool) (JobRecord, error) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()
	rec, ok := jm.jobs[jobID]
	if !ok {
		return JobRecord{}, ErrNotFound
	}
	if !isAdmin && rec.Owner != owner {
		return JobRecord{}, ErrNotFound
	}
	return rec, nil
}

// ListJobs returns recent jobs filtered by owner (or all owners if isAdmin && owner == "").
func (jm *JobManager) ListJobs(owner string, isAdmin bool, limit int) []JobRecord {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	var out []JobRecord
	for _, rec := range jm.jobs {
		if !isAdmin && rec.Owner != owner {
			continue
		}
		if isAdmin && owner != "" && rec.Owner != owner {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
