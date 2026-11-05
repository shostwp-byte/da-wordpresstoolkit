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
	"strings"
	"sync"
	"time"
)

const (
	JobStatusQueued     = "queued"
	JobStatusRunning    = "running"
	JobStatusSucceeded  = "succeeded"
	JobStatusSkipped    = "skipped"
	JobStatusFailed     = "failed"
	JobStatusRolledBack = "rolled_back"

	DefaultWorkerCount    = 4
	DefaultMaxJobsHistory = 200
)

// JobItemResult tracks per-site status inside a multi-instance or sequential queue job.
type JobItemResult struct {
	InstanceID string `json:"instance_id,omitempty"`
	Domain     string `json:"domain"`
	Status     string `json:"status"` // queued | running | succeeded | skipped | rolled_back | failed
	Detail     string `json:"detail,omitempty"`
}

// JobRecord tracks an asynchronous background task (install, clone, sync, snapshot, bulk_update, core_update) for UI polling.
type JobRecord struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Title        string          `json:"title,omitempty"`
	Target       string          `json:"target,omitempty"`
	Owner        string          `json:"owner"`
	InstanceID   string          `json:"instance_id,omitempty"`
	Status       string          `json:"status"`
	Progress     int             `json:"progress"` // 0..100
	Step         string          `json:"step"`
	Summary      string          `json:"summary,omitempty"`
	Error        string          `json:"error,omitempty"`
	TotalItems   int             `json:"total_items,omitempty"`
	DoneItems    int             `json:"done_items,omitempty"`
	SkippedItems int             `json:"skipped_items,omitempty"`
	FailedItems  int             `json:"failed_items,omitempty"`
	Items        []JobItemResult `json:"items,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    time.Time       `json:"started_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at,omitempty"`
	CompletedAt  time.Time       `json:"completed_at,omitempty"`
}

// JobMeta provides structured display metadata when enqueuing a background task.
type JobMeta struct {
	Type        string
	Title       string
	Target      string
	Owner       string
	InstanceID  string
	InitialStep string
	Items       []JobItemResult
}

// ProgressReporter updates a running job's progress percentage and human-readable step label.
type ProgressReporter func(percent int, step string)

// JobFunc is executed asynchronously by the bounded worker pool.
type JobFunc func(ctx context.Context, report ProgressReporter) error

// RichJobFunc receives a JobController for rich item-by-item progress & summary reporting.
type RichJobFunc func(ctx context.Context, ctrl *JobController) error

// JobController lets a running background task safely report progress, summary, and per-item status.
type JobController struct {
	jm *JobManager
	id string
}

// JobID returns the unique identifier of the active background task.
func (jc *JobController) JobID() string {
	if jc == nil {
		return ""
	}
	return jc.id
}

// Report updates overall percentage (0..100) and current step description.
func (jc *JobController) Report(percent int, step string) {
	if jc == nil || jc.jm == nil {
		return
	}
	if percent < 0 {
		percent = 0
	} else if percent > 100 {
		percent = 100
	}
	now := time.Now().UTC()
	jc.jm.mu.Lock()
	if cur, exists := jc.jm.jobs[jc.id]; exists {
		cur.Progress = percent
		if step != "" {
			cur.Step = step
		}
		cur.UpdatedAt = now
		jc.jm.jobs[jc.id] = cur
	}
	jc.jm.mu.Unlock()
}

// SetSummary updates the human-readable outcome summary displayed in the UI drawer/banner.
func (jc *JobController) SetSummary(summary string) {
	if jc == nil || jc.jm == nil {
		return
	}
	now := time.Now().UTC()
	jc.jm.mu.Lock()
	if cur, exists := jc.jm.jobs[jc.id]; exists {
		cur.Summary = strings.TrimSpace(summary)
		cur.UpdatedAt = now
		jc.jm.jobs[jc.id] = cur
	}
	jc.jm.mu.Unlock()
}

// MarkRolledBack marks the job status as rolled_back with an explanatory summary.
func (jc *JobController) MarkRolledBack(summary string) {
	if jc == nil || jc.jm == nil {
		return
	}
	now := time.Now().UTC()
	jc.jm.mu.Lock()
	if cur, exists := jc.jm.jobs[jc.id]; exists {
		cur.Status = JobStatusRolledBack
		if strings.TrimSpace(summary) != "" {
			cur.Summary = strings.TrimSpace(summary)
		}
		cur.UpdatedAt = now
		jc.jm.jobs[jc.id] = cur
	}
	jc.jm.mu.Unlock()
}

// SetItems initializes or replaces the per-item queue snapshot for multi-instance tasks.
func (jc *JobController) SetItems(items []JobItemResult) {
	if jc == nil || jc.jm == nil {
		return
	}
	cloned := make([]JobItemResult, len(items))
	copy(cloned, items)
	now := time.Now().UTC()
	jc.jm.mu.Lock()
	if cur, exists := jc.jm.jobs[jc.id]; exists {
		cur.Items = cloned
		recomputeItemCounters(&cur)
		cur.UpdatedAt = now
		jc.jm.jobs[jc.id] = cur
	}
	jc.jm.mu.Unlock()
}

// UpdateItem updates a single item in the job's queue and recalculates aggregate counters.
func (jc *JobController) UpdateItem(index int, status, detail string) {
	if jc == nil || jc.jm == nil || index < 0 {
		return
	}
	now := time.Now().UTC()
	jc.jm.mu.Lock()
	if cur, exists := jc.jm.jobs[jc.id]; exists && index < len(cur.Items) {
		cloned := make([]JobItemResult, len(cur.Items))
		copy(cloned, cur.Items)
		if status != "" {
			cloned[index].Status = status
		}
		if detail != "" {
			cloned[index].Detail = detail
		}
		cur.Items = cloned
		recomputeItemCounters(&cur)
		cur.UpdatedAt = now
		jc.jm.jobs[jc.id] = cur
	}
	jc.jm.mu.Unlock()
}

func recomputeItemCounters(rec *JobRecord) {
	rec.TotalItems = len(rec.Items)
	done := 0
	skipped := 0
	failed := 0
	for _, it := range rec.Items {
		switch it.Status {
		case JobStatusSucceeded, JobStatusRolledBack:
			done++
		case JobStatusSkipped:
			done++
			skipped++
		case JobStatusFailed:
			done++
			failed++
		}
	}
	rec.DoneItems = done
	rec.SkippedItems = skipped
	rec.FailedItems = failed
}

func cloneJobRecord(rec JobRecord) JobRecord {
	if len(rec.Items) > 0 {
		cp := make([]JobItemResult, len(rec.Items))
		copy(cp, rec.Items)
		rec.Items = cp
	}
	return rec
}

type queuedTask struct {
	id string
	fn RichJobFunc
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
			j.UpdatedAt = now
		}
		jm.jobs[j.ID] = cloneJobRecord(j)
	}
	return nil
}

func (jm *JobManager) persistLocked() {
	list := make([]JobRecord, 0, len(jm.jobs))
	for _, j := range jm.jobs {
		list = append(list, cloneJobRecord(j))
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

// TryLockInstance acquires an exclusive per-instance lock for jobID if the instance is not already locked by another job.
func (jm *JobManager) TryLockInstance(instanceID, jobID string) bool {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" || jobID == "" {
		return true
	}
	jm.mu.Lock()
	defer jm.mu.Unlock()
	if activeID, busy := jm.instanceLocks[instanceID]; busy && activeID != "" && activeID != jobID {
		return false
	}
	jm.instanceLocks[instanceID] = jobID
	return true
}

// UnlockInstance releases an exclusive per-instance lock owned by jobID.
func (jm *JobManager) UnlockInstance(instanceID, jobID string) {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" || jobID == "" {
		return
	}
	jm.mu.Lock()
	if jm.instanceLocks[instanceID] == jobID {
		delete(jm.instanceLocks, instanceID)
	}
	jm.mu.Unlock()
}

// Enqueue schedules a new background job, acquiring an exclusive per-instance lock if instanceID != "".
func (jm *JobManager) Enqueue(jobType, owner, instanceID, initialStep string, fn JobFunc) (JobRecord, error) {
	if fn == nil {
		return JobRecord{}, errors.New("job function is nil")
	}
	return jm.EnqueueWithMeta(JobMeta{
		Type:        jobType,
		Owner:       owner,
		InstanceID:  instanceID,
		InitialStep: initialStep,
	}, func(ctx context.Context, ctrl *JobController) error {
		return fn(ctx, ctrl.Report)
	})
}

// EnqueueWithMeta schedules a background job with rich display metadata and per-item tracking.
func (jm *JobManager) EnqueueWithMeta(meta JobMeta, fn RichJobFunc) (JobRecord, error) {
	if fn == nil {
		return JobRecord{}, errors.New("job function is nil")
	}

	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return JobRecord{}, err
	}
	jobID := "job_" + hex.EncodeToString(b[:])
	now := time.Now().UTC()

	var itemsCopy []JobItemResult
	if len(meta.Items) > 0 {
		itemsCopy = make([]JobItemResult, len(meta.Items))
		copy(itemsCopy, meta.Items)
	}

	rec := JobRecord{
		ID:         jobID,
		Type:       strings.TrimSpace(meta.Type),
		Title:      strings.TrimSpace(meta.Title),
		Target:     strings.TrimSpace(meta.Target),
		Owner:      strings.TrimSpace(meta.Owner),
		InstanceID: strings.TrimSpace(meta.InstanceID),
		Status:     JobStatusQueued,
		Progress:   0,
		Step:       strings.TrimSpace(meta.InitialStep),
		Items:      itemsCopy,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if len(rec.Items) > 0 {
		recomputeItemCounters(&rec)
	}

	jm.mu.Lock()
	if rec.InstanceID != "" {
		if activeID, busy := jm.instanceLocks[rec.InstanceID]; busy && activeID != "" {
			jm.mu.Unlock()
			return JobRecord{}, ErrInstanceBusy
		}
		jm.instanceLocks[rec.InstanceID] = jobID
	}
	jm.jobs[jobID] = rec
	jm.persistLocked()
	jm.mu.Unlock()

	select {
	case jm.queue <- queuedTask{id: jobID, fn: fn}:
		return cloneJobRecord(rec), nil
	default:
		jm.mu.Lock()
		if rec.InstanceID != "" && jm.instanceLocks[rec.InstanceID] == jobID {
			delete(jm.instanceLocks, rec.InstanceID)
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
	now := time.Now().UTC()
	jm.mu.Lock()
	rec, ok := jm.jobs[task.id]
	if !ok {
		jm.mu.Unlock()
		return
	}
	rec.Status = JobStatusRunning
	rec.StartedAt = now
	rec.UpdatedAt = now
	jm.jobs[task.id] = rec
	jm.mu.Unlock()

	ctrl := &JobController{jm: jm, id: task.id}
	err := task.fn(ctx, ctrl)

	doneAt := time.Now().UTC()
	jm.mu.Lock()
	defer jm.mu.Unlock()
	cur, exists := jm.jobs[task.id]
	if !exists {
		return
	}
	for instID, holder := range jm.instanceLocks {
		if holder == task.id {
			delete(jm.instanceLocks, instID)
		}
	}
	cur.CompletedAt = doneAt
	cur.UpdatedAt = doneAt
	if err != nil {
		if cur.Status != JobStatusRolledBack {
			cur.Status = JobStatusFailed
		}
		cur.Error = err.Error()
	} else {
		if cur.Status != JobStatusRolledBack {
			cur.Status = JobStatusSucceeded
		}
		cur.Progress = 100
	}
	jm.jobs[task.id] = cur
	jm.persistLocked()
}

// ClearCompletedJobs removes finished tasks (succeeded, failed, rolled_back) for owner (or all owners if isAdmin && owner == "").
// Active (queued, running) jobs are never removed.
func (jm *JobManager) ClearCompletedJobs(owner string, isAdmin bool) int {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	removed := 0
	for id, rec := range jm.jobs {
		if rec.Status == JobStatusQueued || rec.Status == JobStatusRunning {
			continue
		}
		if !isAdmin && rec.Owner != owner {
			continue
		}
		if isAdmin && owner != "" && rec.Owner != owner {
			continue
		}
		delete(jm.jobs, id)
		removed++
	}
	if removed > 0 {
		jm.persistLocked()
	}
	return removed
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
	return cloneJobRecord(rec), nil
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
		out = append(out, cloneJobRecord(rec))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
