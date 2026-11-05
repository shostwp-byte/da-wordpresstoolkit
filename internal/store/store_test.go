package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStorePersistenceAndTenantIsolation(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("Open store error: %v", err)
	}

	sets := st.ListSetsForOwner("reno26")
	if len(sets) != 3 {
		t.Fatalf("expected 3 seeded built-in sets, got %d", len(sets))
	}

	inst1, err := st.UpsertInstance(InstanceRecord{
		Owner:      "reno26",
		OwnerUID:   1005,
		Domain:     "renolabs-audio.com",
		DomainType: "main",
		DocRoot:    "/home/reno26/domains/renolabs-audio.com/public_html",
		SiteURL:    "https://renolabs-audio.com",
		SiteTitle:  "RENOLABS",
		WPVersion:  "6.7.1",
		PHPVersion: "8.4",
	})
	if err != nil {
		t.Fatalf("UpsertInstance failed: %v", err)
	}

	// Duplicate docroot under a different ID must fail
	if _, err := st.UpsertInstance(InstanceRecord{
		Owner:   "reno26",
		Domain:  "renolabs-audio.com",
		DocRoot: "/home/reno26/domains/renolabs-audio.com/public_html",
	}); !errors.Is(err, ErrDuplicateDocRoot) {
		t.Fatalf("expected ErrDuplicateDocRoot, got %v", err)
	}

	// Tenant isolation check: another user cannot read inst1
	if _, err := st.GetInstanceForOwner(inst1.ID, "otheruser"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected cross-tenant read to return ErrNotFound, got %v", err)
	}

	// Re-open store from disk to verify crash-safe persistence
	st2, err := Open(dir)
	if err != nil {
		t.Fatalf("re-open store error: %v", err)
	}
	loaded, err := st2.GetInstanceForOwner(inst1.ID, "reno26")
	if err != nil || loaded.SiteTitle != "RENOLABS" || loaded.WPVersion != "6.7.1" {
		t.Fatalf("reloaded instance mismatch: err=%v inst=%+v", err, loaded)
	}
}

func TestJobManagerConcurrencyLockAndCompletion(t *testing.T) {
	dir := t.TempDir()
	jm, err := NewJobManager(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jm.Start(ctx)

	blockCh := make(chan struct{})
	j1, err := jm.Enqueue("install", "reno26", "wp_1111222233334444", "Installing WordPress", func(_ context.Context, report ProgressReporter) error {
		report(50, "Configuring wp-config.php")
		<-blockCh
		return nil
	})
	if err != nil {
		t.Fatalf("first Enqueue failed: %v", err)
	}

	// Conflicting job on same instance must be rejected immediately
	if _, err := jm.Enqueue("update", "reno26", "wp_1111222233334444", "Updating plugins", func(_ context.Context, _ ProgressReporter) error {
		return nil
	}); !errors.Is(err, ErrInstanceBusy) {
		t.Fatalf("expected ErrInstanceBusy for concurrent instance task, got %v", err)
	}

	close(blockCh)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := jm.GetJobForOwner(j1.ID, "reno26", false)
		if err == nil && got.Status == JobStatusSucceeded && got.Progress == 100 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	finalJob, err := jm.GetJobForOwner(j1.ID, "reno26", false)
	if err != nil || finalJob.Status != JobStatusSucceeded {
		t.Fatalf("expected job to finish succeeded, got err=%v job=%+v", err, finalJob)
	}
	if _, err := jm.GetJobForOwner(j1.ID, "intruder", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected job lookup by intruder to fail with ErrNotFound, got %v", err)
	}
}

func TestJobManagerRichMetaItemsAndClearCompleted(t *testing.T) {
	dir := t.TempDir()
	jm, err := NewJobManager(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		jm.Wait()
	}()
	jm.Start(ctx)

	rec, err := jm.EnqueueWithMeta(JobMeta{
		Type:        "bulk_update_wp_core",
		Title:       "Cập nhật WordPress Core tuần tự (2 site)",
		Target:      "2 website",
		Owner:       "reno26",
		InitialStep: "Đang xếp hàng...",
		Items: []JobItemResult{
			{InstanceID: "wp_1", Domain: "one.io.vn", Status: JobStatusQueued},
			{InstanceID: "wp_2", Domain: "two.io.vn", Status: JobStatusQueued},
		},
	}, func(_ context.Context, ctrl *JobController) error {
		ctrl.Report(50, "Đang cập nhật [1/2] one.io.vn...")
		ctrl.UpdateItem(0, JobStatusSucceeded, "WP 6.5 → 6.8.1")
		ctrl.UpdateItem(1, JobStatusSkipped, "Đã ở bản mới nhất (WP 6.8.1)")
		ctrl.SetSummary("Hoàn tất 2/2 site: nâng cấp 1, bỏ qua 1")
		return nil
	})
	if err != nil {
		t.Fatalf("EnqueueWithMeta failed: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, gErr := jm.GetJobForOwner(rec.ID, "reno26", false)
		if gErr == nil && got.Status == JobStatusSucceeded {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	got, err := jm.GetJobForOwner(rec.ID, "reno26", false)
	if err != nil {
		t.Fatalf("GetJobForOwner failed: %v", err)
	}
	if got.TotalItems != 2 || got.DoneItems != 2 || got.SkippedItems != 1 || got.FailedItems != 0 {
		t.Fatalf("unexpected item counters: %+v", got)
	}
	if got.Summary != "Hoàn tất 2/2 site: nâng cấp 1, bỏ qua 1" {
		t.Fatalf("unexpected summary: %q", got.Summary)
	}

	// ClearCompletedJobs for another user must not remove reno26's job
	if removed := jm.ClearCompletedJobs("other", false); removed != 0 {
		t.Fatalf("expected 0 removed for other user, got %d", removed)
	}
	if removed := jm.ClearCompletedJobs("reno26", false); removed != 1 {
		t.Fatalf("expected 1 removed for reno26, got %d", removed)
	}
	if len(jm.ListJobs("reno26", false, 10)) != 0 {
		t.Fatalf("expected empty job list after ClearCompletedJobs")
	}
}
