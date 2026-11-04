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
