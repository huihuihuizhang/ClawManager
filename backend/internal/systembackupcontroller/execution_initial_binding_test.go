package systembackupcontroller

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	d "clawreef/internal/systembackupdispatch"
)

// This fixture exercises only private live-context lifetime and ownership. It
// executes no authority SQL and is not evidence of first-binding authorization.
func initialBindingContextFixture(t *testing.T) (context.Context, *originalControllerRun, context.CancelFunc, kube.ResourceRecord, *executionModel) {
	t.Helper()
	auth, model := newExecutionModel(t)
	auth.ApplicationScope = "binding-context-scope"
	input := model.a
	input.MaintenanceOwner = input.TaskPublicID
	s := SQLExecutionWorkStore{Queue: SQLExecutionQueue{DB: auth.DB, InstallationID: input.InstallationID, Owner: input.ClaimOwner, ApplicationScope: auth.ApplicationScope, Policy: LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}}, Authority: auth, Records: SQLExecutionRecords{Authority: auth}}
	child, cancel := context.WithCancel(context.Background())
	live := newOriginalControllerRun(s, input, child)
	active := context.WithValue(child, originalControllerRunKey{}, live)
	record := kube.ResourceRecord{Intent: kube.ResourceIntent{Kind: "Job", Identity: kube.Identity{Namespace: "capture", Name: "original-job", Owner: input.TaskPublicID}, RequestJSON: []byte(`{"kind":"Job"}`)}, Revision: 3, CreateDispatched: true, UID: "original-job-uid", ResourceVersion: "r1"}
	t.Cleanup(func() { live.close(cancel) })
	return active, live, cancel, record, model
}

func TestOriginalControllerBindingContextOwnershipAndClosure(t *testing.T) {
	for _, name := range []string{"healthy", "foreign-authority", "closed", "canceled", "foreign-store-owner", "foreign-store-db"} {
		t.Run(name, func(t *testing.T) {
			active, live, cancel, record, model := initialBindingContextFixture(t)
			input := live.authority
			switch name {
			case "foreign-authority":
				input.AttemptNo++
			case "closed":
				live.close(cancel)
			case "canceled":
				cancel()
			case "foreign-store-owner":
				copy := *live.store.Authority.Authorization.(*executionAuth)
				live.store.Records.Authority.Authorization = &copy
			case "foreign-store-db":
				live.store.Records.Authority.DB = nil
			}
			called := false
			var retained context.Context
			_, err := WithOriginalControllerBinding(active, input, record, func(scoped context.Context) (d.JobBinding, error) {
				called = true
				retained = scoped
				f, _ := scoped.Value(originalControllerBindingKey{}).(*originalControllerBinding)
				if f == nil || f.ctx != scoped || f.run != live || f.closed.Load() {
					t.Fatal("original live frame missing")
				}
				record.Intent.RequestJSON[0] = '!'
				if string(f.record.Intent.RequestJSON) != `{"kind":"Job"}` {
					t.Fatal("caller alias changed original frame")
				}
				return d.JobBinding{}, nil
			})
			allowed := name == "healthy"
			if called != allowed || (err == nil) != allowed || len(model.queries) != 0 {
				t.Fatal("closed/foreign scope changed behavior or issued SQL", called, err)
			}
			if allowed {
				f := retained.Value(originalControllerBindingKey{}).(*originalControllerBinding)
				if !f.closed.Load() || retained.Err() == nil {
					t.Fatal("returned frame remained live")
				}
			}
		})
	}
	called := false
	if _, err := WithOriginalControllerBinding(context.Background(), d.Authority{}, kube.ResourceRecord{}, func(ctx context.Context) (d.JobBinding, error) {
		called = true
		if ctx.Value(originalControllerBindingKey{}) != nil {
			t.Fatal("legacy caller acquired private frame")
		}
		return d.JobBinding{}, nil
	}); err != nil || !called {
		t.Fatal("legacy behavior changed", err)
	}
}

func TestOriginalControllerBindingUnknownBecomesReadOnly(t *testing.T) {
	active, live, _, record, model := initialBindingContextFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		_, err := WithOriginalControllerBinding(active, live.authority, record, func(ctx context.Context) (d.JobBinding, error) {
			f := ctx.Value(originalControllerBindingKey{}).(*originalControllerBinding)
			if f.readOnly != (attempt == 1) {
				t.Fatal("unknown binding could acquire another first-renewal path")
			}
			if attempt == 0 {
				return d.JobBinding{}, ErrExecutionCommitUnknown
			}
			return d.JobBinding{UID: record.UID}, nil
		})
		if attempt == 0 && !errors.Is(err, ErrExecutionCommitUnknown) || attempt == 1 && err != nil {
			t.Fatal(err)
		}
	}
	if len(model.queries) != 0 {
		t.Fatal("context test issued SQL")
	}
}

func TestOriginalControllerBindingShutdownCancelsAndJoinsDetachedCaller(t *testing.T) {
	active, live, cancel, record, model := initialBindingContextFixture(t)
	started, canceled, release, finished, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{})
	go func() {
		_, err := WithOriginalControllerBinding(context.WithoutCancel(active), live.authority, record, func(ctx context.Context) (d.JobBinding, error) {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return d.JobBinding{}, ctx.Err()
		})
		finished <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("binding did not start")
	}
	go func() { live.close(cancel); close(closed) }()
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("detached caller escaped original cancellation")
	}
	select {
	case <-closed:
		t.Fatal("controller returned before in-flight binding joined")
	default:
	}
	close(release)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("binding did not stop")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("controller did not join binding")
	}
	if len(model.queries) != 0 {
		t.Fatal("lifetime fixture issued SQL")
	}
}
