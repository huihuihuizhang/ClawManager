package systembackupexecution

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Actual native SQL/locally signed HTTPS immutable-object protocol. Payloads
// here are explicitly named JSON DATA, not signed public artifact acceptance.
func TestOriginalPublicationContinuationMySQL(t *testing.T) {
	for _, mode := range []string{"reentry-and-next-stage", "concurrent-claim", "next-readback-failure", "unknown-query-only", "confirmed-version-changed", "stage-hole", "finalization-required", "production-pass-needs-next-intent", "close-joins-next-stage"} {
		t.Run(mode, func(t *testing.T) {
			x, store, state := newAOriginalPublicationService(t)
			h := x.history
			ctx := context.Background()
			intent := func(kind string) publicationJSONIntent {
				suffix := map[string]string{"manifest_put": "manifest.json", "marker_put": "_COMMITTED", "acceptance_put": "_ACCEPTANCE", "catalog_registration_append": "catalog/registration.json"}[kind]
				return publicationJSONIntent{Kind: kind, Key: store.config.Root + h.original.TaskPublicID + "/" + strconv.FormatUint(h.original.AttemptNo, 10) + "/" + suffix, Payload: []byte(`{"local":"original continuation protocol DATA"}`), Deadline: time.Now().Add(8 * time.Second)}
			}
			release := func(token c.ClaimToken) {
				t.Helper()
				if _, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, token, time.Second); err != nil {
					t.Fatal(err)
				}
				if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET next_reconcile_at=NULL WHERE public_id=?`, h.original.TaskPublicID); err != nil {
					t.Fatal(err)
				}
			}
			firstKind := "manifest_put"
			if mode == "stage-hole" {
				firstKind = "marker_put"
			}
			first := intent(firstKind)
			if mode == "unknown-query-only" {
				if _, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, first); err != nil || !send {
					t.Fatal(err)
				}
			} else if _, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, first); err != nil {
				t.Fatal(err)
			}
			if mode == "finalization-required" {
				for _, kind := range publicationContinuationOrder[1:] {
					if _, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent(kind)); err != nil {
						t.Fatal(err)
					}
				}
			}
			release(h.token)
			if mode == "confirmed-version-changed" {
				if _, err := h.admin.Exec(`UPDATE system_backup_v2_external_actions SET observed_version='other-version' WHERE target_public_id=?`, h.original.TaskPublicID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "concurrent-claim" {
				type result struct {
					p   *publicationContinuation
					err error
				}
				finished := make(chan result, 2)
				for i := 0; i < 2; i++ {
					go func() { p, err := h.service.preparePublicationContinuation(ctx, store); finished <- result{p, err} }()
				}
				var acquired []*publicationContinuation
				for i := 0; i < 2; i++ {
					r := <-finished
					if r.err != nil && !errors.Is(r.err, c.ErrClaimNotAcquired) {
						t.Fatal(r.err)
					}
					if r.p != nil {
						acquired = append(acquired, r.p)
					}
				}
				if len(acquired) != 1 || state.puts != 1 {
					t.Fatal("concurrent continuation duplicated claim or PUT", len(acquired), state.puts)
				}
				if err := acquired[0].close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if mode == "production-pass-needs-next-intent" {
				if err := h.service.RunPublicationPass(ctx); !errors.Is(err, ErrPublicationNextIntentRequired) || state.puts != 1 {
					t.Fatal("production pass silently skipped the confirmed task", err, state.puts)
				}
				var status string
				if err := h.admin.QueryRow(`SELECT status FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&status); err != nil || status != "publishing" {
					t.Fatal("next intent refusal changed task status", status, err)
				}
				return
			}
			if mode == "finalization-required" {
				if err := h.service.runPublicationContinuation(ctx, store); !errors.Is(err, ErrPublicationFinalizationRequired) {
					t.Fatal("confirmed catalog was treated as acceptance", err)
				}
				var status string
				var usable bool
				if err := h.admin.QueryRow(`SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&status, &usable); err != nil || status != "publishing" || usable || state.puts != 4 {
					t.Fatal("premature success", status, usable, state.puts, err)
				}
				return
			}
			p, err := h.service.preparePublicationContinuation(ctx, store)
			if mode == "unknown-query-only" {
				if err != nil || p != nil || state.puts != 0 {
					t.Fatal("unknown action acquired a send continuation", p, err, state.puts)
				}
				return
			}
			if mode == "stage-hole" || mode == "confirmed-version-changed" {
				if err == nil || p != nil || state.puts != 1 {
					t.Fatal("invalid original chain accepted", p, err, state.puts)
				}
				return
			}
			if err != nil || p == nil || p.next != "marker_put" || p.attempt != h.original.AttemptNo || p.claim.Target.PublicID != h.original.TaskPublicID || p.claim.RowVersion <= h.token.RowVersion || len(p.objects) != 1 || p.objects[0].Version != "original-v1" || state.puts != 1 {
				t.Fatal("actual same-task continuation", p, err, state.puts)
			}
			defer p.close()
			// The caller already holds this task's write lock. Recheck must use
			// only this exact transaction and the access created before any TX;
			// the native fixture also rejects Kubernetes I/O while SQL is held.
			locked, err := h.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var lockedStatus string
			if err := locked.QueryRowContext(ctx, `SELECT status FROM system_backup_v2_backups WHERE public_id=? FOR UPDATE`, h.original.TaskPublicID).Scan(&lockedStatus); err != nil {
				locked.Rollback()
				t.Fatal(err)
			}
			start := time.Now()
			if err := p.recheckTx(ctx, locked); err != nil {
				locked.Rollback()
				t.Fatal("same outer task lock recheck", err)
			}
			if time.Since(start) > 2*time.Second {
				locked.Rollback()
				t.Fatal("same transaction recheck waited for itself")
			}
			if err := locked.Rollback(); err != nil {
				t.Fatal(err)
			}
			if mode == "close-joins-next-stage" {
				entered, releaseRead := make(chan struct{}), make(chan struct{})
				defer func() {
					select {
					case <-releaseRead:
					default:
						close(releaseRead)
					}
				}()
				state.mu.Lock()
				state.onGet = func() {
					close(entered)
					select {
					case <-releaseRead:
					case <-time.After(2 * time.Second):
						t.Error("test read release was not delivered")
					}
				}
				state.mu.Unlock()
				published, closed := make(chan error, 1), make(chan error, 2)
				go func() { _, err := p.publishNext(ctx, store, intent("marker_put")); published <- err }()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("actual next-stage read not entered")
				}
				for i := 0; i < 2; i++ {
					go func() { closed <- p.close() }()
				}
				select {
				case err := <-closed:
					t.Fatal("close returned before its in-flight stage joined", err)
				case <-time.After(50 * time.Millisecond):
				}
				close(releaseRead)
				if err := <-published; err != nil {
					t.Fatal(err)
				}
				if err := <-closed; err != nil {
					t.Fatal(err)
				}
				if err := <-closed; err != nil {
					t.Fatal("second close did not share successful release", err)
				}
				if _, err := p.publishNext(ctx, store, intent("marker_put")); !errors.Is(err, c.ErrExecutionAuthority) || state.puts != 2 {
					t.Fatal("closed handle sent another stage", err, state.puts)
				}
				return
			}
			if mode == "next-readback-failure" {
				state.mu.Lock()
				state.getUnavailable = true
				state.mu.Unlock()
			}
			object, err := p.publishNext(ctx, store, intent("marker_put"))
			if mode == "next-readback-failure" {
				if err == nil || object.receipt != nil || state.puts != 2 {
					t.Fatal("failed next stage became success", err, state.puts)
				}
				if _, err := p.publishNext(ctx, store, intent("marker_put")); !errors.Is(err, c.ErrExecutionAuthority) || state.puts != 2 {
					t.Fatal("spent continuation replayed a PUT", err, state.puts)
				}
				var old, stateSQL, status string
				if h.db.QueryRow(`SELECT state FROM system_backup_v2_external_actions WHERE target_public_id=? AND action_type='manifest_put'`, h.original.TaskPublicID).Scan(&old) != nil || old != "confirmed_present" || h.db.QueryRow(`SELECT state FROM system_backup_v2_external_actions WHERE target_public_id=? AND action_type='marker_put'`, h.original.TaskPublicID).Scan(&stateSQL) != nil || stateSQL != "provider_unreachable" || h.db.QueryRow(`SELECT status FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&status) != nil || status != "finalization_unknown" {
					t.Fatal("next failure erased original confirmed facts", old, stateSQL, status)
				}
				if err := p.close(); err != nil {
					t.Fatal(err)
				}
				if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET next_reconcile_at=NULL WHERE public_id=?`, h.original.TaskPublicID); err != nil {
					t.Fatal(err)
				}
				state.mu.Lock()
				state.getUnavailable = false
				state.mu.Unlock()
				if err := h.service.RunPublicationPass(ctx); err != nil || state.puts != 2 {
					t.Fatal("production unknown recovery resent the next stage", err, state.puts)
				}
				if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET next_reconcile_at=NULL WHERE public_id=?`, h.original.TaskPublicID); err != nil {
					t.Fatal(err)
				}
				if err := h.service.RunPublicationPass(ctx); !errors.Is(err, ErrPublicationFinalizationRequired) || state.puts != 2 {
					t.Fatal("production confirmed recovery did not require independent acceptance", err, state.puts)
				}
				return
			}
			if err != nil || object.receipt == nil || state.puts != 2 {
				t.Fatal("next real immutable stage", err, state.puts)
			}
			if _, err := p.publishNext(ctx, store, intent("marker_put")); !errors.Is(err, c.ErrExecutionAuthority) || state.puts != 2 {
				t.Fatal("same handle sent twice", err, state.puts)
			}
			if err := p.close(); err != nil {
				t.Fatal(err)
			}
			if _, err := h.admin.Exec(`UPDATE system_backup_v2_backups SET next_reconcile_at=NULL WHERE public_id=?`, h.original.TaskPublicID); err != nil {
				t.Fatal(err)
			}
			reopened, err := h.service.preparePublicationContinuation(ctx, store)
			if err != nil || reopened == nil {
				t.Fatal(err)
			}
			defer reopened.close()
			if reopened.next != "acceptance_put" || len(reopened.objects) != 2 || reopened.claim.RowVersion <= p.claim.RowVersion || state.puts != 2 {
				t.Fatal("reentry regenerated the prior stage", reopened.next, state.puts)
			}
			if _, err := reopened.publishNext(ctx, store, intent("acceptance_put")); !errors.Is(err, ErrPublicationFinalizationRequired) || state.puts != 2 {
				t.Fatal("missing independent acceptance allowed a send", err, state.puts)
			}
		})
	}
}
