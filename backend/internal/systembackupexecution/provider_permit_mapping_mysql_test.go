package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
)

// These are actual signed-row fault injections through the private fixture's
// administrator, not the fenced installation writer protocol. Both original
// Stage entry points must observe each committed current row after preparation.
func assertPreparedPermitCurrentOwnerMappingSQL(t *testing.T, owner *PublicJobOwner, admin *sql.DB, authority d.Authority, job d.JobBinding, invocation worker.Invocation, lease worker.KeyUseLease, sign func(func(*a.OriginalRecord)) ([]byte, []byte)) {
	t.Helper()
	ctx := context.Background()
	if sign == nil {
		t.Fatal("original owner signer fixture missing")
	}
	in, err := owner.readExecutionInput(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	invocationHash, err := invocation.Hash()
	if err != nil {
		t.Fatal(err)
	}
	pod := BoundPod{Namespace: job.Namespace, Name: "capture-pod", UID: lease.Identity.PodUID, ServiceAccountUID: lease.Identity.ServiceAccountUID}
	prepared, err := owner.prepareProviderPermit(ctx, in, job, pod, worker.ControlRequest{Action: "key-check", Invocation: invocation, InvocationSHA256: invocationHash})
	if err != nil {
		t.Fatal(err)
	}
	query := `SELECT signed_record,signature FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=?`
	key := invocation.ProviderKey.Request.Key
	var originalRaw, originalSig []byte
	if err := admin.QueryRowContext(ctx, query, authority.InstallationID, key.IdentityHash, key.RegistryVersion).Scan(&originalRaw, &originalSig); err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, raw, sig []byte) {
		t.Helper()
		result, err := admin.ExecContext(ctx, `UPDATE system_backup_installation_kek_authority SET signed_record=?,signature=? WHERE installation_id=? AND identity_hash=? AND registry_version=?`, raw, sig, authority.InstallationID, key.IdentityHash, key.RegistryVersion)
		if err != nil {
			t.Fatal(err)
		}
		count, err := result.RowsAffected()
		var observedRaw, observedSig []byte
		readErr := admin.QueryRowContext(ctx, query, authority.InstallationID, key.IdentityHash, key.RegistryVersion).Scan(&observedRaw, &observedSig)
		if err != nil || count != 1 || readErr != nil || !bytes.Equal(raw, observedRaw) || !bytes.Equal(sig, observedSig) {
			t.Fatal("current signed owner row mutation not independently observed", count, err, readErr)
		}
	}
	for _, tc := range []struct {
		name             string
		edit             func(*a.OriginalRecord)
		corruptSignature bool
		allowed          bool
	}{
		{"revision", func(m *a.OriginalRecord) { m.Revision = "owner-r2"; m.Source.RecordVersion = "v2" }, false, true},
		{"renewal", func(m *a.OriginalRecord) { m.Revision = "owner-r2"; m.Until = m.Until.Add(time.Minute) }, false, true},
		{"minimum_boundary", func(m *a.OriginalRecord) { m.Until = prepared.ValidUntil() }, false, true},
		{"shorter_than_original_minimum", func(m *a.OriginalRecord) { m.Until = prepared.ValidUntil().Add(-time.Microsecond) }, false, false},
		{"generate_revoked", func(m *a.OriginalRecord) { m.GenerateRevoked = true }, false, false},
		{"unwrap_only_revoked", func(m *a.OriginalRecord) { m.UnwrapRevoked = true }, false, true},
		{"future", func(m *a.OriginalRecord) { m.NotBefore = time.Now().Add(time.Minute) }, false, false},
		{"expired", func(m *a.OriginalRecord) { m.Until = time.Now().Add(-time.Second) }, false, false},
		{"corrupt_signature", func(m *a.OriginalRecord) { m.Revision = "owner-r2" }, true, false},
	} {
		t.Run("owner-mapping-"+tc.name, func(t *testing.T) {
			currentRaw, currentSig := sign(tc.edit)
			if tc.corruptSignature {
				currentSig[0] ^= 1
			}
			write(t, currentRaw, currentSig)
			t.Cleanup(func() { write(t, originalRaw, originalSig) })
			for _, reuse := range []bool{false, true} {
				func() {
					tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					guard, err := owner.Gate.Authority.Bind(ctx, tx, authority)
					if err != nil || guard.Recheck(ctx, tx) != nil {
						t.Fatal("original current guard before owner mapping Stage", err)
					}
					before := providerStageRows(t, ctx, tx)
					initialUntil := prepared.ValidUntil()
					if reuse {
						err = prepared.StageOriginal(ctx, tx, lease, "key-check", guard)
					} else {
						err = prepared.Stage(ctx, tx, lease, "key-check")
					}
					if (err == nil) != tc.allowed {
						t.Fatal("current signed owner mapping Stage decision", reuse, tc.allowed, err)
					}
					if !prepared.ValidUntil().Equal(initialUntil) || providerStageRows(t, ctx, tx) != before {
						t.Fatal("current mapping changed original lifetime/journal/reference/epoch")
					}
					if reuse && !tc.allowed && (guard.Recheck(ctx, tx) == nil || !guard.ValidUntil().IsZero()) {
						t.Fatal("failed original mapping guard revived")
					}
				}()
			}
		})
	}
}
