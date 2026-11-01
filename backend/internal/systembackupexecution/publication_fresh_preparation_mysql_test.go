package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Real current publisher, original authenticated capture plan, production
// 104/121/102 DDL and TLS-owned SQL. This is transport preparation, not a
// six-domain capture/C/acceptance substitute. Negative rows are inert DATA.
func TestPublicationFreshPreparationActualRenewMySQL(t *testing.T) {
	for _, mode := range []string{"fresh", "assembly-fresh", "old-104-without-capsule", "assembly-old-104-without-capsule", "old-material", "old-activation", "old-owner", "old-upload", "old-121-planned", "old-121-sending", "old-107-sequence-zero", "old-102-without-capsule", "policy-change", "stale-claim", "canceled", "renew-commit-ack-lost"} {
		t.Run(mode, func(t *testing.T) {
			var lose atomic.Bool
			f := newAPublicationMaterialFixtureControl(t, false, func(inner driver.Connector) driver.Connector {
				return aPublicationACKConnector{Connector: inner, lose: &lose}
			})
			aPublicationActualObservationDDL(t, f)
			h, ctx := f.x.history, context.Background()
			claim := h.token
			var ttl, heartbeat, reconcile int64
			if err := h.admin.QueryRow(`SELECT controller_claim_ttl_seconds,controller_claim_heartbeat_seconds,controller_reconcile_interval_seconds FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1`, h.original.InstallationID).Scan(&ttl, &heartbeat, &reconcile); err != nil {
				t.Fatal(err)
			}
			policy := c.LeasePolicy{TTL: time.Duration(ttl) * time.Second, HeartbeatInterval: time.Duration(heartbeat) * time.Second, ReconcileInterval: time.Duration(reconcile) * time.Second}
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := h.admin.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(mode, "old-104") {
				if _, err := h.service.beginPublicationCandidate(ctx, claim, 1, f.store.config, f.request); err != nil {
					t.Fatal("original104", err)
				}
				if _, err := h.service.loadPublicationMaterialIntent(ctx, claim, 1); !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("counter must have no capsule", err)
				}
			}
			suffix := map[string]string{"old-material": "", "old-activation": "_activation", "old-owner": "_job_owner", "old-upload": "_result_1"}
			if ending, ok := suffix[mode]; ok {
				id := publicationMaterialID(h.original.InstallationID, h.original.TaskPublicID, 1) + ending
				if mode == "old-upload" {
					id = "sev_pub_upload_" + strings.Repeat("b", 64) + ending
				}
				tx, err := h.admin.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err = registerPublicationMetadata(ctx, tx, h.original.InstallationID, h.original.TaskPublicID, id, []byte(`{"inert_old_delegation":true}`), time.Now().Add(time.Hour)); err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(mode, "old-121") || mode == "old-107-sequence-zero" {
				exec(`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,row_version,started_at) VALUES('backup',?,1,'publish','running',1,UTC_TIMESTAMP(6))`, h.original.TaskPublicID)
				if mode == "old-107-sequence-zero" {
					exec(`INSERT INTO system_backup_v2_job_observations(origin_installation_id,target_type,target_public_id,attempt_no,phase,job_unit_key,job_uid,job_generation,relay_identity_ref,relay_identity_version,relay_identity_bound_at,relay_identity_expires_at,last_accepted_sequence,progress_sequence,created_at) VALUES(?,'backup',?,1,'publish','upload-old','11111111-2222-4333-8444-555555555555',1,'old-ref','old-version',UTC_TIMESTAMP(6),TIMESTAMPADD(SECOND,30,UTC_TIMESTAMP(6)),0,0,UTC_TIMESTAMP(6))`, h.original.InstallationID, h.original.TaskPublicID)
				} else {
					state := "planned"
					var started any
					if mode == "old-121-sending" {
						state, started = "sending", time.Now().UTC()
					}
					exec(`INSERT INTO system_backup_v2_job_send_intents(origin_installation_id,task_public_id,phase,job_unit_key,namespace_name,namespace_uid,job_name,spec_sha256,send_state,send_started_at) VALUES(?,?,'publish','upload-old','backup','namespace-old','upload-old',?,?,?)`, h.original.InstallationID, h.original.TaskPublicID, strings.Repeat("c", 64), state, started)
				}
			}
			if mode == "policy-change" {
				policy.TTL += time.Second
			}
			if mode == "old-102-without-capsule" {
				body := []byte(`{"inert_old_action":true}`)
				exec(`INSERT INTO system_backup_v2_external_actions(public_id,origin_installation_id,target_type,target_public_id,action_type,logical_action_hash,action_key,canonical_payload_bytes,payload_sha256,content_length,final_key,dispatch_deadline) VALUES('sxa_11111111-2222-4333-8444-555555555555',?,'backup',?,'manifest_put',?,'old-action',?,?,?,'artifacts/old/manifest.json',TIMESTAMPADD(SECOND,30,UTC_TIMESTAMP(6)))`, h.original.InstallationID, h.original.TaskPublicID, strings.Repeat("d", 64), body, hash(body), len(body))
				if _, err := h.service.loadPublicationMaterialIntent(ctx, claim, 1); !errors.Is(err, sql.ErrNoRows) {
					t.Fatal("102 counter must have no capsule", err)
				}
			}
			if mode == "stale-claim" {
				claim.RowVersion++
			}
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := claim
			requestBefore, _ := json.Marshal(f.request)
			var versionBefore uint64
			var configBefore []byte
			var leaseBefore, beatBefore time.Time
			ledgerBefore := aPreparationLedgerFingerprint(t, h.admin)
			if h.admin.QueryRow(`SELECT row_version,config_snapshot_json,controller_lease_expires_at,heartbeat_at FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&versionBefore, &configBefore, &leaseBefore, &beatBefore) != nil {
				t.Fatal("before state")
			}
			providerBefore := f.x.logins.Load() + f.x.decrypts.Load() + f.x.generates.Load()
			nativeBefore := f.secretCreates + f.secretUpdates + f.jobCreates
			if mode == "renew-commit-ack-lost" {
				lose.Store(true)
			}
			var err error
			if strings.HasPrefix(mode, "assembly-") {
				err = h.service.renewOriginalPublicationAssemblyClaim(ctx, &claim, 1, policy)
			} else {
				err = h.service.renewFreshOriginalPublicationPreparation(ctx, &claim, 1, policy, f.store.config, f.request)
			}
			var versionAfter uint64
			var configAfter []byte
			var lease, beat, now time.Time
			if h.admin.QueryRow(`SELECT row_version,config_snapshot_json,controller_lease_expires_at,heartbeat_at,UTC_TIMESTAMP(6) FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&versionAfter, &configAfter, &lease, &beat, &now) != nil {
				t.Fatal("after state")
			}
			positive := mode == "fresh" || mode == "assembly-fresh"
			if positive {
				if err != nil || claim.RowVersion != before.RowVersion+1 || versionAfter != versionBefore+1 || !lease.Equal(beat.Add(policy.TTL)) || now.Before(beat) || !now.Before(lease) {
					t.Fatal("actual original CAS/SQL clock renewal", err, versionAfter, versionBefore)
				}
			} else {
				if err == nil || claim != before {
					t.Fatal("negative changed caller token", err)
				}
				if mode == "renew-commit-ack-lost" {
					if !errors.Is(err, errAPublicationACKLost) || versionAfter != versionBefore+1 {
						t.Fatal("real unknown commit counter", err)
					}
				} else if versionAfter != versionBefore || !lease.Equal(leaseBefore) || !beat.Equal(beatBefore) {
					t.Fatal("negative renewed SQL", err)
				}
				if strings.HasPrefix(mode, "old-") || strings.HasPrefix(mode, "assembly-old") {
					if !errors.Is(err, errOriginalPublicationPreparationExists) {
						t.Fatal("missed original delegation", err)
					}
				}
			}
			requestAfter, _ := json.Marshal(f.request)
			if !bytes.Equal(configBefore, configAfter) || !bytes.Equal(requestBefore, requestAfter) || ledgerBefore != aPreparationLedgerFingerprint(t, h.admin) || f.x.logins.Load()+f.x.decrypts.Load()+f.x.generates.Load() != providerBefore || f.secretCreates+f.secretUpdates+f.jobCreates != nativeBefore {
				t.Fatal("renewal changed original bytes or reached provider/native")
			}
		})
	}
}

func aPreparationLedgerFingerprint(t *testing.T, db *sql.DB) string {
	t.Helper()
	var snapshot []byte
	for _, table := range []string{"system_backup_v2_staging_resources", "system_backup_v2_evidence", "system_backup_v2_execution_records", "system_backup_v2_job_send_intents", "system_backup_v2_job_observations", "system_backup_v2_external_actions"} {
		rows, err := db.Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var bodies []string
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			raw, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			bodies = append(bodies, hash(raw))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
		sort.Strings(bodies)
		raw, _ := json.Marshal(struct {
			Table         string
			Columns, Rows []string
		}{table, columns, bodies})
		snapshot = append(snapshot, raw...)
	}
	return hash(snapshot)
}
