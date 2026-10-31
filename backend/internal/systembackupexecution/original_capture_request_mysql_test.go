package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// Mutate the ORIGINAL rows after this request authenticated the complete plan,
// while the original live ConfigMap is being read. Ready has no issuer Stage:
// the request's final complete input/ciphertext recheck must reject it itself.
func assertOriginalCaptureRequestMutations(t *testing.T, owner *PublicJobOwner, client *fake.Clientset, admin *sql.DB, controlClient *worker.ControlClient, authority d.Authority, invocation worker.Invocation) {
	t.Helper()
	ctx := context.Background()
	type mutation struct{ table, column string }
	for _, m := range []mutation{
		{"system_backup_v2_execution_inputs", "profile_json"},
		{"system_backup_v2_execution_inputs", "profile_sha256"},
		{"system_backup_v2_backups", "runner"},
		{"system_backup_v2_backups", "config_snapshot_json"},
		{"system_backup_v2_backups", "controller_owner"},
		{"system_backup_v2_execution_records", "payload_sha256"},
		{"system_backup_v2_execution_records", "key_ref"},
		{"system_backup_v2_execution_records", "sealed_payload"},
	} {
		var original []byte
		if err := admin.QueryRow("SELECT " + m.column + " FROM " + m.table).Scan(&original); err != nil {
			t.Fatal(err)
		}
		var armed atomic.Bool
		armed.Store(true)
		var changed atomic.Bool
		client.PrependReactor("get", "configmaps", func(action ktest.Action) (bool, runtime.Object, error) {
			if !armed.CompareAndSwap(true, false) {
				return false, nil, nil
			}
			value := append(append([]byte(nil), original...), ' ')
			if m.column == "profile_sha256" || m.column == "payload_sha256" {
				value = []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			}
			result, err := admin.Exec("UPDATE "+m.table+" SET "+m.column+"=?", value)
			if err != nil {
				t.Error(err)
				return true, nil, err
			}
			count, err := result.RowsAffected()
			var actual []byte
			if err != nil || count != 1 || admin.QueryRow("SELECT "+m.column+" FROM "+m.table).Scan(&actual) != nil || !bytes.Equal(actual, value) || bytes.Equal(actual, original) {
				t.Error("mutation did not change exactly one original row to the requested bytes", m.column, count, err)
				return true, nil, errors.New("original mutation was not applied")
			}
			changed.Store(true)
			return false, nil, nil
		})
		err := controlClient.Ready(ctx, invocation)
		if _, restore := admin.Exec("UPDATE "+m.table+" SET "+m.column+"=?", original); restore != nil {
			t.Fatal(restore)
		}
		if !changed.Load() || err == nil || errors.Is(err, worker.ErrNotReady) {
			t.Fatal("mid-request original mutation escaped terminal rejection", m.column, changed.Load(), err)
		}
		t.Log("actual Ready rejected mid-request original mutation", m.column)
	}
	in, err := owner.executionInput(ctx, authority, false)
	if err != nil {
		t.Fatal(err)
	}
	plan, discovery, original, err := owner.Gate.Records.OpenOriginalCapturePlan(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plan.CanonicalJSON)
	var binding d.JobBinding
	var raw []byte
	if admin.QueryRow("SELECT binding_json FROM system_backup_v2_runtime_resources WHERE resource_kind='Job'").Scan(&raw) != nil || json.Unmarshal(raw, &binding) != nil {
		t.Fatal("original binding")
	}
	if _, _, err = original.MatchPart(ctx, owner.Gate.Records, in, binding, invocation); err != nil {
		t.Fatal("original request part", err)
	}
	// Caller-owned observations cannot change the private part used by issuer.
	plan.CanonicalJSON[0] = '!'
	for index := range discovery.Parts {
		discovery.Parts[index].Intent.SpecJSON[0] = '!'
		discovery.Parts[index].InvocationJSON[0] = '!'
	}
	if _, _, err = original.MatchPart(ctx, owner.Gate.Records, in, binding, invocation); err != nil {
		t.Fatal("caller observation mutation changed private authenticated part", err)
	}
	other, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, _, err = original.MatchPart(other, owner.Gate.Records, in, binding, invocation); err == nil {
		t.Fatal("plan credential escaped original request context")
	}
	if _, _, err = (&c.OriginalCapturePlan{}).MatchPart(ctx, owner.Gate.Records, in, binding, invocation); err == nil {
		t.Fatal("caller-constructed plan credential accepted")
	}
}

func assertOriginalClaimWithdrawnBeforeReserve(t *testing.T, client *fake.Clientset, admin *sql.DB, controlClient *worker.ControlClient, invocation worker.Invocation, generates *atomic.Int32) {
	t.Helper()
	var original string
	if admin.QueryRow("SELECT controller_owner FROM system_backup_v2_backups").Scan(&original) != nil {
		t.Fatal("original claim owner")
	}
	withdrawn := original + "-withdrawn"
	var armed, changed atomic.Bool
	armed.Store(true)
	client.PrependReactor("get", "configmaps", func(action ktest.Action) (bool, runtime.Object, error) {
		if !armed.CompareAndSwap(true, false) {
			return false, nil, nil
		}
		result, err := admin.Exec("UPDATE system_backup_v2_backups SET controller_owner=?", withdrawn)
		if err != nil {
			t.Error(err)
			return true, nil, err
		}
		count, err := result.RowsAffected()
		var actual string
		if err != nil || count != 1 || admin.QueryRow("SELECT controller_owner FROM system_backup_v2_backups").Scan(&actual) != nil || actual != withdrawn || actual == original {
			t.Error("current claim withdrawal not independently observed")
			return true, nil, errors.New("claim not withdrawn")
		}
		changed.Store(true)
		return false, nil, nil
	})
	before := generates.Load()
	_, err := worker.NewOriginalKeyAuthority(context.Background(), controlClient, invocation)
	if _, restore := admin.Exec("UPDATE system_backup_v2_backups SET controller_owner=?", original); restore != nil {
		t.Fatal(restore)
	}
	if !changed.Load() || err == nil {
		t.Fatal("mid-request withdrawn claim admitted original key reserve", changed.Load(), err)
	}
	var uses, permits, candidates int
	if admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE key_use_json IS NOT NULL").Scan(&uses) != nil || admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id LIKE 'sev_apermit_%'").Scan(&permits) != nil || admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE candidate_cipher IS NOT NULL OR result_cipher IS NOT NULL").Scan(&candidates) != nil || uses != 0 || permits != 0 || candidates != 0 || generates.Load() != before {
		t.Fatal("withdrawn current claim produced key use, signed permit, accepted candidate or Generate", uses, permits, candidates, generates.Load()-before)
	}
	t.Log("actual key-reserve rejected independently observed mid-request claim withdrawal before all key/candidate/provider effects")
}
