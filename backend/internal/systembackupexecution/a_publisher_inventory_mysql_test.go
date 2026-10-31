package systembackupexecution

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestAPublisherCaptureInventoryOriginalBytesAfterFinalWorkloadIO(t *testing.T) {
	for _, mode := range []string{"unchanged", "plan-cipher", "plan-keyref", "profile", "grant-file", "record-key-file", "original-custody-grant"} {
		t.Run(mode, func(t *testing.T) {
			x := newAPublisherVerifierFixture(t)
			h := x.history
			ctx := context.Background()
			calls := 0
			changed := false
			h.owner.Client.(*fake.Clientset).PrependReactor("get", "serviceaccounts", func(ktesting.Action) (bool, kruntime.Object, error) {
				calls++
				if calls == 3 {
					var err error
					switch mode {
					case "plan-cipher":
						_, err = h.admin.Exec("UPDATE system_backup_v2_execution_records SET sealed_payload=CONCAT(sealed_payload,'x') WHERE record_kind='plan'")
					case "plan-keyref":
						_, err = h.admin.Exec("UPDATE system_backup_v2_execution_records SET key_ref=CONCAT(key_ref,'x') WHERE record_kind='plan'")
					case "profile":
						_, err = h.admin.Exec("UPDATE system_backup_v2_execution_inputs SET profile_json=CONCAT(profile_json,' ')")
					case "grant-file":
						err = os.WriteFile(h.cfg.GrantMount.File, []byte(`{"revoked":true}`), 0600)
					case "record-key-file":
						key := h.owner.Identity.DeploymentBinding().RecordKeys[0]
						err = os.WriteFile(filepath.Join(filepath.Dir(h.service.ConfigPath), key.Ref), make([]byte, 32), 0600)
					case "original-custody-grant":
						err = os.WriteFile(filepath.Join(filepath.Dir(h.service.ConfigPath), "grant.json"), []byte(`{"replacement":true}`), 0600)
					}
					if err != nil {
						t.Fatal("committed original change", err)
					}
					changed = true
				}
				return false, nil, nil
			})
			parts, err := h.owner.Gate.Records.PublisherCaptureParts(ctx, h.access)
			if !changed {
				t.Fatal("last workload I/O not reached")
			}
			if mode == "unchanged" {
				if err != nil || !reflect.DeepEqual(parts, []string{"workspace"}) {
					t.Fatal("original inventory", parts, err)
				}
			} else if err == nil || parts != nil {
				t.Fatal("stale inventory accepted", parts, err)
			}
		})
	}
}

func TestAPublisherCapturedRecordDetachedCannotMutateVerifier(t *testing.T) {
	x := newAPublisherVerifierFixture(t)
	ctx := context.Background()
	v, err := x.factory.ForPart(ctx, x.history.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	record, err := v.CapturedRecord(ctx)
	if err != nil {
		t.Fatal(err)
	}
	record.CandidateJSON[0] = 'x'
	record.Input.ConfigSnapshot[0] = 'x'
	again, err := v.CapturedRecord(ctx)
	if err != nil || again.CandidateJSON[0] == 'x' || again.Input.ConfigSnapshot[0] == 'x' {
		t.Fatal("detached history mutated current verifier", err)
	}
}
