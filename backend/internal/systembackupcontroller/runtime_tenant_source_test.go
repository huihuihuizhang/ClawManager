package systembackupcontroller

import (
	"context"
	"errors"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRuntimeTenantProCheckPrecedesNativeReads(t *testing.T) {
	for _, mode := range []string{"no-owner", "owner-refuses", "approved", "lite", "stopped"} {
		t.Run(mode, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			source := b.InstanceIdentity{ID: 2, UserID: 1, Generation: 7, Mode: "pro", OS: "linux", Status: "running", Namespace: "test-user-1", Pod: "original"}
			calls := 0
			owner := &SQLRuntimeControl{cfg: RuntimeControlConfig{Namespace: "test-system", Client: client}}
			if mode != "no-owner" {
				owner.cfg.TenantProSourceCheck = func(_ context.Context, actual b.InstanceIdentity) error {
					calls++
					if actual != source {
						t.Fatal("source was changed before owner admission")
					}
					if mode == "owner-refuses" {
						return errors.New("original source changed")
					}
					return nil
				}
			}
			if mode == "lite" {
				source.Mode = "lite"
			}
			if mode == "stopped" {
				source.Status = "stopped"
			}
			_, err := owner.prepareSources(context.Background(), d.Authority{TaskPublicID: "task", AttemptNo: 1}, []b.InstanceIdentity{source})
			if err == nil {
				t.Fatal("missing original Pod was accepted")
			}
			if mode == "approved" {
				if calls != 1 || len(client.Actions()) != 1 || client.Actions()[0].GetVerb() != "get" || client.Actions()[0].GetResource().Resource != "pods" || client.Actions()[0].GetNamespace() != source.Namespace {
					t.Fatalf("approved original source did not enter native preparation: calls=%d, actions=%v", calls, client.Actions())
				}
			} else if len(client.Actions()) != 0 || (mode == "owner-refuses" && calls != 1) || (mode != "owner-refuses" && calls != 0) {
				t.Fatalf("source rejection had effects: calls=%d, actions=%v", calls, client.Actions())
			}
		})
	}
}
