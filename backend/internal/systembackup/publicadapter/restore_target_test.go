package publicadapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

type targetProofFunc func(context.Context, d.Authority, RestoreTarget) error

func (f targetProofFunc) VerifyRestoreTarget(ctx context.Context, a d.Authority, x RestoreTarget) error {
	return f(ctx, a, x)
}

func TestRestoreTargetStructuralRulesNeverReplaceCurrentProof(t *testing.T) {
	f, _, _ := setup(t)
	a := f.in.Authority
	a.TaskType = "preflight"
	a.TaskPublicID = "spf_11111111-1111-4111-8111-111111111111"
	a.Phase = "preflight"
	source := SourceDatabase{Name: "synthetic_source", ServerUUID: "44444444-4444-4444-8444-444444444444"}
	target := RestoreTarget{SchemaVersion: "system-backup-b-restore-target.v1", Kind: "isolated_drill", InstallationID: a.InstallationID, MatrixKey: "k8s-single-node", Namespace: "cm-drill-b", NamespaceUID: "55555555-5555-4555-8555-555555555555", DatabaseName: "cm_drill_b", DatabaseServerUUID: source.ServerUUID, SchemaSHA256: strings.Repeat("a", 64), AdminPolicy: "replace_bootstrap_with_source_admin", StartPolicy: "stopped_tasks_disabled", IsolationEvidence: RelayEvidence{PublicID: "sev_isolation", SHA256: strings.Repeat("b", 64)}, Storage: []RestoreStorage{}}
	for _, name := range []string{"valid", "nil-proof", "revoked", "source-collision", "namespace", "installation", "starts-agent", "admin-policy", "hostpath-proof"} {
		t.Run(name, func(t *testing.T) {
			x := target
			s := source
			calls := 0
			var proof RestoreTargetProof = targetProofFunc(func(context.Context, d.Authority, RestoreTarget) error {
				calls++
				if name == "revoked" {
					return &Failure{"permission_denied"}
				}
				return nil
			})
			switch name {
			case "nil-proof":
				proof = nil
			case "source-collision":
				s.Name = x.DatabaseName
			case "namespace":
				x.Namespace = "production"
			case "installation":
				x.InstallationID = "installation_foreign"
			case "starts-agent":
				x.StartPolicy = "start"
			case "admin-policy":
				x.AdminPolicy = "keep-target"
			case "hostpath-proof":
				x.Storage = []RestoreStorage{{SourceMountSHA256: strings.Repeat("f", 64), Kind: "hostpath"}}
			}
			err := CheckRestoreTarget(context.Background(), a, x, s, proof)
			if name == "valid" {
				if err != nil || calls != 1 {
					t.Fatal(err, calls)
				}
			} else if err == nil {
				t.Fatal("invalid target accepted")
			}
			if name != "valid" && name != "revoked" && calls != 0 {
				t.Fatal("invalid descriptor reached proof owner")
			}
			if name == "nil-proof" && !errors.Is(err, d.ErrNotReady) {
				t.Fatal(err)
			}
		})
	}
}
