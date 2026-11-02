package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// Reuse the actual SAN/TLS MySQL/source-role/full-schema fixture. Its API
// observations are finite protocol models, not live kubelet certification.
// Migration134's exact owner-reviewed census classification is a prerequisite;
// this fixture must not remove its two tables or relax the census to pass.
func sourceSQLObservationFixture(t *testing.T) (*dOriginalSixPartTask, *originalSourceMetadataAuthority) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux staging paths and the owned SAN/TLS SQL source fixture")
	}
	f := newDOriginalSixPartTaskWithOptions(t, dOriginalSixPartFixtureOptions{PublicationForward: true})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	authority := f.installOriginalMetadataSources(ctx, t)
	s := f.service
	client := f.owner.Client.(*kubefake.Clientset)
	pod, err := client.CoreV1().Pods(s.Config.Namespace).Get(ctx, s.controllerActor.PodName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Spec.Containers = []corev1.Container{{Name: s.Config.StagingLocation.Container, Image: s.Config.WorkerImage}}
	if _, err = client.CoreV1().Pods(s.Config.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	installPublicationStagingFixture(t, s, client, pod.Name)
	return f, authority
}

func sourceObservationControlCounts(t *testing.T, f *dOriginalSixPartTask) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_attempts", "system_backup_v2_operations", "system_backup_v2_evidence", "system_backup_v2_runtime_resources", "system_backup_v2_runtime_writers"} {
		var count int
		if f.db.QueryRow("SELECT COUNT(*) FROM "+table).Scan(&count) != nil {
			t.Fatal("owned control-row census", table)
		}
		out[table] = count
	}
	return out
}

func revokeSourceObservationGrant(t *testing.T, f *dOriginalSixPartTask) {
	t.Helper()
	p := f.service.captureMaterials.Discovery
	raw, err := os.ReadFile(p.GrantFile)
	var envelope signedSourceMetadataGrant
	var grant originalSourceMetadataGrant
	if err != nil || json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope.Record, &grant) != nil {
		t.Fatal("original source envelope")
	}
	grant.Revoked = true
	envelope.Record, _ = json.Marshal(grant)
	envelope.Signature = ed25519.Sign(f.metadataSigner, append([]byte(sourceMetadataGrantDomain), envelope.Record...))
	raw, _ = json.Marshal(envelope)
	if os.WriteFile(p.GrantFile, raw, 0600) != nil {
		t.Fatal("owned source grant revocation")
	}
}

func TestSourceSQLObservationActualLeastPrivilegeAndTaskBoundaryMySQL(t *testing.T) {
	f, capture := sourceSQLObservationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before := sourceObservationControlCounts(t, f)
	client := f.owner.Client.(*kubefake.Clientset)
	actionStart := len(client.Actions())
	observer, err := f.service.newSourceSQLObservation(ctx)
	if err != nil {
		t.Fatal("original deployment/source observation", err)
	}
	facts, err := observer.observe(ctx)
	if err != nil || facts == nil || !reflect.DeepEqual(facts.instances, f.sourceInventory.Instances) || len(facts.metadata.Images) != len(f.sourceInventory.Instances) || facts.server != f.server || facts.database != f.database || facts.inventorySHA256 == "" || !facts.observedAt.Before(facts.until) {
		t.Fatal("actual complete SQL source observation", err)
	}
	stopped := false
	for _, instance := range facts.instances {
		stopped = stopped || instance.ID == 9 && instance.Status == "stopped"
	}
	if !stopped {
		t.Fatal("original stopped fixture omitted; this is SQL data, not physical proof")
	}
	if facts.until.After(f.service.Forward.DeploymentBinding().ExpiresAt) || facts.until.After(observer.delegation.grant.Until) {
		t.Fatal("observation extended an original source/Forward window")
	}
	var ignored int
	if observer.source.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_backups").Scan(&ignored) == nil {
		t.Fatal("source reader unexpectedly has control-row access")
	}
	// Task lease loss closes CAPTURE, not the independent currently enabled
	// deployment metadata delegation. No fake task or replacement claim is used.
	if _, err := f.db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET controller_lease_expires_at=UTC_TIMESTAMP(6) WHERE public_id=?", f.publicID); err != nil {
		t.Fatal(err)
	}
	if capture.Recheck(ctx) == nil {
		t.Fatal("capture lost its original task gate")
	}
	if _, err := f.service.sourceMetadataAuthority(ctx, f.owner, d.Input{}); err == nil {
		t.Fatal("empty task admitted into capture")
	}
	if facts, err = observer.observe(ctx); err != nil || facts == nil {
		t.Fatal("actual deployment observation incorrectly borrowed task authority", err)
	}
	for _, action := range client.Actions()[actionStart:] {
		if action.GetVerb() != "get" {
			t.Fatal("SQL observation performed non-read Kubernetes action", action.GetVerb())
		}
	}
	if after := sourceObservationControlCounts(t, f); !reflect.DeepEqual(before, after) {
		t.Fatal("observation registered task/key-use/evidence/runtime work")
	}
}

func TestSourceSQLObservationRejectsRevocationAndIncompleteReadMySQL(t *testing.T) {
	f, _ := sourceSQLObservationFixture(t)
	s := f.service
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, fault := range []string{"disabled", "profile", "wrong-source-pool", "missing-business-read", "conditional-workbuddy", "interrupted-source-read", "expired", "canceled", "last-get-revocation"} {
		t.Run(fault, func(t *testing.T) {
			observer, err := s.newSourceSQLObservation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			readCtx := ctx
			switch fault {
			case "disabled":
				if _, err = f.db.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET last_effective_enabled=FALSE WHERE origin_installation_id=?", s.Config.InstallationID); err != nil {
					t.Fatal(err)
				}
				defer f.db.ExecContext(ctx, "UPDATE system_backup_v2_installation_state SET last_effective_enabled=TRUE WHERE origin_installation_id=?", s.Config.InstallationID)
			case "profile":
				raw, err := os.ReadFile(s.Config.ProfileFile)
				if err != nil {
					t.Fatal(err)
				}
				if os.WriteFile(s.Config.ProfileFile, []byte("{}"), 0600) != nil {
					t.Fatal("profile replacement")
				}
				defer os.WriteFile(s.Config.ProfileFile, raw, 0600)
			case "wrong-source-pool":
				original := s.Source
				s.Source = f.control
				defer func() { s.Source = original }()
				observer, err = s.newSourceSQLObservation(ctx)
				if err != nil {
					t.Fatal("fresh observer setup with changed pool", err)
				}
			case "missing-business-read":
				// Names are generated by this task-owned fixture, never HTTP input.
				if _, err = f.db.ExecContext(ctx, "REVOKE SELECT ON `"+f.database+"`.`users` FROM '"+s.Config.SourceUser+"'@'127.0.0.1'"); err != nil {
					t.Fatal(err)
				}
				defer f.db.ExecContext(ctx, "GRANT SELECT ON `"+f.database+"`.`users` TO '"+s.Config.SourceUser+"'@'127.0.0.1'")
			case "conditional-workbuddy":
				// The running instance now requires actual Linux UID provenance;
				// missing it must fail. Original stopped instance9 remains present.
				if _, err = f.db.ExecContext(ctx, "UPDATE instances SET type='workbuddy',instance_mode='lite',runtime_type='gateway',runtime_variant='linux',os_type='linux' WHERE id=7"); err != nil {
					t.Fatal(err)
				}
				for _, original := range f.sourceInventory.Instances {
					if original.ID == 7 {
						defer f.db.ExecContext(ctx, "UPDATE instances SET type=?,instance_mode=?,runtime_type=?,runtime_variant=?,os_type=? WHERE id=7", original.Type, original.Mode, original.Backend, original.Variant, original.OS)
					}
				}
			case "interrupted-source-read":
				s.Source.SetMaxOpenConns(1)
				connection, err := s.Source.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { connection.Close(); s.Source.SetMaxOpenConns(4) }()
				var stop context.CancelFunc
				readCtx, stop = context.WithCancel(ctx)
				defer stop()
				go func() { time.Sleep(20 * time.Millisecond); stop() }()
			case "expired":
				observer.delegation.until = time.Now().Add(-time.Second)
			case "canceled":
				var stop context.CancelFunc
				readCtx, stop = context.WithCancel(ctx)
				stop()
			case "last-get-revocation":
				client := f.owner.Client.(*kubefake.Clientset)
				armed := true
				client.PrependReactor("get", "serviceaccounts", func(action ktest.Action) (bool, kruntime.Object, error) {
					if armed && action.(ktest.GetAction).GetName() == s.captureMaterials.Discovery.SourceAPIServiceAccount {
						armed = false
						revokeSourceObservationGrant(t, f)
					}
					return false, nil, nil
				})
			}
			if facts, err := observer.observe(readCtx); err == nil || facts != nil {
				t.Fatal("revoked/changed/incomplete observation returned facts")
			}
		})
	}
}
