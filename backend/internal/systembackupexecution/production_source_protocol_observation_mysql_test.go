package systembackupexecution

import (
	"context"
	"reflect"
	"runtime"
	"testing"
	"time"

	root "clawreef/internal/systembackup"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func sourceProtocolFixture(t *testing.T, empty bool) (*dOriginalSixPartTask, *sourceProtocolScenario) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux original staging paths and task-owned SAN/TLS MySQL")
	}
	scenario := newSourceProtocolScenario(t, empty)
	f := newTasklessProtocolBase(t, scenario)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scenario.installMetadata(ctx, t, f)
	verifySourceProtocolOriginalCollections(ctx, t, f, scenario.empty)
	if err := checkDOriginalCoreUnchanged(f.service, f.sealedCore); err != nil {
		t.Fatal("independent scenario core changed after its original signing", err)
	}
	var count int
	if f.db.QueryRow("SELECT COUNT(*) FROM instances WHERE id IN (7,9)").Scan(&count) != nil || count != 0 {
		t.Fatal("independent fixture borrowed or rewrote the original stopped case")
	}
	return f, scenario
}

// Actual restricted SQL + real TLS HTTP/RESP/S3/Kubernetes/native protocol
// parsing. Controlled declared running state is not deployed physical proof;
// no stop/resume/witness method or readiness/publication row is synthesized.
func TestSourceDependenciesIndependentAllRunningTLSMySQL(t *testing.T) {
	f, scenario := sourceProtocolFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	before := sourceObservationControlCounts(t, f)
	var ignored int
	if f.service.Source.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_backups").Scan(&ignored) == nil {
		t.Fatal("actual source role unexpectedly reads control task metadata")
	}
	facts, err := f.service.ObserveSourceDependencies(ctx)
	if err != nil || facts.WriterSHA256() == "" || facts.MetadataSHA256() == "" || facts.metadata.inventory == nil || !facts.CheckedAt().Before(facts.ValidUntil()) {
		t.Fatal("complete independent running source protocol observation", err)
	}
	source := facts.metadata.inventory.source
	assertSourceProtocolObservedCollections(ctx, t, f, false, source)
	if len(source.Users) != 1 || len(source.Instances) != 2 || source.Instances[0].ID != 107 || source.Instances[1].ID != 109 || len(source.TeamFacts.Teams) != 1 || len(source.Skills.Skills) != 1 || len(facts.metadata.skills.Objects) != 1 {
		t.Fatal("complete actual independently declared SQL/object collections changed")
	}
	for _, instance := range source.Instances {
		if instance.Status != "running" {
			t.Fatal("non-running source slipped through a positive scenario")
		}
	}
	scenario.mu.Lock()
	reads, mutations := map[string]int{}, scenario.mutations
	for key, value := range scenario.reads {
		reads[key] = value
	}
	scenario.mu.Unlock()
	if mutations != 0 || reads["GET /v1/backup/capabilities"] == 0 || reads["GET /v1/gateways/gw-107-5"] < 2 || reads["continued deployments"] == 0 || reads["continued configmaps"] == 0 || reads["GET /api/v1/persistentvolumes/source-pv"] == 0 {
		t.Fatal("actual native/TLS pagination/PV reads omitted or mutation attempted", reads, mutations)
	}
	if !reflect.DeepEqual(before, sourceObservationControlCounts(t, f)) {
		t.Fatal("observation created task/control rows")
	}
	var readiness int
	if f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_execution_readiness").Scan(&readiness) != nil || readiness != 0 {
		t.Fatal("taskless fixture supplied a positive readiness input")
	}
}

func TestSourceDependenciesIndependentEmptyTLSMySQL(t *testing.T) {
	f, scenario := sourceProtocolFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	before := sourceObservationControlCounts(t, f)
	facts, err := f.service.ObserveSourceDependencies(ctx)
	if err != nil || facts.WriterSHA256() == "" || facts.MetadataSHA256() == "" || facts.metadata.inventory == nil {
		t.Fatal("genuinely empty source collections did not reach successful EOF", err)
	}
	source := facts.metadata.inventory.source
	assertSourceProtocolObservedCollections(ctx, t, f, true, source)
	if len(source.Users) != 0 || len(source.Instances) != 0 || len(source.TeamFacts.Teams) != 0 || len(source.TeamFacts.Members) != 0 || len(source.Skills.Skills) != 0 || len(source.Skills.Blobs) != 0 || len(source.Skills.Versions) != 0 || len(facts.metadata.skills.Objects) != 0 || len(facts.metadata.secrets.Selections) != 0 {
		t.Fatal("empty source was produced by dropping nonempty source data")
	}
	// Required controller/platform/PVC/CA control objects remain accounted for
	// by real API census. They are not fabricated empty namespace observations.
	if len(facts.metadata.deployment.Selections) != 1 || facts.metadata.deployment.Selections[0].Name != "d-original-kms-ca" {
		t.Fatal("existing public CA control metadata was silently filtered")
	}
	scenario.mu.Lock()
	nativeCalls, mutations := scenario.reads["GET /v1/backup/capabilities"], scenario.mutations
	scenario.mu.Unlock()
	if nativeCalls != 0 || mutations != 0 || !reflect.DeepEqual(before, sourceObservationControlCounts(t, f)) {
		t.Fatal("empty actual writer set required invented native observation or mutated state")
	}
}

func TestSourceDependenciesIndependentOriginalDriftTLSMySQL(t *testing.T) {
	f, scenario := sourceProtocolFixture(t, false)
	baselineContext, finishBaseline := context.WithTimeout(context.Background(), 2*time.Minute)
	baseline, baselineErr := f.service.ObserveSourceDependencies(baselineContext)
	finishBaseline()
	if baselineErr != nil || baseline.WriterSHA256() == "" || baseline.MetadataSHA256() == "" || baseline.metadata.inventory == nil || len(baseline.metadata.inventory.source.Instances) != 2 {
		t.Fatal("same original fixture must first complete the positive observation", baselineErr)
	}
	for _, fault := range []string{"missing-participant", "unknown-controller", "metadata-permission", "metadata-rv", "writer-token", "native-permission", "native-generation", "final-metadata"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			scenario.mu.Lock()
			scenario.fault, scenario.version2 = fault, false
			scenario.events = map[string][]int{}
			scenario.mu.Unlock()
			defer func() {
				scenario.mu.Lock()
				scenario.fault, scenario.version2 = "", false
				delete(scenario.objects, "Deployment/backup/unknown-controller")
				scenario.mu.Unlock()
			}()
			if fault == "missing-participant" {
				if _, err := f.db.ExecContext(ctx, "DELETE FROM system_backup_participants WHERE scope=? AND participant_id='application-mutations'", f.service.Config.ApplicationScope); err != nil {
					t.Fatal(err)
				}
				var remaining int
				if f.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_participants WHERE scope=? AND participant_id='application-mutations'", f.service.Config.ApplicationScope).Scan(&remaining) != nil || remaining != 0 {
					t.Fatal("actual participant deletion was not visible in original SQL")
				}
				defer func() {
					if err := (root.Gate{DB: f.db}).RegisterParticipant(context.Background(), f.service.Config.ApplicationScope, "application-mutations"); err != nil {
						t.Error(err)
					}
				}()
			}
			if fault == "unknown-controller" {
				one := int32(1)
				if err := scenario.addObject(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "unknown-controller", Namespace: "backup", UID: "unknown-controller-uid", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: &one}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, ReadyReplicas: 1}}); err != nil {
					t.Fatal(err)
				}
			}
			before := sourceObservationControlCounts(t, f)
			facts, err := f.service.ObserveSourceDependencies(ctx)
			if err == nil || facts.WriterSHA256() != "" || facts.MetadataSHA256() != "" || facts.metadata.inventory != nil {
				t.Fatal("actual permission/pagination/native/final source drift accepted", fault, err)
			}
			if !reflect.DeepEqual(before, sourceObservationControlCounts(t, f)) {
				t.Fatal("failed source observation mutated task/control state")
			}
			scenario.mu.Lock()
			events := map[string][]int{}
			for key, values := range scenario.events {
				events[key] = append([]int{}, values...)
			}
			scenario.mu.Unlock()
			if fault == "final-metadata" {
				initial, trigger, changed := events["initial-metadata-response"], events["final-native-trigger"], events["final-metadata-response"]
				if len(initial) == 0 || len(trigger) != 1 || len(changed) == 0 || initial[len(initial)-1] >= trigger[0] || changed[0] <= trigger[0] {
					t.Fatal("final source change did not follow native state and subsequent metadata re-read", events)
				}
			} else if fault != "missing-participant" && len(events[fault]) == 0 {
				t.Fatal("declared protocol fault was never emitted on the actual observation path", fault, events)
			}
		})
	}
}
