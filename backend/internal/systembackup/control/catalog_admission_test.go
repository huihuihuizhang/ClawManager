package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql/driver"
	"sort"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/recovery"
)

func sixPlanFixture(t *testing.T) (Task, SixDomainPlan, recovery.Trust, recovery.Signer) {
	t.Helper()
	task := testTask()
	task.Status, task.CreatedAt, task.Deadline, task.ProfileRevision = "publishing", 100, 2000, strings.Repeat("b", 64)
	ref := func(id string) recovery.Reference {
		return recovery.Reference{ID: id, Version: "v1", SHA256: strings.Repeat("a", 64)}
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	signer := recovery.Signer{ID: "manifest-key", Version: "v1", Private: key}
	trust := recovery.Trust{{ID: signer.ID, Version: signer.Version, Purpose: recovery.ManifestPurpose, Public: key.Public().(ed25519.PublicKey)}}
	id := recovery.Identity{Origin: "isolated-origin", Backup: task.ID, Attempt: 1, Orchestrator: "k8s", Profile: "cluster"}
	m := recovery.Manifest{Schema: recovery.Version, Identity: id, AppVersion: "v1", GitVersion: "abc", CreatedAt: 100, Purpose: "functional_test", MigrationHash: ref("x").SHA256, SchemaHash: ref("x").SHA256, CaptureHash: ref("x").SHA256, Config: ref("config"), SecretPolicy: ref("secrets"), SchemaCoverage: ref("schema"), Target: recovery.Target{Class: "same-cluster-copy", Risks: []string{}, Attestation: ref("target")}, Consistency: "strong", CommitMarker: "_COMMITTED", Parts: map[string]recovery.PartSummary{}, Domains: map[string]recovery.Summary{}, ControlPlane: recovery.Summary{Count: 1, Status: "passed", Evidence: ref("control")}, Warnings: []recovery.Warning{}}
	idx := recovery.Index{Schema: recovery.Version, Identity: id}
	for _, name := range append(recovery.RequiredParts(), "restore-metadata/envelope.json", "control/evidence.json.enc") {
		k := name
		if !strings.Contains(name, "/") {
			k += "/data.enc"
			m.Parts[name] = recovery.PartSummary{Status: "completed", Objects: []string{k}, Checkpoint: ref(name), Consistency: "strong"}
		}
		idx.Objects = append(idx.Objects, recovery.Object{Key: k, Version: "immutable-v1", Size: 16, SHA256: recovery.Hash([]byte(k))})
	}
	sort.Slice(idx.Objects, func(i, j int) bool { return idx.Objects[i].Key < idx.Objects[j].Key })
	for _, name := range recovery.SixDomains() {
		m.Domains[name] = recovery.Summary{Count: 1, Status: "passed", Evidence: ref(name)}
	}
	p := SixDomainPlan{Input: recovery.PublishInput{Manifest: m, Index: idx, Locator: recovery.Locator{Provider: "s3", Bucket: "fixture", Prefix: "isolated/backup", FailureDomain: "test"}, Bootstrap: recovery.Bootstrap{ReadCredential: ref("read"), CA: ref("ca"), KEK: ref("kek"), Identity: ref("identity")}, DecisionTime: 500, Deadline: task.Deadline}, ArtifactProvider: ref("artifact-provider"), CatalogProvider: ref("catalog-provider"), Cleanup: ref("cleanup"), ManifestKey: recovery.Reference{ID: signer.ID, Version: signer.Version, SHA256: recovery.Hash(trust[0].Public)}}
	if e := validateSixPlan(task, p); e != nil {
		t.Fatal(e)
	}
	return task, p, trust, signer
}

func TestCatalogAdmissionBindsFrozenPlanAndConfirmedPredecessors(t *testing.T) {
	for _, scenario := range []string{"index", "changed-index", "pending-writer", "manifest", "changed-key", "changed-manifest", "missing-index", "marker", "changed-marker", "acceptance-denied"} {
		t.Run(scenario, func(t *testing.T) {
			task, p, trust, signer := sixPlanFixture(t)
			v := testVault()
			if scenario == "changed-key" {
				p.ManifestKey.SHA256 = strings.Repeat("c", 64)
			}
			raw, _ := recovery.Marshal(p)
			sealed, e := v.seal(task, "six-domain-publication", "plan", raw)
			if e != nil {
				t.Fatal(e)
			}
			pending := int64(0)
			if scenario == "pending-writer" {
				pending = 1
			}
			steps := []sqlStep{recordStep(sealed), {contains: "system_backup_pauses", rows: [][]driver.Value{{pending}}}}
			request := func(suffix, key string, payload []byte) recovery.Request {
				return recovery.Request{ActionID: task.ID + "-1-" + suffix, Key: key, Size: int64(len(payload)), SHA256: recovery.Hash(payload), Payload: payload, Deadline: task.Deadline, Generation: 1, Condition: "create-if-absent", Target: p.ArtifactProvider}
			}
			indexRaw, _ := recovery.Marshal(p.Input.Index)
			index := request("index", "artifact-index.json", indexRaw)
			prior := func(q recovery.Request) (sqlStep, recovery.Object) {
				o := recovery.Object{Key: q.Key, Version: "confirmed-v1", Size: q.Size, SHA256: q.SHA256}
				b, _ := recovery.Marshal(q)
				obs, _ := recovery.Marshal(recovery.Observation{State: "present", Key: q.Key, Object: o, Strong: true, ValidUntil: 3000, Proof: p.Cleanup})
				return sqlStep{contains: "SELECT request_json,action_state,observation_json", rows: [][]driver.Value{{b, "present", obs}}}, o
			}
			r := index
			want := scenario == "index" || scenario == "manifest" || scenario == "marker"
			if scenario == "changed-index" {
				r.Payload = []byte(`{}`)
				r.Size = 2
				r.SHA256 = recovery.Hash(r.Payload)
			}
			if scenario != "index" && scenario != "changed-index" && scenario != "pending-writer" {
				step, o := prior(index)
				if scenario == "missing-index" {
					step.rows = nil
				}
				steps = append(steps, step)
				m := p.Input.Manifest
				m.Index = o
				if scenario == "changed-manifest" {
					m.AppVersion = "different"
				}
				mb, e := recovery.Seal(m, recovery.ManifestPurpose, signer.ID, signer.Version, signer.Private, trust)
				if e != nil {
					t.Fatal(e)
				}
				r = request("manifest", "manifest.json", mb)
				if scenario == "marker" || scenario == "changed-marker" || scenario == "acceptance-denied" {
					step, _ = prior(r)
					steps = append(steps, step)
					marker := recovery.Marker{Schema: recovery.Version, Identity: m.Identity, ManifestSHA256: r.SHA256, IndexSHA256: index.SHA256}
					if scenario == "changed-marker" {
						marker.Identity.Attempt++
					}
					b, _ := recovery.Marshal(marker)
					r = request("marker", "_COMMITTED", b)
					if scenario == "acceptance-denied" {
						r.Key = "_ACCEPTANCE"
					}
				}
			}
			store, script := scriptStore(t, steps...)
			tx, e := store.DB.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			e = CatalogAdmission(v, trust)(context.Background(), tx, task, r)
			if (e == nil) != want || script.writes != 0 {
				t.Fatalf("accepted=%v want=%v writes=%d error=%v", e == nil, want, script.writes, e)
			}
		})
	}
}

func TestSixDomainPlanCannotBroadenTaskPurpose(t *testing.T) {
	task, p, _, _ := sixPlanFixture(t)
	task.Request.Purpose = "acceptance"
	p.Input.Manifest.Purpose = "acceptance"
	if validateSixPlan(task, p) == nil {
		t.Fatal("owner widened functional API")
	}
}

func TestSixDomainCommitRequiresConfirmedMarkerAndImmutableProjection(t *testing.T) {
	for _, scenario := range []string{"success", "missing-marker", "different-projection", "lost-commit"} {
		t.Run(scenario, func(t *testing.T) {
			task, p, _, _ := sixPlanFixture(t)
			task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
			marker := recovery.Object{Key: "_COMMITTED", Version: "fixed-v1", Size: 2, SHA256: recovery.Hash([]byte(`{}`))}
			result := recovery.PublicationResult{Core: recovery.Core{Marker: marker}}
			b, _ := recovery.Marshal(result)
			observed, _ := recovery.Marshal(recovery.Observation{Object: marker})
			steps := workerCommit(task)
			row := sqlStep{contains: "SELECT observation_json,action_state", rows: [][]driver.Value{{observed, "present"}}}
			if scenario == "missing-marker" {
				row.rows = nil
			}
			steps = append(steps, row)
			if scenario != "missing-marker" {
				steps = append(steps, sqlStep{contains: "INSERT INTO system_backup_recovery_publications", affected: 1})
				stored := b
				if scenario == "different-projection" {
					stored = []byte(`{}`)
				}
				steps = append(steps, sqlStep{contains: "SELECT result_json", rows: [][]driver.Value{{stored}}})
				if scenario != "different-projection" {
					steps = append(steps, workerCommit(task)...)
				}
			}
			store, script := scriptStore(t, steps...)
			script.loseCommit = scenario == "lost-commit"
			e := (SixDomainPublisher{Store: store}).commit(context.Background(), task, p, result)
			if (e == nil) != (scenario == "success") {
				t.Fatal(scenario, e)
			}
			if scenario == "missing-marker" && script.writes != 0 {
				t.Fatal("projection before marker confirmation")
			}
			if scenario == "different-projection" && script.commits != 0 {
				t.Fatal("replaced immutable result")
			}
		})
	}
}
