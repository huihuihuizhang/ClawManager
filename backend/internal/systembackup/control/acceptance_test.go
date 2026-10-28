package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"clawreef/internal/systembackup/recovery"
)

func acceptanceFixture(t *testing.T) (Task, SixDomainPlan, recovery.Trust, []recovery.Request, []recovery.Object) {
	return acceptanceFixtureFor(t, true)
}
func acceptanceFixtureFor(t *testing.T, eligible bool) (Task, SixDomainPlan, recovery.Trust, []recovery.Request, []recovery.Object) {
	t.Helper()
	task, p, trust, manifestSigner := sixPlanFixture(t)
	task.Request.Purpose = "acceptance"
	p.Input.Locator.Prefix = "isolated/" + p.Input.Manifest.Identity.Origin + "/" + task.ID + "/1"
	policy := p.Input.Manifest.Config
	policy.ID = "acceptance-policy"
	task.Request.AcceptancePolicy = &policy
	p.Input.Manifest.Purpose = "acceptance"
	p.Input.Manifest.Target.Class = "dr-ready-external"
	p.Input.Manifest.KEKRecoverable = true
	if !eligible {
		p.Input.Manifest.Target.Class = "same-cluster-copy"
	}
	p.Acceptance = &AcceptanceEvidence{Policy: policy, Proof: p.Cleanup, Target: p.Input.Manifest.Target.Attestation, KEK: p.Input.Bootstrap.KEK, ControlPlane: p.Input.Manifest.ControlPlane.Evidence, Verifiers: map[string]recovery.Reference{}}
	for _, name := range recovery.SixDomains() {
		ref := policy
		ref.ID = name + "-readonly-verifier"
		p.Acceptance.Verifiers[name] = ref
	}
	signers := []recovery.Signer{manifestSigner}
	for i, purpose := range []recovery.Purpose{recovery.AcceptancePurpose, recovery.CatalogPurpose} {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 10)}, 32))
		signer := recovery.Signer{ID: string(purpose), Version: "v1", Private: key}
		signers = append(signers, signer)
		trust = append(trust, recovery.TrustKey{ID: signer.ID, Version: signer.Version, Purpose: purpose, Public: key.Public().(ed25519.PublicKey)})
		ref := recovery.Reference{ID: signer.ID, Version: signer.Version, SHA256: recovery.Hash(key.Public().(ed25519.PublicKey))}
		if i == 0 {
			p.AcceptanceKey = ref
		} else {
			p.CatalogKey = ref
		}
	}
	var requests []recovery.Request
	var objects []recovery.Object
	add := func(suffix, key string, raw []byte, target recovery.Reference) {
		q := recovery.Request{ActionID: task.ID + "-1-" + suffix, Key: key, Payload: raw, Size: int64(len(raw)), SHA256: recovery.Hash(raw), Deadline: task.Deadline, Generation: 1, Condition: "create-if-absent", Target: target}
		requests = append(requests, q)
		objects = append(objects, recovery.Object{Key: key, Version: "immutable-v1", Size: q.Size, SHA256: q.SHA256})
	}
	idx, _ := recovery.Marshal(p.Input.Index)
	add("index", "artifact-index.json", idx, p.ArtifactProvider)
	m := p.Input.Manifest
	m.Index = objects[0]
	mb, e := recovery.Seal(m, recovery.ManifestPurpose, signers[0].ID, "v1", signers[0].Private, trust)
	if e != nil {
		t.Fatal(e)
	}
	add("manifest", "manifest.json", mb, p.ArtifactProvider)
	marker, _ := recovery.Marshal(recovery.Marker{Schema: recovery.Version, Identity: m.Identity, ManifestSHA256: requests[1].SHA256, IndexSHA256: requests[0].SHA256})
	add("marker", "_COMMITTED", marker, p.ArtifactProvider)
	a, e := recovery.BuildAcceptance(m, p.Input.Index, mb, marker, p.Cleanup, p.Input.DecisionTime)
	if e != nil {
		t.Fatal(e)
	}
	ab, e := recovery.Seal(a, recovery.AcceptancePurpose, signers[1].ID, "v1", signers[1].Private, trust)
	if e != nil {
		t.Fatal(e)
	}
	add("acceptance", "_ACCEPTANCE", ab, p.ArtifactProvider)
	matrix, _ := m.Identity.Matrix()
	record := recovery.Record{Schema: recovery.Version, ID: recovery.RegistrationID(m.Identity), Type: "artifact_registered", Registration: &recovery.Registration{Identity: m.Identity, Matrix: matrix, Locator: p.Input.Locator, Core: recovery.Core{Index: objects[0], Manifest: objects[1], Marker: objects[2], Acceptance: objects[3]}, Bootstrap: p.Input.Bootstrap, AcceptanceKey: p.AcceptanceKey, DecisionTime: p.Input.DecisionTime}}
	rb, e := recovery.Seal(record, recovery.CatalogPurpose, signers[2].ID, "v1", signers[2].Private, trust)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := record.Key()
	add("registration", key, rb, p.CatalogProvider)
	if validateSixPlan(task, p) != nil {
		t.Fatal("bad acceptance fixture")
	}
	return task, p, trust, requests, objects
}
func acceptancePrior(q recovery.Request, o recovery.Object, proof recovery.Reference) sqlStep {
	raw, _ := recovery.Marshal(q)
	obs, _ := recovery.Marshal(recovery.Observation{State: "present", Key: q.Key, Object: o, Proof: proof, Strong: true, ValidUntil: 3000})
	return sqlStep{contains: "SELECT request_json,action_state,observation_json", rows: [][]driver.Value{{raw, "present", obs}}}
}

func TestAcceptanceAdmissionRequiresFrozenAuthorizationAndExactSignedChain(t *testing.T) {
	for _, scenario := range []string{"index", "acceptance", "registration", "negative-acceptance", "ineligible-registration", "missing-auth", "changed-plan", "changed-request", "wrong-signing-key", "changed-payload", "missing-marker", "wrong-catalog-target", "functional-cannot-register"} {
		t.Run(scenario, func(t *testing.T) {
			task, p, trust, requests, objects := acceptanceFixtureFor(t, scenario != "negative-acceptance" && scenario != "ineligible-registration")
			v := testVault()
			binding, _ := acceptanceBinding(task, p)
			if scenario == "changed-plan" {
				p.Input.Manifest.GitVersion = "new-version"
			}
			if scenario == "changed-request" {
				binding.RequestSHA256 = recovery.Hash([]byte("other"))
			}
			if scenario == "functional-cannot-register" {
				task.Request.Purpose = "functional_test"
				task.Request.AcceptancePolicy = nil
				p.Acceptance = nil
				p.Input.Manifest.Purpose = "functional_test"
			}
			if scenario == "wrong-signing-key" {
				p.AcceptanceKey.SHA256 = recovery.Hash([]byte("untrusted"))
				binding, _ = acceptanceBinding(task, p)
			}
			plan, _ := recovery.Marshal(p)
			sealed, _ := v.seal(task, "six-domain-publication", "plan", plan)
			steps := []sqlStep{recordStep(sealed)}
			if scenario != "functional-cannot-register" {
				auth, _ := recovery.Marshal(binding)
				receipt, _ := v.seal(task, "six-domain-acceptance", "authorization", auth)
				if scenario == "missing-auth" {
					steps = append(steps, sqlStep{contains: "SELECT record_kind"})
				} else {
					steps = append(steps, recordStep(receipt))
				}
			}
			index := 4
			if scenario == "index" {
				index = 0
			}
			if scenario == "acceptance" || scenario == "negative-acceptance" || scenario == "wrong-signing-key" || scenario == "changed-payload" || scenario == "missing-marker" {
				index = 3
			}
			q := requests[index]
			early := scenario == "missing-auth" || scenario == "changed-plan" || scenario == "changed-request"
			if !early {
				steps = append(steps, sqlStep{contains: "system_backup_pauses", rows: [][]driver.Value{{int64(0)}}})
				for i := 0; i < index; i++ {
					if scenario == "functional-cannot-register" && i == 2 {
						break
					}
					step := acceptancePrior(requests[i], objects[i], p.Cleanup)
					if scenario == "missing-marker" && i == 2 {
						step.rows = nil
					}
					steps = append(steps, step)
				}
			}
			if scenario == "changed-payload" {
				q.Payload = []byte(`{}`)
				q.Size = 2
				q.SHA256 = recovery.Hash(q.Payload)
			}
			if scenario == "wrong-catalog-target" {
				q.Target = p.ArtifactProvider
			}
			store, script := scriptStore(t, steps...)
			tx, _ := store.DB.BeginTx(context.Background(), nil)
			defer tx.Rollback()
			e := CatalogAdmission(v, trust)(context.Background(), tx, task, q)
			want := scenario == "index" || scenario == "acceptance" || scenario == "negative-acceptance" || scenario == "registration"
			if (e == nil) != want || script.writes != 0 {
				t.Fatalf("accepted %v want %v: %v", e == nil, want, e)
			}
		})
	}
}

func TestAcceptanceTaskRequiresExplicitMatchingProfilePolicy(t *testing.T) {
	task, p, _, _, _ := acceptanceFixture(t)
	for _, scenario := range []string{"match", "missing", "different", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			profile := Profile{ID: task.Request.Profile, Revision: task.ProfileRevision, Kinds: []string{"backup"}, Ready: true, AcceptancePolicy: &p.Acceptance.Policy}
			if scenario == "missing" {
				profile.AcceptancePolicy = nil
			}
			if scenario == "different" {
				other := p.Acceptance.Policy
				other.Version = "v2"
				profile.AcceptancePolicy = &other
			}
			b, _ := json.Marshal(profile)
			steps := []sqlStep{{contains: "WHERE actor_id=? AND idempotency_key=? FOR UPDATE"}, {contains: "system_backup_profiles", rows: [][]driver.Value{{b, scenario != "expired"}}}}
			if scenario == "match" {
				steps = append(steps, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{int64(1000)}}}, sqlStep{contains: "INSERT INTO system_backup_tasks", affected: 1}, sqlStep{contains: "INSERT INTO system_backup_v2_events", affected: 1})
			}
			store, script := scriptStore(t, steps...)
			_, e := store.Create(context.Background(), 1, "acceptance-test", task.Request, time.Hour)
			if (e == nil) != (scenario == "match") || scenario != "match" && script.writes != 0 {
				t.Fatal(e)
			}
		})
	}
	for _, kind := range []string{"drill", "preflight", "catalog_import", "catalog_scan"} {
		r := task.Request
		r.Kind = kind
		if r.Validate() == nil {
			t.Fatal("acceptance widened to", kind)
		}
	}
}

type rejectAcceptance struct{ calls int }

func (v *rejectAcceptance) VerifyAcceptance(context.Context, Task, SixDomainPlan) error {
	v.calls++
	return ErrNotReady
}
func TestAcceptanceMissingOrRejectedEvidenceCannotAuthorize(t *testing.T) {
	task, p, _, _, _ := acceptanceFixture(t)
	task.Status = "validating"
	v := &rejectAcceptance{}
	if AuthorizeSixDomainAcceptance(context.Background(), testVault(), task, p, nil) == nil || AuthorizeSixDomainAcceptance(context.Background(), testVault(), task, p, v) == nil || v.calls != 1 {
		t.Fatal("missing evidence admitted")
	}
	p.Acceptance.Verifiers["teams"] = recovery.Reference{}
	if validateSixPlan(task, p) == nil {
		t.Fatal("missing independent domain verifier accepted")
	}
}

type acceptanceVerifierFunc func(context.Context, Task, SixDomainPlan) error

func (f acceptanceVerifierFunc) VerifyAcceptance(ctx context.Context, t Task, p SixDomainPlan) error {
	return f(ctx, t, p)
}
func TestAcceptanceAuthorizationRetryPinsOriginalEvidenceAndPlan(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-plan", true: "changed-plan"}[changed], func(t *testing.T) {
			task, p, _, _, _ := acceptanceFixture(t)
			task.Status = "validating"
			task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
			binding, _ := acceptanceBinding(task, p)
			raw, _ := recovery.Marshal(binding)
			v := testVault()
			sealed, _ := v.seal(task, "six-domain-acceptance", "authorization", raw)
			if changed {
				p.Input.Manifest.GitVersion = "changed"
			}
			store, script := scriptStore(t, readRecordSteps(task, sealed)...)
			v.Store = store
			calls := 0
			verifier := acceptanceVerifierFunc(func(context.Context, Task, SixDomainPlan) error { calls++; return nil })
			e := AuthorizeSixDomainAcceptance(context.Background(), v, task, p, verifier)
			if (e == nil) == changed || calls != 1 || script.writes != 0 {
				t.Fatal("authorization replaced after takeover", e)
			}
		})
	}
}

func TestAcceptanceResultCommitChecksAllConfirmedObjectsAndRegistration(t *testing.T) {
	for _, scenario := range []string{"complete", "missing-registration", "changed-core"} {
		t.Run(scenario, func(t *testing.T) {
			task, p, trust, requests, objects := acceptanceFixture(t)
			var record recovery.Record
			if _, e := trust.Open(requests[4].Payload, recovery.CatalogPurpose, &record); e != nil {
				t.Fatal(e)
			}
			result := recovery.PublicationResult{Core: record.Registration.Core, Registration: &record, RegistrationObject: objects[4], LocalAcceptance: true}
			if scenario == "changed-core" {
				result.Core.Index.Version = "replacement"
			}
			steps := []sqlStep{}
			for i := range requests {
				step := acceptancePrior(requests[i], objects[i], p.Cleanup)
				if scenario == "missing-registration" && i == 4 {
					step.rows = nil
				}
				steps = append(steps, step)
				if scenario == "changed-core" {
					break
				}
			}
			v := testVault()
			if scenario == "complete" {
				plan, _ := recovery.Marshal(p)
				sealed, _ := v.seal(task, "six-domain-publication", "plan", plan)
				binding, _ := acceptanceBinding(task, p)
				raw, _ := recovery.Marshal(binding)
				auth, _ := v.seal(task, "six-domain-acceptance", "authorization", raw)
				steps = append(steps, recordStep(sealed), recordStep(auth), sqlStep{contains: "system_backup_pauses", rows: [][]driver.Value{{int64(0)}}})
				for i := 0; i < 4; i++ {
					steps = append(steps, acceptancePrior(requests[i], objects[i], p.Cleanup))
				}
			}
			s, script := scriptStore(t, steps...)
			tx, _ := s.DB.BeginTx(context.Background(), nil)
			defer tx.Rollback()
			e := (SixDomainPublisher{Store: s, Vault: v, Publisher: recovery.Publisher{Trust: trust}}).checkAcceptanceResult(context.Background(), tx, task, p, result)
			if (e == nil) != (scenario == "complete") || script.writes != 0 {
				t.Fatal("unconfirmed publication accepted", e)
			}
		})
	}
}

func TestAcceptanceReportNeverTreatsTaskSuccessAsRestoreAuthorization(t *testing.T) {
	task, _, trust, requests, objects := acceptanceFixture(t)
	task.Status = "succeeded"
	var record recovery.Record
	_, _ = trust.Open(requests[4].Payload, recovery.CatalogPurpose, &record)
	result := recovery.PublicationResult{Core: record.Registration.Core, Registration: &record, RegistrationObject: objects[4], LocalAcceptance: true}
	raw, _ := recovery.Marshal(result)
	s, script := scriptStore(t, sqlStep{contains: "FROM system_backup_tasks", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT result_json", rows: [][]driver.Value{{raw}}})
	r, e := s.Report(context.Background(), task.ID)
	if e != nil || r.Acceptance == nil || !r.Acceptance.Registered || !r.Acceptance.LocalAcceptance || r.RecordID != record.ID || r.RestoreAuthorized || script.writes != 0 {
		t.Fatal(r, e)
	}
	b, _ := json.Marshal(r)
	if bytes.Contains(b, []byte("bootstrap")) || bytes.Contains(b, []byte("isolated-origin")) {
		t.Fatal("private publication data in report")
	}
}

func TestAcceptanceTerminalCannotUseLegacyFunctionalPublication(t *testing.T) {
	task, _, _, _, _ := acceptanceFixture(t)
	task.CanCancel = false
	task.LeaseUntil = time.Now().Add(time.Minute).UnixMilli()
	steps := append(workerCommit(task), sqlStep{contains: "FROM system_backup_tasks", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "system_backup_redis_items", rows: [][]driver.Value{{int64(0)}}}, sqlStep{contains: "SELECT result_json FROM system_backup_recovery_publications"})
	s, script := scriptStore(t, steps...)
	if _, e := s.Advance(context.Background(), task, "succeeded", ""); e == nil || script.writes != 0 {
		t.Fatal("missing acceptance result treated as functional success", e)
	}
}
