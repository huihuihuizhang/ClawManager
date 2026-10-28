package control

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"clawreef/internal/systembackup/recovery"
)

// SixDomainPlan is frozen before cancellation closes. Owner adapters supply
// actual six-part checkpoints; a two-domain Bundle cannot be cast to this type.
type SixDomainPlan struct {
	Input                                  recovery.PublishInput
	ArtifactProvider, CatalogProvider      recovery.Reference
	Cleanup                                recovery.Reference
	ManifestKey, AcceptanceKey, CatalogKey recovery.Reference
	Acceptance                             *AcceptanceEvidence `json:",omitempty"`
}

func sameDocument(a, b any) bool {
	x, e := recovery.Marshal(a)
	y, f := recovery.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func validateSixPlan(t Task, p SixDomainPlan) error {
	in := p.Input
	if in.Locator.Validate() != nil || in.Bootstrap.Validate() != nil {
		return ErrInvalid
	}
	if t.Request.Validate() != nil || t.Request.Kind != "backup" || in.Manifest.Identity.Backup != t.ID || in.Manifest.Purpose != t.Request.Purpose || in.Deadline != t.Deadline || in.DecisionTime < t.CreatedAt || in.DecisionTime > in.Deadline || p.ArtifactProvider.Validate() != nil || p.CatalogProvider.Validate() != nil || p.Cleanup.Validate() != nil || p.ManifestKey.Validate() != nil {
		return ErrInvalid
	}
	index, e := recovery.Marshal(in.Index)
	if e != nil {
		return ErrInvalid
	}
	m := in.Manifest
	m.Index = recovery.Object{Key: "artifact-index.json", Version: "pending", Size: int64(len(index)), SHA256: recovery.Hash(index)}
	if m.Validate(in.Index) != nil || validateAcceptancePlan(t, p) != nil {
		return ErrInvalid
	}
	return nil
}
func FreezeSixDomainPlan(ctx context.Context, v Vault, t Task, p SixDomainPlan) error {
	if t.Status != "validating" || validateSixPlan(t, p) != nil {
		return ErrInvalid
	}
	b, e := recovery.Marshal(p)
	if e != nil {
		return ErrInvalid
	}
	return v.Put(ctx, t, "six-domain-publication", "plan", b)
}

// CatalogAdmission binds every publication step to encrypted task intent and
// confirmed predecessors. Native provider capability checks remain mandatory
// at the provider boundary; this function cannot manufacture their evidence.
func CatalogAdmission(v Vault, trust recovery.Trust) func(context.Context, *sql.Tx, Task, recovery.Request) error {
	return func(ctx context.Context, tx *sql.Tx, t Task, r recovery.Request) error {
		if r.Validate() != nil || r.Generation != 1 {
			return ErrInvalid
		}
		sealed, e := readRecord(ctx, tx, t, "six-domain-publication")
		if e != nil {
			return ErrNotReady
		}
		raw, e := v.open(t, "six-domain-publication", "plan", sealed)
		if e != nil {
			return e
		}
		defer clear(raw)
		var p SixDomainPlan
		if json.Unmarshal(raw, &p) != nil || validateSixPlan(t, p) != nil || r.Deadline != t.Deadline {
			return ErrInvalid
		}
		if t.Request.Purpose == "acceptance" {
			if e := checkAcceptanceAuthorization(ctx, tx, v, t, p); e != nil {
				return e
			}
		}
		// No publication can race source compensation, a live capture worker, or
		// a closed mutation gate, including after a takeover.
		var pending int
		if tx.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM system_backup_pauses WHERE task_id=? AND resumed=FALSE)+(SELECT COUNT(*) FROM system_backup_maintenance WHERE task_id=? AND closed=TRUE)+"+pendingWorkersSQL, t.ID, t.ID, t.ID, t.ID).Scan(&pending) != nil || pending != 0 {
			return ErrNotReady
		}
		base := p.Input.Manifest.Identity.Backup + "-" + strconv.FormatInt(p.Input.Manifest.Identity.Attempt, 10)
		prior := func(suffix string) (recovery.Request, recovery.Observation, error) {
			var request, observation []byte
			var state string
			if tx.QueryRowContext(ctx, "SELECT request_json,action_state,observation_json FROM system_backup_catalog_actions WHERE task_id=? AND action_id=? FOR UPDATE", t.ID, base+suffix).Scan(&request, &state, &observation) != nil || state != "present" {
				return recovery.Request{}, recovery.Observation{}, ErrNotReady
			}
			var q recovery.Request
			var o recovery.Observation
			if json.Unmarshal(request, &q) != nil || json.Unmarshal(observation, &o) != nil || q.Validate() != nil || q.ActionID != base+suffix || q.Deadline != t.Deadline || q.Target != p.ArtifactProvider || o.ValidateOutcome(q, "present", o.ValidUntil) != nil {
				return q, o, ErrConflict
			}
			return q, o, nil
		}
		matches := func(suffix string, value any) error {
			if r.ActionID != base+suffix || !sameDocument(json.RawMessage(r.Payload), value) {
				return ErrConflict
			}
			return nil
		}
		if r.Key == "artifact-index.json" {
			if r.Target != p.ArtifactProvider {
				return ErrConflict
			}
			return matches("-index", p.Input.Index)
		}
		indexReq, index, e := prior("-index")
		if e != nil {
			return e
		}
		if r.Key == "manifest.json" {
			var m recovery.Manifest
			h, e := trust.Open(r.Payload, recovery.ManifestPurpose, &m)
			if e != nil || r.Target != p.ArtifactProvider || h.KeyID != p.ManifestKey.ID || h.KeyVersion != p.ManifestKey.Version {
				return ErrConflict
			}
			boundKey := false
			for _, key := range trust {
				if key.ID == h.KeyID && key.Version == h.KeyVersion && key.Purpose == h.Purpose && recovery.Hash(key.Public) == p.ManifestKey.SHA256 {
					boundKey = true
				}
			}
			if !boundKey {
				return ErrConflict
			}
			expected := p.Input.Manifest
			expected.Index = index.Object
			if !sameDocument(expected, m) {
				return ErrConflict
			}
			return matches("-manifest", json.RawMessage(r.Payload))
		}
		manifestReq, manifestObject, e := prior("-manifest")
		if e != nil {
			return e
		}
		if r.Key == "_COMMITTED" {
			if r.Target != p.ArtifactProvider {
				return ErrConflict
			}
			return matches("-marker", recovery.Marker{Schema: recovery.Version, Identity: p.Input.Manifest.Identity, ManifestSHA256: manifestReq.SHA256, IndexSHA256: indexReq.SHA256})
		}
		if t.Request.Purpose != "acceptance" {
			return ErrInvalid
		}
		markerReq, markerObject, e := prior("-marker")
		if e != nil {
			return e
		}
		m := p.Input.Manifest
		m.Index = index.Object
		var signedManifest recovery.Manifest
		if !sameDocument(json.RawMessage(indexReq.Payload), p.Input.Index) || boundSignature(trust, manifestReq.Payload, recovery.ManifestPurpose, p.ManifestKey, &signedManifest) != nil || !sameDocument(m, signedManifest) {
			return ErrConflict
		}
		expected, e := recovery.BuildAcceptance(m, p.Input.Index, manifestReq.Payload, markerReq.Payload, p.Cleanup, p.Input.DecisionTime)
		if e != nil {
			return ErrConflict
		}
		if r.Key == "_ACCEPTANCE" {
			var actual recovery.Acceptance
			if r.Target != p.ArtifactProvider || boundSignature(trust, r.Payload, recovery.AcceptancePurpose, p.AcceptanceKey, &actual) != nil || !sameDocument(actual, expected) {
				return ErrConflict
			}
			return matches("-acceptance", json.RawMessage(r.Payload))
		}
		acceptanceReq, acceptanceObject, e := prior("-acceptance")
		if e != nil {
			return e
		}
		var actual recovery.Acceptance
		if !expected.LocalAcceptance || boundSignature(trust, acceptanceReq.Payload, recovery.AcceptancePurpose, p.AcceptanceKey, &actual) != nil || !sameDocument(actual, expected) {
			return ErrConflict
		}
		matrix, _ := m.Identity.Matrix()
		record := recovery.Record{Schema: recovery.Version, ID: recovery.RegistrationID(m.Identity), Type: "artifact_registered", Registration: &recovery.Registration{Identity: m.Identity, Matrix: matrix, Locator: p.Input.Locator, Core: recovery.Core{Index: index.Object, Manifest: manifestObject.Object, Marker: markerObject.Object, Acceptance: acceptanceObject.Object}, Bootstrap: p.Input.Bootstrap, AcceptanceKey: p.AcceptanceKey, DecisionTime: p.Input.DecisionTime}}
		key, e := record.Key()
		var signed recovery.Record
		if e != nil || r.Key != key || r.Target != p.CatalogProvider || boundSignature(trust, r.Payload, recovery.CatalogPurpose, p.CatalogKey, &signed) != nil || !sameDocument(signed, record) {
			return ErrConflict
		}
		return matches("-registration", json.RawMessage(r.Payload))
	}
}

type SixDomainPublisher struct {
	Store              SQLStore
	Vault              Vault
	Publisher          recovery.Publisher
	AcceptanceVerifier AcceptanceVerifier
}

func (s SixDomainPublisher) Publish(ctx context.Context, t Task) error {
	raw, e := s.Vault.Get(ctx, t, "six-domain-publication", "plan")
	if e != nil {
		return e
	}
	defer clear(raw)
	var plan SixDomainPlan
	if json.Unmarshal(raw, &plan) != nil || validateSixPlan(t, plan) != nil {
		return ErrInvalid
	}
	if t.Request.Purpose == "acceptance" && (s.AcceptanceVerifier == nil || s.AcceptanceVerifier.VerifyAcceptance(ctx, t, plan) != nil) {
		return ErrNotReady
	}
	p := s.Publisher
	if e := checkPublisherKeys(p, plan, t.Request.Purpose); e != nil {
		return e
	}
	if p.Artifact.Store == nil || p.Catalog.Store == nil || p.Artifact.Store.Identity() != plan.ArtifactProvider || p.Catalog.Store.Identity() != plan.CatalogProvider {
		return ErrNotReady
	}
	if p.Proofs == nil {
		return ErrNotReady
	}
	p.Proofs = boundCleanup{p.Proofs, plan.Cleanup}
	j := CatalogActions{Store: s.Store, Task: t, Admission: CatalogAdmission(s.Vault, p.Trust)}
	p.Artifact.Journal = j
	p.Catalog.Journal = j
	result, e := p.Publish(ctx, plan.Input)
	if e != nil {
		return e
	}
	if t.Request.Purpose == "functional_test" && (result.Registration != nil || result.LocalAcceptance) {
		return ErrConflict
	}
	return s.commit(ctx, t, plan, result)
}

type boundCleanup struct {
	recovery.PublicationProofs
	expected recovery.Reference
}

func (b boundCleanup) Cleanup(ctx context.Context, id recovery.Identity) (recovery.Reference, error) {
	r, e := b.PublicationProofs.Cleanup(ctx, id)
	if e != nil || r != b.expected {
		return recovery.Reference{}, recovery.ErrUnavailable
	}
	return r, nil
}
func (s SixDomainPublisher) commit(ctx context.Context, t Task, p SixDomainPlan, result recovery.PublicationResult) error {
	tx, e := s.Store.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Store.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	var raw []byte
	var state string
	id := t.ID + "-" + strconv.FormatInt(p.Input.Manifest.Identity.Attempt, 10) + "-marker"
	if tx.QueryRowContext(ctx, "SELECT observation_json,action_state FROM system_backup_catalog_actions WHERE task_id=? AND action_id=? FOR UPDATE", t.ID, id).Scan(&raw, &state) != nil || state != "present" {
		return ErrNotReady
	}
	var observed recovery.Observation
	if json.Unmarshal(raw, &observed) != nil || observed.Object != result.Core.Marker {
		return ErrConflict
	}
	if t.Request.Purpose == "acceptance" {
		if e := s.checkAcceptanceResult(ctx, tx, t, p, result); e != nil {
			return e
		}
	}
	projection, e := recovery.Marshal(result)
	if e != nil {
		return ErrInvalid
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_recovery_publications(task_id,result_json) VALUES(?,?) ON DUPLICATE KEY UPDATE task_id=VALUES(task_id)", t.ID, projection)
	if e != nil {
		return ErrNotReady
	}
	if tx.QueryRowContext(ctx, "SELECT result_json FROM system_backup_recovery_publications WHERE task_id=? FOR UPDATE", t.ID).Scan(&raw) != nil || !bytes.Equal(raw, projection) {
		return ErrConflict
	}
	if s.Store.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
