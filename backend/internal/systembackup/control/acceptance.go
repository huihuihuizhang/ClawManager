package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/recovery"
)

// AcceptanceEvidence names immutable owner evidence, never a client supplied
// success flag. Verifiers must use independent read-only target credentials.
type AcceptanceEvidence struct {
	Policy, Proof, Target, KEK, ControlPlane recovery.Reference
	Verifiers                                map[string]recovery.Reference
}

// AcceptanceVerifier checks the evidence's actual content, identities, target
// failure domain, KEK recovery, all six independent verifiers and policy against
// the complete frozen plan. It is read-only, including during crash recovery.
// Missing owner implementations cannot be replaced with unconditional success.
type AcceptanceVerifier interface {
	VerifyAcceptance(context.Context, Task, SixDomainPlan) error
}

func validateAcceptancePlan(t Task, p SixDomainPlan) error {
	if t.Request.Purpose != "acceptance" {
		if p.Acceptance != nil {
			return ErrInvalid
		}
		return nil
	}
	a := p.Acceptance
	id := p.Input.Manifest.Identity
	if !strings.HasSuffix(p.Input.Locator.Prefix, "/"+id.Origin+"/"+id.Backup+"/"+strconv.FormatInt(id.Attempt, 10)) {
		return ErrInvalid
	}
	if a == nil || t.Request.AcceptancePolicy == nil || a.Policy != *t.Request.AcceptancePolicy || a.Policy.Validate() != nil || a.Proof.Validate() != nil || a.Target != p.Input.Manifest.Target.Attestation || a.KEK != p.Input.Bootstrap.KEK || a.ControlPlane != p.Input.Manifest.ControlPlane.Evidence || len(a.Verifiers) != 6 || p.AcceptanceKey.Validate() != nil || p.CatalogKey.Validate() != nil {
		return ErrInvalid
	}
	for _, name := range recovery.SixDomains() {
		if a.Verifiers[name].Validate() != nil {
			return ErrInvalid
		}
	}
	keys := []recovery.Reference{p.ManifestKey, p.AcceptanceKey, p.CatalogKey}
	for i, key := range keys {
		for _, other := range keys[:i] {
			if key.ID == other.ID || key.SHA256 == other.SHA256 {
				return ErrInvalid
			}
		}
	}
	return nil
}

type acceptanceAuthorization struct {
	Task, RequestSHA256, ProfileRevision, PlanSHA256 string
	Evidence                                         recovery.Reference
}

func acceptanceBinding(t Task, p SixDomainPlan) (acceptanceAuthorization, error) {
	if validateSixPlan(t, p) != nil || p.Acceptance == nil {
		return acceptanceAuthorization{}, ErrInvalid
	}
	b, e := recovery.Marshal(p)
	if e != nil {
		return acceptanceAuthorization{}, ErrInvalid
	}
	return acceptanceAuthorization{t.ID, t.Request.Hash(), t.ProfileRevision, recovery.Hash(b), p.Acceptance.Proof}, nil
}

// AuthorizeSixDomainAcceptance is called after freezing the plan and before
// leaving validating. The immutable receipt is also checked inside each SQL
// publication admission transaction; a signature alone cannot grant admission.
func AuthorizeSixDomainAcceptance(ctx context.Context, v Vault, t Task, p SixDomainPlan, verifier AcceptanceVerifier) error {
	if t.Status != "validating" || verifier == nil {
		return ErrNotReady
	}
	binding, e := acceptanceBinding(t, p)
	if e != nil {
		return e
	}
	if e = verifier.VerifyAcceptance(ctx, t, p); e != nil {
		return ErrNotReady
	}
	b, e := recovery.Marshal(binding)
	if e != nil {
		return ErrInvalid
	}
	return v.Put(ctx, t, "six-domain-acceptance", "authorization", b)
}

func checkAcceptanceAuthorization(ctx context.Context, tx *sql.Tx, v Vault, t Task, p SixDomainPlan) error {
	expected, e := acceptanceBinding(t, p)
	if e != nil {
		return e
	}
	sealed, e := readRecord(ctx, tx, t, "six-domain-acceptance")
	if e != nil {
		return ErrNotReady
	}
	b, e := v.open(t, "six-domain-acceptance", "authorization", sealed)
	if e != nil {
		return e
	}
	defer clear(b)
	var actual acceptanceAuthorization
	if json.Unmarshal(b, &actual) != nil || actual != expected {
		return ErrConflict
	}
	return nil
}

func boundSignature(trust recovery.Trust, raw []byte, purpose recovery.Purpose, key recovery.Reference, value any) error {
	h, e := trust.Open(raw, purpose, value)
	if e != nil || h.KeyID != key.ID || h.KeyVersion != key.Version {
		return ErrConflict
	}
	for _, k := range trust {
		if k.ID == h.KeyID && k.Version == h.KeyVersion && k.Purpose == purpose && recovery.Hash(k.Public) == key.SHA256 {
			return nil
		}
	}
	return ErrConflict
}

func checkPublisherKeys(p recovery.Publisher, plan SixDomainPlan, purpose string) error {
	keys := []struct {
		signer  recovery.Signer
		purpose recovery.Purpose
		ref     recovery.Reference
	}{{p.ManifestSigner, recovery.ManifestPurpose, plan.ManifestKey}}
	if purpose == "acceptance" {
		keys = append(keys, struct {
			signer  recovery.Signer
			purpose recovery.Purpose
			ref     recovery.Reference
		}{p.AcceptanceSigner, recovery.AcceptancePurpose, plan.AcceptanceKey}, struct {
			signer  recovery.Signer
			purpose recovery.Purpose
			ref     recovery.Reference
		}{p.CatalogSigner, recovery.CatalogPurpose, plan.CatalogKey})
	}
	for _, k := range keys {
		b, e := recovery.Seal(struct{}{}, k.purpose, k.signer.ID, k.signer.Version, k.signer.Private, p.Trust)
		var v struct{}
		if e != nil || boundSignature(p.Trust, b, k.purpose, k.ref, &v) != nil {
			return ErrNotReady
		}
	}
	return nil
}

func (s SixDomainPublisher) checkAcceptanceResult(ctx context.Context, tx *sql.Tx, t Task, p SixDomainPlan, result recovery.PublicationResult) error {
	base := t.ID + "-" + strconv.FormatInt(p.Input.Manifest.Identity.Attempt, 10)
	steps := []struct {
		suffix string
		object recovery.Object
	}{{"index", result.Core.Index}, {"manifest", result.Core.Manifest}, {"marker", result.Core.Marker}, {"acceptance", result.Core.Acceptance}}
	if result.LocalAcceptance {
		if result.Registration == nil {
			return ErrConflict
		}
		steps = append(steps, struct {
			suffix string
			object recovery.Object
		}{"registration", result.RegistrationObject})
	} else if result.Registration != nil || result.RegistrationObject != (recovery.Object{}) {
		return ErrConflict
	}
	var last recovery.Request
	for _, step := range steps {
		var raw, observation []byte
		var state string
		if tx.QueryRowContext(ctx, "SELECT request_json,action_state,observation_json FROM system_backup_catalog_actions WHERE task_id=? AND action_id=? FOR UPDATE", t.ID, base+"-"+step.suffix).Scan(&raw, &state, &observation) != nil || state != "present" {
			return ErrNotReady
		}
		var q recovery.Request
		var o recovery.Observation
		if json.Unmarshal(raw, &q) != nil || json.Unmarshal(observation, &o) != nil || q.ActionID != base+"-"+step.suffix || o.Object != step.object || o.ValidateOutcome(q, "present", o.ValidUntil) != nil {
			return ErrConflict
		}
		if step.suffix == "acceptance" {
			var a recovery.Acceptance
			if boundSignature(s.Publisher.Trust, q.Payload, recovery.AcceptancePurpose, p.AcceptanceKey, &a) != nil || a.LocalAcceptance != result.LocalAcceptance {
				return ErrConflict
			}
		}
		if step.suffix == "registration" {
			var r recovery.Record
			if boundSignature(s.Publisher.Trust, q.Payload, recovery.CatalogPurpose, p.CatalogKey, &r) != nil || !sameDocument(r, *result.Registration) {
				return ErrConflict
			}
		}
		last = q
	}
	return CatalogAdmission(s.Vault, s.Publisher.Trust)(ctx, tx, t, last)
}
