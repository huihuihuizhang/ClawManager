package recovery

import (
	"context"
	"strconv"
)

// PublicationProofs are backed by the capture/verification and staging resource
// journals. They must never be implemented as unconditional booleans.
type PublicationProofs interface {
	PreCommit(context.Context, Manifest, Index) error
	Cleanup(context.Context, Identity) (Reference, error)
}
type PublishInput struct {
	Manifest               Manifest
	Index                  Index
	Locator                Locator
	Bootstrap              Bootstrap
	DecisionTime, Deadline int64
}
type PublicationResult struct {
	Core               Core
	Registration       *Record
	RegistrationObject Object
	LocalAcceptance    bool
}
type Publisher struct {
	Artifact                                        Finalizer
	Catalog                                         Finalizer
	Trust                                           Trust
	ManifestSigner, AcceptanceSigner, CatalogSigner Signer
	Proofs                                          PublicationProofs
	Authenticate                                    Authenticator
	Now                                             func() int64
}

func requestFor(id, key string, b []byte, deadline int64) Request {
	return Request{ActionID: id, Key: key, SHA256: Hash(b), Size: int64(len(b)), Deadline: deadline, Generation: 1, Condition: "create-if-absent", Payload: b}
}
func putFinal(ctx context.Context, f Finalizer, r Request) (Object, error) {
	if e := f.Execute(ctx, r); e != nil {
		return Object{}, e
	}
	o, e := f.Store.Observe(ctx, r.Key)
	if e != nil || !o.decisive(r.Key, f.Now()) || o.State != "present" || o.Object.SHA256 != r.SHA256 {
		return Object{}, ErrUnavailable
	}
	return o.Object, nil
}

// Publish consumes already sealed immutable data parts. It persists exact bytes
// through each Finalizer before any external send. Functional tasks never need
// an acceptance/catalog signer. A missing owner/part/proof cannot be skipped.
func (p Publisher) Publish(ctx context.Context, in PublishInput) (PublicationResult, error) {
	var out PublicationResult
	if p.Now == nil || p.Proofs == nil || p.Authenticate == nil || p.Artifact.Store == nil || in.Index.Validate() != nil || !in.Locator.valid() || in.Locator != p.Artifact.Store.Location() || !in.Bootstrap.valid() || in.DecisionTime > p.Now() {
		return out, ErrContract
	}
	m := in.Manifest
	indexRaw, e := Marshal(in.Index)
	if e != nil {
		return out, e
	}
	// A provisional immutable version permits validation before first write;
	// the provider's actual version replaces it before manifest bytes freeze.
	m.Index = Object{"artifact-index.json", "pending", int64(len(indexRaw)), Hash(indexRaw)}
	if m.Validate(in.Index) != nil {
		return out, ErrContract
	}
	if e = p.Proofs.PreCommit(ctx, m, in.Index); e != nil {
		return out, ErrUnavailable
	}
	if e = authenticateIndex(ctx, p.Artifact.Store, p.Authenticate, m, in.Index); e != nil {
		return out, e
	}
	base := m.Identity.Backup + "-" + strconv.FormatInt(m.Identity.Attempt, 10)
	out.Core.Index, e = putFinal(ctx, p.Artifact, requestFor(base+"-index", "artifact-index.json", indexRaw, in.Deadline))
	if e != nil {
		return out, e
	}
	m.Index = out.Core.Index
	manifest, e := Seal(m, ManifestPurpose, p.ManifestSigner.ID, p.ManifestSigner.Version, p.ManifestSigner.Private, p.Trust)
	if e != nil {
		return out, e
	}
	out.Core.Manifest, e = putFinal(ctx, p.Artifact, requestFor(base+"-manifest", "manifest.json", manifest, in.Deadline))
	if e != nil {
		return out, e
	}
	marker, e := Marshal(Marker{Version, m.Identity, Hash(manifest), m.Index.SHA256})
	if e != nil {
		return out, e
	}
	out.Core.Marker, e = putFinal(ctx, p.Artifact, requestFor(base+"-marker", "_COMMITTED", marker, in.Deadline))
	if e != nil {
		return out, e
	}
	cleanup, e := p.Proofs.Cleanup(ctx, m.Identity)
	if e != nil || !cleanup.valid() {
		return out, ErrUnavailable
	}
	if m.Purpose == "functional_test" {
		return out, nil
	}
	a, e := BuildAcceptance(m, in.Index, manifest, marker, cleanup, in.DecisionTime)
	if e != nil {
		return out, e
	}
	ab, e := Seal(a, AcceptancePurpose, p.AcceptanceSigner.ID, p.AcceptanceSigner.Version, p.AcceptanceSigner.Private, p.Trust)
	if e != nil {
		return out, e
	}
	out.Core.Acceptance, e = putFinal(ctx, p.Artifact, requestFor(base+"-acceptance", "_ACCEPTANCE", ab, in.Deadline))
	if e != nil {
		return out, e
	}
	out.LocalAcceptance = a.LocalAcceptance
	if !a.LocalAcceptance {
		return out, nil
	}
	matrix, _ := m.Identity.Matrix()
	h := Header{"Ed25519", p.AcceptanceSigner.ID, p.AcceptanceSigner.Version, AcceptancePurpose, Version}
	key, e := p.Trust.key(h)
	if e != nil {
		return out, e
	}
	r := Registration{m.Identity, matrix, in.Locator, out.Core, in.Bootstrap, Reference{h.KeyID, h.KeyVersion, Hash(key)}, in.DecisionTime}
	// Read and authenticate ALL immutable payloads before issuing registration.
	if _, e = verifyCore(ctx, p.Artifact.Store, p.Authenticate, p.Trust, r); e != nil {
		return out, e
	}
	record := Record{Schema: Version, ID: RegistrationID(m.Identity), Type: "artifact_registered", Registration: &r}
	req, e := FreezeRecord(record, p.CatalogSigner, p.Trust, base+"-registration", in.Deadline)
	if e != nil {
		return out, e
	}
	out.RegistrationObject, e = putFinal(ctx, p.Catalog, req)
	if e != nil {
		return out, e
	}
	out.Registration = &record
	return out, nil
}
