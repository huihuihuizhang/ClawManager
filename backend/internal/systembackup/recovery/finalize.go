package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
)

type Action struct {
	Request Request
	State   string
}

// Implementations atomically fence task/operation ownership, freeze bytes,
// close cancellation before Sent, and permit at most one unresolved action.
type Journal interface {
	Prepare(context.Context, Request) (Action, error)
	Sent(context.Context, Action) error
	Observe(context.Context, Action, string, Observation) error
}
type Finalizer struct {
	Store   AppendProvider
	Journal Journal
	Now     func() int64
}

func (f Finalizer) confirm(ctx context.Context, a Action, o Observation) error {
	r := a.Request
	if !o.decisive(r.Key, f.Now()) {
		return ErrUnavailable
	}
	if o.State == "absent" {
		// Before the native grant expires, an earlier in-flight PUT may arrive.
		if f.Now() < r.Deadline {
			return ErrUnavailable
		}
		if e := f.Journal.Observe(ctx, a, "absent", o); e != nil {
			return e
		}
		return ErrUnavailable
	}
	if o.Object.SHA256 != r.SHA256 || o.Object.Size != r.Size {
		_ = f.Journal.Observe(ctx, a, "conflict", o)
		return ErrConflict
	}
	b, e := readObject(ctx, f.Store, o.Object)
	if e != nil {
		return e
	}
	if !bytes.Equal(b, r.Payload) {
		_ = f.Journal.Observe(ctx, a, "conflict", o)
		return ErrConflict
	}
	return f.Journal.Observe(ctx, a, "present", o)
}

// Execute never resends an unresolved write after a takeover or lost response.
// The persisted request bytes, generation and deadline remain authoritative.
func (f Finalizer) Execute(ctx context.Context, r Request) error {
	if r.Validate() != nil || f.Store == nil || f.Journal == nil || f.Now == nil {
		return ErrContract
	}
	target := f.Store.Identity()
	if !target.valid() {
		return ErrUnavailable
	}
	if r.Target == (Reference{}) {
		r.Target = target
	}
	if r.Target != target {
		return ErrConflict
	}
	a, e := f.Journal.Prepare(ctx, r)
	if e != nil {
		return e
	}
	expected, _ := Marshal(r)
	actual, _ := Marshal(a.Request)
	if !bytes.Equal(expected, actual) {
		return ErrConflict
	}
	switch a.State {
	case "present":
		// Revalidate external bytes even after a confirmed local projection.
	case "request_sent", "provider_unreachable":
	case "prepared":
		if f.Now() >= r.Deadline {
			return ErrUnavailable
		}
		if e = f.Journal.Sent(ctx, a); e != nil {
			return e
		}
		a.State = "request_sent"
		o, e := f.Store.Create(ctx, r)
		if e == nil {
			return f.confirm(ctx, a, o)
		}
		_ = f.Journal.Observe(ctx, a, "provider_unreachable", Observation{})
		return ErrUnavailable
	case "conflict":
		return ErrConflict
	default:
		return ErrUnavailable
	}
	o, e := f.Store.Observe(ctx, r.Key)
	if e != nil {
		return ErrUnavailable
	}
	return f.confirm(ctx, a, o)
}

type Signer struct {
	ID, Version string
	Private     ed25519.PrivateKey
}

func FreezeRecord(r Record, signer Signer, trust Trust, action string, deadline int64) (Request, error) {
	key, e := r.Key()
	if e != nil {
		return Request{}, e
	}
	b, e := Seal(r, CatalogPurpose, signer.ID, signer.Version, signer.Private, trust)
	if e != nil {
		return Request{}, e
	}
	req := Request{ActionID: action, Key: key, SHA256: Hash(b), Size: int64(len(b)), Deadline: deadline, Generation: 1, Condition: "create-if-absent", Payload: b}
	return req, req.Validate()
}

// Registration is issued only after independent full artifact authentication.
// Functional-test artifacts cannot be registered by this entry point.
func (i Importer) Registration(ctx context.Context, r Registration, signer Signer, action string, deadline int64) (Request, error) {
	if i.Resolve == nil || i.Catalog.Now == nil || r.DecisionTime > i.Catalog.Now() || deadline <= i.Catalog.Now() {
		return Request{}, ErrContract
	}
	record := Record{Schema: Version, ID: RegistrationID(r.Identity), Type: "artifact_registered", Registration: &r}
	if _, e := record.Key(); e != nil {
		return Request{}, e
	}
	store, auth, e := i.Resolve(ctx, r.Locator, r.Bootstrap)
	if e != nil {
		return Request{}, ErrUnavailable
	}
	if _, e = verifyCore(ctx, store, auth, i.Catalog.Trust, r); e != nil {
		return Request{}, e
	}
	return FreezeRecord(record, signer, i.Catalog.Trust, action, deadline)
}

type DeletionProof struct {
	RegistrationID, RegistrationSHA256, PruneRun, CandidateSHA256, FirstActor string
	DeletedAt                                                                 int64
	Evidence                                                                  Reference
}
type PruneProof interface {
	// Must read the original frozen plan and DB deletion CAS in one consistent
	// fenced transaction, and prove ALL versions/delete markers are absent.
	VerifyDeleted(context.Context, Registration, DeletionProof) error
}

func Tombstone(ctx context.Context, r Record, recordHash string, p DeletionProof, proof PruneProof, signer Signer, trust Trust, action string, deadline int64) (Request, error) {
	if _, e := r.Key(); e != nil {
		return Request{}, e
	}
	if r.Registration == nil || r.Type != "artifact_registered" || proof == nil || p.RegistrationID != r.ID || p.RegistrationSHA256 != recordHash || !p.Evidence.valid() || p.DeletedAt < r.Registration.DecisionTime || p.DeletedAt >= deadline {
		return Request{}, ErrContract
	}
	if e := proof.VerifyDeleted(ctx, *r.Registration, p); e != nil {
		return Request{}, ErrUnavailable
	}
	d := Deletion{r.ID, recordHash, r.Registration.Locator, r.Registration.Core, p.PruneRun, p.CandidateSHA256, p.DeletedAt, p.FirstActor}
	return FreezeRecord(Record{Schema: Version, ID: "sbd_" + r.ID[4:], Type: "artifact_deleted", Deletion: &d}, signer, trust, action, deadline)
}
