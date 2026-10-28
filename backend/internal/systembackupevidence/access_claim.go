package systembackupevidence

import "context"

// Only the lifecycle can attach this capability, after its claim transaction
// commits. Seeing a live claim in SQL is not proof that this caller owns it.
// Authorities must also authenticate the producer/session/worker separately.
type evidenceAccessKey struct{}

type evidenceAccess struct {
	Kind, ID, Claim string
	RowVersion      int64
}

func withEvidenceAccess(ctx context.Context, kind string, r Record) context.Context {
	return context.WithValue(ctx, evidenceAccessKey{}, evidenceAccess{kind, r.Manifest.Identity.ID, r.Claim, r.RowVersion})
}

func evidenceAccessFrom(ctx context.Context, kind, id string) (evidenceAccess, bool) {
	a, ok := ctx.Value(evidenceAccessKey{}).(evidenceAccess)
	return a, ok && a.Kind == kind && a.ID == id && a.Claim != "" && a.RowVersion > 1
}
