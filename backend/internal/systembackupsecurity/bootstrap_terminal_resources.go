package systembackupsecurity

import (
	"context"

	pd "clawreef/internal/systembackupproducer"
)

// BootstrapTerminalResource is one compiled concrete owner, not an Original
// authority or an operator-supplied approval. BindingSHA256 identifies its
// original controlled deployment mapping; it does not certify capabilities.
// Prepare observes real resources outside SQL. A missing/failed owner closes
// fresh use while terminal current-identity authorization remains separate.
type BootstrapTerminalResource interface {
	BootstrapResourceValidator
	TerminalKeys() []string
	BindingSHA256() (string, error)
	PrepareTerminalResource(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapTerminalResourceCheck, error)
}

type BootstrapTerminalResourceCheck interface {
	// L2 follows original admin/RBAC and capture owner, before operation lookup.
	// MinIO's concrete grouped owner locks head -> grant -> sorted five refs.
	// Use systembackupminioauthority's shared SQL codec/current reader; never
	// duplicate its SQL*Version/NUL signature domains in a terminal adapter.
	// Candidate-path authoritative time must share BootstrapSQL.SampleTime's
	// floor and failure latch, including reads inside that concrete reader.
	// No physical provider/Kube I/O belongs in either identity method.
	AuthorizeIdentity(context.Context, pd.BootstrapSQL) (*pd.Timestamp, error)
	RecheckIdentity(context.Context, pd.BootstrapReadSQL) error
	DependencyDeadline() *pd.Timestamp
	LockReferences(context.Context, pd.BootstrapSQL) error
	Recheck(context.Context, pd.BootstrapReadSQL) error
}
