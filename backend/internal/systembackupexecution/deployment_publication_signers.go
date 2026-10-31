package systembackupexecution

import (
	"context"
	"database/sql"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

// Independent startup material input; no change to D's parent deployment
// config/Forward grant hashing and no use of a capture execution authority.
type PublicationSignerInput = s.PublicationSignerInput
type PublicationSignerRuntime = s.PublicationSignerRuntime
type PublicationSignerMaterials = s.PublicationSignerMaterials
type PublicationSigningMount = s.PublicationSigningMount

const PublicationSignerMaterialsVersion = s.PublicationSignerMaterialsVersion

type DeploymentPublicationSignerFactory struct {
	factory *s.SQLPublicationSignerFactory
}

func NewDeploymentPublicationSignerFactory(ctx context.Context, db *sql.DB, k kubernetes.Interface, runtime PublicationSignerRuntime, input PublicationSignerInput) (*DeploymentPublicationSignerFactory, error) {
	f, err := s.NewSQLPublicationSignerFactory(ctx, db, k, runtime, input)
	if err != nil {
		return nil, err
	}
	return &DeploymentPublicationSignerFactory{factory: f}, nil
}

// ForTask accepts the ORIGINAL acquired/renewed publisher token. No current
// claim is synthesized, cached or substituted when its row version changes.
func (f *DeploymentPublicationSignerFactory) ForTask(ctx context.Context, claim c.ClaimToken) (*s.SQLPublicationTaskSigners, error) {
	if f == nil || f.factory == nil || claim.Target.Kind != c.TargetBackup {
		return nil, c.ErrClaimLost
	}
	return f.factory.ForTask(ctx, claim.Target.PublicID, s.SQLSigningClaim{ControllerOwner: claim.Owner, RowVersion: claim.RowVersion})
}

func (f *DeploymentPublicationSignerFactory) History(ctx context.Context) (*s.ArtifactSigningKeyHistory, error) {
	if f == nil || f.factory == nil {
		return nil, c.ErrExecutionAuthority
	}
	return f.factory.History(ctx)
}
