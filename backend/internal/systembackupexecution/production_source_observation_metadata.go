package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

// Inert metadata only. It neither grants a task nor proves a writer was stopped.
// Private fields cannot be supplied through JSON or a caller's passed flag.
type SourceMetadataObservation struct {
	inventory  *observedSourceInventory
	skills     worker.SkillObjectCaptureSpec
	deployment worker.ResourceCaptureSpec
	secrets    worker.ResourceCaptureSpec
	checkedAt  time.Time
	until      time.Time
	sha256     string
}

func (o SourceMetadataObservation) CheckedAt() time.Time  { return o.checkedAt }
func (o SourceMetadataObservation) ValidUntil() time.Time { return o.until }
func (o SourceMetadataObservation) SHA256() string        { return o.sha256 }

// ObserveSourceMetadata uses the same signed deployment/controller delegation,
// pinned CA/credentials and finite source readers as capture. It deliberately
// does not call task-scoped capture or registration with a fabricated Input.
func (s *DeploymentService) ObserveSourceMetadata(ctx context.Context) (SourceMetadataObservation, error) {
	var zero SourceMetadataObservation
	x, err := s.newSourceSQLObservation(ctx)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	return x.observeMetadata(ctx)
}

func (x *sourceSQLObservation) observeMetadata(ctx context.Context) (SourceMetadataObservation, error) {
	var zero SourceMetadataObservation
	before, err := x.observeInventory(ctx)
	if err != nil {
		return zero, err
	}
	access := x.metadataReadAccess()
	clients, err := access.openClients(ctx)
	if err != nil {
		return zero, err
	}
	defer clients.Close()
	skills, err := access.skillObjectMetadata(ctx, clients, before.source.Skills)
	if err != nil {
		return zero, err
	}
	deployment, secrets, err := access.resourceMetadata(ctx, clients)
	if err != nil {
		return zero, err
	}
	// Repeat actual finite source reads rather than treating a credential or an
	// initial response as continued identity/completeness proof.
	server, database, err := clients.Redis.Identity(ctx)
	if err != nil || server != x.delegation.service.captureMaterials.Discovery.Redis.ServerID || database != x.delegation.service.captureMaterials.Discovery.Redis.Policy.DB || access.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	lastSkills, err := access.skillObjectMetadata(ctx, clients, before.source.Skills)
	if err != nil || !reflect.DeepEqual(skills, lastSkills) {
		return zero, d.ErrNotReady
	}
	lastDeployment, lastSecrets, err := access.resourceMetadata(ctx, clients)
	if err != nil || !reflect.DeepEqual(deployment, lastDeployment) || !reflect.DeepEqual(secrets, lastSecrets) {
		return zero, d.ErrNotReady
	}
	after, err := x.observeInventory(ctx)
	if err != nil || before.sha256 != after.sha256 || !reflect.DeepEqual(before.sql.metadata, after.sql.metadata) || access.Recheck(ctx) != nil || !time.Now().Before(x.delegation.until) {
		return zero, d.ErrNotReady
	}
	raw, err := json.Marshal(struct {
		Inventory, Scope, Server string
		Database                 int
		Skills                   worker.SkillObjectCaptureSpec
		Deployment, Secrets      worker.ResourceCaptureSpec
	}{before.sha256, x.delegation.scope, server, database, skills, deployment, secrets})
	if err != nil || len(raw) > 8<<20 {
		return zero, d.ErrNotReady
	}
	return SourceMetadataObservation{inventory: after, skills: skills, deployment: deployment, secrets: secrets, checkedAt: after.sql.observedAt, until: x.delegation.until, sha256: hash(raw)}, nil
}
