package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Only the independent full GET plus a final original SQL snapshot can mint
// this receipt. A transport PUT/HEAD observation or copied object DTO cannot.
type publicationObjectReceipt struct {
	access  *security.SQLPublisherCaptureAuthority
	service *DeploymentService
	action  publicationJournalAction
	target  PublicationTargetMaterials
	object  nativePublicationObject
}

func (d *DeploymentService) publicationReceipt(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, action publicationJournalAction, object nativePublicationObject) (nativePublicationObject, error) {
	access, err := d.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return nativePublicationObject{}, err
	}
	// Finish ALL network/current workload reads before the final short SQL.
	if access.Check(ctx) != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	tx, err := d.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nativePublicationObject{}, errPublicationUnavailable
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return nativePublicationObject{}, err
	}
	if d.checkPublicationTargetTx(ctx, tx, guard.Facts(), target) != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	current, err := scanPublicationAction(tx.QueryRowContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND public_id=? FOR SHARE", d.Config.InstallationID, claim.Target.PublicID, action.ID))
	expectedVersion := action.Version
	if action.State != "confirmed_present" {
		expectedVersion++
	}
	if err != nil || current.Version != expectedVersion || current.LogicalSHA != action.LogicalSHA || current.Kind != action.Kind || current.Key != object.Key || !bytes.Equal(current.Payload, action.Payload) || current.State != "confirmed_present" || !current.ObjectVersion.Valid || current.ObjectVersion.String != object.Version || !current.ObjectSHA.Valid || current.ObjectSHA.String != object.SHA256 || current.Size != object.Size || guard.RecheckTx(ctx, tx) != nil {
		return nativePublicationObject{}, errPublicationUnavailable
	}
	if tx.Rollback() != nil {
		return nativePublicationObject{}, errPublicationUnavailable
	}
	receipt := &publicationObjectReceipt{access: access, service: d, action: current, target: target, object: object}
	object.receipt = receipt
	return object, nil
}

// The final consumer joins its SAME original task transaction. The receipt
// keeps its original current claim/window; a real Renew requires explicit new
// full readback and a new receipt, never silent adoption of the newer token.
func (object nativePublicationObject) recheckPublicationReceiptTx(ctx context.Context, tx *sql.Tx, claim c.ClaimToken) error {
	receipt := object.receipt
	if receipt == nil || receipt.access == nil || receipt.service == nil || object.Key != receipt.object.Key || object.Version != receipt.object.Version || object.Size != receipt.object.Size || object.SHA256 != receipt.object.SHA256 {
		return c.ErrExecutionAuthority
	}
	scope := receipt.access.Scope()
	if claim.Target.Kind != c.TargetBackup || claim.Target.PublicID != scope.BackupPublicID || claim.Owner != scope.Claim.ControllerOwner || claim.RowVersion != scope.Claim.RowVersion {
		return c.ErrClaimLost
	}
	guard, err := receipt.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	d := receipt.service
	// These checks are bounded local file/JSON/TLS-material checks, no network
	// and no nested SQL. The independently pinned target must still be original.
	store, err := d.publicationStore(ctx)
	if err != nil {
		return err
	}
	store.Close()
	if store.config != receipt.target || d.checkPublicationTargetTx(ctx, tx, guard.Facts(), receipt.target) != nil {
		return c.ErrExecutionAuthority
	}
	current, err := scanPublicationAction(tx.QueryRowContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND public_id=? FOR SHARE", d.Config.InstallationID, scope.BackupPublicID, receipt.action.ID))
	a := receipt.action
	if err != nil || current.Version != a.Version || current.State != "confirmed_present" || current.LogicalSHA != a.LogicalSHA || current.Key != object.Key || current.Size != object.Size || !bytes.Equal(current.Payload, a.Payload) || current.ObjectVersion != a.ObjectVersion || current.ObjectSHA != a.ObjectSHA || guard.RecheckTx(ctx, tx) != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}
