package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

// Forward discovery retains its signed mount admission. Recovery can bind only
// the original authenticated task plan, even if its forward materials expired.
// RuntimeControl.BuildWriters still loads the exact original control rows, and
// every physical effect still requires the independent recovery grant.
func (s *DeploymentService) validateRuntimeWriterInventory(ctx context.Context, owner *PublicJobOwner, in d.Input, inventory b.SourceInventory, frozen []b.FrozenWriter) error {
	if s.validateRuntimeInventory(inventory) == nil {
		return nil
	}
	if frozen == nil || owner == nil || in.Authority.TaskType != "backup" {
		return d.ErrNotReady
	}
	original, _, discovery, err := owner.input(ctx, in.Authority, true)
	if err != nil {
		return err
	}
	if original.Authority != in.Authority || original.ProfileID != in.ProfileID || original.ProfileRevision != in.ProfileRevision {
		return d.ErrNotReady
	}
	return matchOriginalRuntimeInventory(inventory, frozen, discovery)
}

// discovery has already been opened by LoadRecoveryPlan under SQLRecoveryAuthority.
// Neither a current source with the same numeric ID nor a subset of writers can
// borrow the saved task's recovery authority.
func matchOriginalRuntimeInventory(inventory b.SourceInventory, frozen []b.FrozenWriter, discovery b.Discovery) error {
	var original b.SourceInventory
	if frozen == nil || len(frozen) == 0 || hash(discovery.Source) != discovery.SourceSHA256 ||
		json.Unmarshal(discovery.Source, &original) != nil || !reflect.DeepEqual(frozen, discovery.Writers) {
		return d.ErrNotReady
	}
	// LinuxProfile clones empty SQL slices to nil when binding its frozen plan.
	if len(original.Users) == 0 {
		original.Users = nil
	}
	if len(inventory.Users) == 0 {
		inventory.Users = nil
	}
	if len(original.Instances) == 0 {
		original.Instances = nil
	}
	if len(inventory.Instances) == 0 {
		inventory.Instances = nil
	}
	original.RuntimeTestScope = original.RuntimeTestScope.Clone()
	inventory.RuntimeTestScope = inventory.RuntimeTestScope.Clone()
	original.TeamFacts = team.CloneSourceFacts(original.TeamFacts)
	inventory.TeamFacts = team.CloneSourceFacts(inventory.TeamFacts)
	if !reflect.DeepEqual(inventory, original) {
		return d.ErrNotReady
	}
	return nil
}

// Recovery's inventory guard checks the entire authenticated saved plan before
// Pending/StopJob/Resume. It must not rediscover current capture parts or dereference
// the forward-only capture materials on a recovery-only controller restart.
func (s *DeploymentService) originalRecoveryInventory(ctx context.Context, in d.Input, discovery b.Discovery) error {
	if s.Runtime == nil || s.Runtime.Owner == nil || in.Authority.TaskType != "backup" {
		return d.ErrNotReady
	}
	original, _, saved, err := s.Runtime.Owner.input(ctx, in.Authority, true)
	if err != nil {
		return err
	}
	if original.Authority != in.Authority || original.ProfileID != in.ProfileID || original.ProfileRevision != in.ProfileRevision {
		return d.ErrNotReady
	}
	return matchOriginalRecoveryDiscovery(discovery, saved)
}

func matchOriginalRecoveryDiscovery(discovery, saved b.Discovery) error {
	if !reflect.DeepEqual(discovery, saved) {
		return d.ErrNotReady
	}
	return nil
}
