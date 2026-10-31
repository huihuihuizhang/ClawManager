package publicadapter

import (
	"context"
	"encoding/json"

	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

// Only this post-RR boundary may do original remote source metadata reads.
// It cannot replace users/instances/Skills or the original Team SQL facts.
// Preflight remains SQL-only and does not call providers or construct Jobs.
func (p *LinuxProfile) freezeSources(ctx context.Context, in d.Input, source SourceInventory, writers []FrozenWriter) (SourceInventory, error) {
	if (p.cfg.FreezeSources == nil && p.cfg.FreezeSourcesWithWriters == nil) || in.Authority.TaskType != "backup" {
		return source, nil
	}
	var resolved *team.Inventory
	var metadata json.RawMessage
	var err error
	if p.cfg.FreezeSourcesWithWriters != nil {
		resolved, metadata, err = p.cfg.FreezeSourcesWithWriters(ctx, cloneInput(in), cloneSourceInventory(source), append([]FrozenWriter{}, writers...))
	} else {
		resolved, metadata, err = p.cfg.FreezeSources(ctx, cloneInput(in), cloneSourceInventory(source))
	}
	if err != nil || ctx.Err() != nil || len(metadata) < 2 || len(metadata) > 8<<20 || !json.Valid(metadata) {
		return SourceInventory{}, d.ErrNotReady
	}
	if source.TeamFacts != nil {
		users, owners := map[int]bool{}, map[int]int{}
		for _, id := range source.Users {
			users[id] = true
		}
		for _, instance := range source.Instances {
			owners[instance.ID] = instance.UserID
		}
		if resolved == nil || resolved.Validate(users, owners) != nil || !source.TeamFacts.MatchesInventory(*resolved) {
			return SourceInventory{}, d.ErrNotReady
		}
		source.Teams = team.CloneInventory(resolved)
	} else if resolved != nil {
		return SourceInventory{}, d.ErrNotReady
	}
	source.CaptureMetadata = append(json.RawMessage(nil), metadata...)
	return source, nil
}
