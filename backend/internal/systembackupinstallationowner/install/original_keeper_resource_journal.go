package install

import (
	"context"
	"encoding/json"
	"reflect"

	"clawreef/internal/systembackup/kube"
)

// One adapter belongs to one keeper and serializes its CAS updates. The
// original append-only journal, not this struct, retains the resource state.
type originalKeeperResourceJournal struct {
	journal  *originalWriterJournal
	identity kube.Identity
	check    func(context.Context) error
}

var _ kube.ResourceJournal = (*originalKeeperResourceJournal)(nil)

func (j *originalKeeperResourceJournal) current(ctx context.Context) (kube.ResourceRecord, bool, error) {
	var out kube.ResourceRecord
	if j == nil || j.journal == nil || j.check == nil || j.check(ctx) != nil || j.identity.Owner != "adoption-"+j.journal.operation {
		return out, false, ErrInstall
	}
	j.journal.mu.Lock()
	defer j.journal.mu.Unlock()
	if j.journal.failed || j.journal.root == nil {
		return out, false, ErrInstall
	}
	inspection, err := j.journal.inspect(ctx, j.journal.operation, j.journal.inventory)
	if err != nil || inspection.TailSHA256 != j.journal.tail {
		return out, false, ErrInstall
	}
	found := false
	for _, event := range inspection.Records {
		if event.Writer != "keeper/"+j.identity.Namespace+"/"+j.identity.Name || event.Action != "longhorn_keeper_resource_record" {
			continue
		}
		var next kube.ResourceRecord
		if json.Unmarshal(event.Data, &next) != nil || next.Intent.Identity != j.identity || next.Intent.Kind != kube.LonghornKeeperResource || next.Revision != out.Revision+1 || found && !reflect.DeepEqual(next.Intent, out.Intent) {
			return out, false, ErrInstall
		}
		out, found = next, true
	}
	return out, found, nil
}

func (j *originalKeeperResourceJournal) save(ctx context.Context, record kube.ResourceRecord) (kube.ResourceRecord, error) {
	record.Revision++
	if j.check(ctx) != nil || j.journal.append(ctx, "keeper/"+j.identity.Namespace+"/"+j.identity.Name, "longhorn_keeper_resource_record", nil, record) != nil {
		return kube.ResourceRecord{}, ErrInstall
	}
	return record, nil
}

func (j *originalKeeperResourceJournal) Prepare(ctx context.Context, intent kube.ResourceIntent) (kube.ResourceRecord, error) {
	if j == nil || j.journal == nil {
		return kube.ResourceRecord{}, ErrInstall
	}
	j.journal.resourceMu.Lock()
	defer j.journal.resourceMu.Unlock()
	current, found, err := j.current(ctx)
	if err != nil || intent.Identity != j.identity || intent.Kind != kube.LonghornKeeperResource || !digestPattern.MatchString(intent.RequestSHA256) || len(intent.RequestJSON) == 0 {
		return kube.ResourceRecord{}, ErrInstall
	}
	if found {
		if !reflect.DeepEqual(current.Intent, intent) {
			return kube.ResourceRecord{}, ErrInstall
		}
		return current, nil
	}
	return j.save(ctx, kube.ResourceRecord{Intent: intent})
}

func (j *originalKeeperResourceJournal) update(ctx context.Context, expected kube.ResourceRecord, change func(*kube.ResourceRecord) bool) (kube.ResourceRecord, error) {
	if j == nil || j.journal == nil {
		return kube.ResourceRecord{}, ErrInstall
	}
	j.journal.resourceMu.Lock()
	defer j.journal.resourceMu.Unlock()
	current, found, err := j.current(ctx)
	if err != nil || !found || !reflect.DeepEqual(current, expected) || !change(&current) {
		return kube.ResourceRecord{}, ErrInstall
	}
	return j.save(ctx, current)
}

func (j *originalKeeperResourceJournal) RecordCreate(ctx context.Context, r kube.ResourceRecord) (kube.ResourceRecord, error) {
	return j.update(ctx, r, func(v *kube.ResourceRecord) bool {
		if v.CreateDispatched || v.Deleting || v.Deleted || v.UID != "" {
			return false
		}
		v.CreateDispatched = true
		return true
	})
}
func (j *originalKeeperResourceJournal) Observe(ctx context.Context, r kube.ResourceRecord, uid, rv string) (kube.ResourceRecord, error) {
	return j.update(ctx, r, func(v *kube.ResourceRecord) bool {
		if !v.CreateDispatched || v.Deleted || uid == "" || rv == "" || v.UID != "" && v.UID != uid {
			return false
		}
		v.UID, v.ResourceVersion = uid, rv
		return true
	})
}
func (j *originalKeeperResourceJournal) RecordDelete(ctx context.Context, r kube.ResourceRecord) (kube.ResourceRecord, error) {
	return j.update(ctx, r, func(v *kube.ResourceRecord) bool {
		if v.UID == "" || v.ResourceVersion == "" || v.Deleted || v.Deleting {
			return false
		}
		v.Deleting = true
		return true
	})
}
func (j *originalKeeperResourceJournal) RecordAbsent(ctx context.Context, r kube.ResourceRecord) error {
	_, err := j.update(ctx, r, func(v *kube.ResourceRecord) bool {
		if v.Deleted || v.CreateDispatched && v.UID == "" || v.UID != "" && !v.Deleting {
			return false
		}
		v.Deleted = true
		return true
	})
	return err
}
