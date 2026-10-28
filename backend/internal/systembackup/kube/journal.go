package kube

import (
	"context"
	"database/sql"
	"errors"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ResourceRows maps to the common controller's authoritative resource/Job
// repository. There is no additional task state or shadow cleanup inventory.
// Load must SELECT FOR UPDATE; writes must affect exactly one row. Missing rows
// return sql.ErrNoRows. Store and Fence MUST use the supplied transaction only.
type ResourceRows interface {
	Load(context.Context, *sql.Tx, ResourceIntent) (ResourceRecord, error)
	Insert(context.Context, *sql.Tx, ResourceRecord) error
	CAS(context.Context, *sql.Tx, int64, ResourceRecord) error
}

// SQLJournal provides transaction/fencing/CAS semantics independently of the
// shared schema's physical column names. Fence locks and validates the current
// controller lease/generation in the same DB transaction. A process-only check
// is insufficient. This adapter never creates tables, grants or credentials.
type SQLJournal struct {
	DB    *sql.DB
	Rows  ResourceRows
	Fence func(context.Context, *sql.Tx) error
}

func validateIntent(i ResourceIntent) bool {
	if len(i.RequestJSON) == 0 || len(i.RequestJSON) > 1<<20 {
		return false
	}
	var u unstructured.Unstructured
	if u.UnmarshalJSON(i.RequestJSON) != nil {
		return false
	}
	a := u.GetAnnotations()
	if a[RequestHashAnnotation] != i.RequestSHA256 {
		return false
	}
	delete(a, RequestHashAnnotation)
	u.SetAnnotations(a)
	// freeze omits an originally absent annotations map, so preserve that
	// canonical representation when this was the only annotation.
	if len(a) == 0 {
		u.SetAnnotations(nil)
	}
	validated, _, err := freeze(i.Kind, &u)
	return err == nil && sameIntent(validated, i)
}

func validRecord(r ResourceRecord) bool {
	if r.Revision <= 0 || len(r.UID) > 256 || len(r.ResourceVersion) > 256 || ((r.UID == "") != (r.ResourceVersion == "")) {
		return false
	}
	if r.UID != "" && !r.CreateDispatched {
		return false
	}
	if r.Deleting && (r.UID == "" || r.Deleted) {
		return false
	}
	return !(r.Deleted && r.UID == "" && r.CreateDispatched)
}

func (j SQLJournal) transact(ctx context.Context, i ResourceIntent, change func(ResourceRecord, bool) (ResourceRecord, bool, error)) (ResourceRecord, error) {
	if j.DB == nil || j.Rows == nil || j.Fence == nil || !validateIntent(i) {
		return ResourceRecord{}, ErrJournal
	}
	tx, err := j.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ResourceRecord{}, ErrJournal
	}
	defer tx.Rollback()
	if j.Fence(ctx, tx) != nil {
		return ResourceRecord{}, ErrJournal
	}
	current, err := j.Rows.Load(ctx, tx, i)
	missing := errors.Is(err, sql.ErrNoRows)
	if err != nil && !missing {
		return ResourceRecord{}, ErrJournal
	}
	if !missing && (!sameIntent(current.Intent, i) || !validRecord(current)) {
		return ResourceRecord{}, ErrOwnership
	}
	next, write, err := change(current, missing)
	if err != nil {
		return ResourceRecord{}, err
	}
	if !validRecord(next) || !sameIntent(next.Intent, i) {
		return ResourceRecord{}, ErrJournal
	}
	if write {
		if missing {
			err = j.Rows.Insert(ctx, tx, next)
		} else {
			err = j.Rows.CAS(ctx, tx, current.Revision, next)
		}
		if err != nil {
			return ResourceRecord{}, ErrJournal
		}
	}
	if j.Fence(ctx, tx) != nil || ctx.Err() != nil {
		return ResourceRecord{}, ErrJournal
	}
	if tx.Commit() != nil {
		return ResourceRecord{}, ErrJournal
	}
	return next, nil
}
func (j SQLJournal) Prepare(ctx context.Context, i ResourceIntent) (ResourceRecord, error) {
	return j.transact(ctx, i, func(current ResourceRecord, missing bool) (ResourceRecord, bool, error) {
		if !missing {
			return current, false, nil
		}
		i.RequestJSON = append([]byte(nil), i.RequestJSON...)
		return ResourceRecord{Intent: i, Revision: 1}, true, nil
	})
}
func sameRecord(a, b ResourceRecord) bool {
	return sameIntent(a.Intent, b.Intent) && a.Revision == b.Revision && a.CreateDispatched == b.CreateDispatched && a.UID == b.UID && a.ResourceVersion == b.ResourceVersion && a.Deleting == b.Deleting && a.Deleted == b.Deleted
}
func (j SQLJournal) mutate(ctx context.Context, old ResourceRecord, change func(*ResourceRecord) error) (ResourceRecord, error) {
	return j.transact(ctx, old.Intent, func(current ResourceRecord, missing bool) (ResourceRecord, bool, error) {
		if missing || !sameRecord(current, old) {
			return ResourceRecord{}, false, ErrJournal
		}
		if err := change(&current); err != nil {
			return ResourceRecord{}, false, err
		}
		current.Revision++
		if current.Revision <= old.Revision {
			return ResourceRecord{}, false, ErrJournal
		}
		return current, true, nil
	})
}
func (j SQLJournal) RecordCreate(ctx context.Context, r ResourceRecord) (ResourceRecord, error) {
	return j.mutate(ctx, r, func(n *ResourceRecord) error {
		if n.CreateDispatched || n.UID != "" || n.Deleting || n.Deleted {
			return ErrOwnership
		}
		n.CreateDispatched = true
		return nil
	})
}
func (j SQLJournal) Observe(ctx context.Context, r ResourceRecord, uid, rv string) (ResourceRecord, error) {
	return j.mutate(ctx, r, func(n *ResourceRecord) error {
		if !n.CreateDispatched || n.Deleted || uid == "" || rv == "" || (n.UID != "" && n.UID != uid) {
			return ErrOwnership
		}
		n.UID = uid
		n.ResourceVersion = rv
		return nil
	})
}
func (j SQLJournal) RecordDelete(ctx context.Context, r ResourceRecord) (ResourceRecord, error) {
	return j.mutate(ctx, r, func(n *ResourceRecord) error {
		if !n.CreateDispatched || n.UID == "" || n.Deleted {
			return ErrOwnership
		}
		n.Deleting = true
		return nil
	})
}
func (j SQLJournal) RecordAbsent(ctx context.Context, r ResourceRecord) error {
	_, err := j.mutate(ctx, r, func(n *ResourceRecord) error {
		if n.UID == "" && n.CreateDispatched {
			return ErrPending
		}
		n.Deleted = true
		n.Deleting = false
		return nil
	})
	return err
}
