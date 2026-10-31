package kube

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
)

// ResourceColumns must be mapped by the shared schema owner. The resource key
// (Scope, Kind, Namespace, Name) requires a UNIQUE index, the table must be
// InnoDB, and row-version updates must be used by ALL writers. No defaults or
// automatic DDL are provided: this must not invent a competing public schema.
// Dispatched stores a create-dispatch intent, not a duplicate "created" flag.
type ResourceColumns struct {
	Scope, Kind, Namespace, Name, Owner, RequestHash, RequestJSON string
	Revision, Dispatched, UID, ResourceVersion, Lifecycle         string
}
type MappedResourceRows struct {
	scope, created, load, insert, update, conflict string
	attemptArgs                                    []any
}

var sqlColumn = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// NewMappedResourceRows generates parameterized MySQL statements against an
// explicit controller-owned schema mapping. "created" is for drill resources;
// "ready" is for staging resources. Job observation repositories may implement
// ResourceRows directly when their projection requires different SQL.
func NewMappedResourceRows(scope, table, created string, c ResourceColumns) (*MappedResourceRows, error) {
	return newMappedResourceRows(scope, table, created, c, nil)
}

// Public task resources have an original target/attempt/phase FK. Every read,
// insert and CAS binds those same coordinates; legacy tables keep their mapping.
func NewAttemptMappedResourceRows(scope, table, created string, c ResourceColumns, target string, attempt uint64, phase string) (*MappedResourceRows, error) {
	if !sqlColumn.MatchString(target) || attempt == 0 || !sqlColumn.MatchString(phase) {
		return nil, ErrJournal
	}
	return newMappedResourceRows(scope, table, created, c, []any{target, attempt, phase})
}

func newMappedResourceRows(scope, table, created string, c ResourceColumns, attemptArgs []any) (*MappedResourceRows, error) {
	if scope == "" || len(scope) > 256 || !sqlColumn.MatchString(table) || (created != "created" && created != "ready") {
		return nil, ErrJournal
	}
	names := []string{c.Scope, c.Kind, c.Namespace, c.Name, c.Owner, c.RequestHash, c.RequestJSON, c.Revision, c.Dispatched, c.UID, c.ResourceVersion, c.Lifecycle}
	seen := map[string]bool{}
	for idx, n := range names {
		if !sqlColumn.MatchString(n) || seen[n] {
			return nil, ErrJournal
		}
		seen[n] = true
		names[idx] = "`" + n + "`"
	}
	key := names[0] + " = ? AND " + names[1] + " = ? AND " + names[2] + " = ? AND " + names[3] + " = ?"
	table = "`" + table + "`"
	r := &MappedResourceRows{scope: scope, created: created, attemptArgs: append([]any{}, attemptArgs...)}
	extraNames, extraMarks := "", ""
	if len(attemptArgs) != 0 {
		for _, name := range []string{"target_type", "attempt_no", "phase"} {
			if seen[name] {
				return nil, ErrJournal
			}
		}
		r.conflict = "SELECT 1 FROM " + table + " WHERE " + key + " FOR UPDATE"
		key += " AND `target_type` = ? AND `attempt_no` = ? AND `phase` = ?"
		extraNames = ",`target_type`,`attempt_no`,`phase`"
		extraMarks = ",?,?,?"
	}
	r.load = "SELECT " + strings.Join(names[4:], ",") + " FROM " + table + " WHERE " + key + " FOR UPDATE"
	r.insert = "INSERT INTO " + table + " (" + strings.Join(names, ",") + extraNames + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?" + extraMarks + ")"
	r.update = "UPDATE " + table + " SET " + names[7] + " = ?, " + names[8] + " = ?, " + names[9] + " = ?, " + names[10] + " = ?, " + names[11] + " = ? WHERE " + key + " AND " + names[7] + " = ? AND " + names[5] + " = ?"
	return r, nil
}
func (r *MappedResourceRows) Load(ctx context.Context, tx *sql.Tx, i ResourceIntent) (ResourceRecord, error) {
	if r == nil || tx == nil {
		return ResourceRecord{}, ErrJournal
	}
	n := ResourceRecord{Intent: ResourceIntent{Identity: Identity{Namespace: i.Identity.Namespace, Name: i.Identity.Name}, Kind: i.Kind}}
	var state string
	args := append([]any{r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name}, r.attemptArgs...)
	err := tx.QueryRowContext(ctx, r.load, args...).Scan(&n.Intent.Identity.Owner, &n.Intent.RequestSHA256, &n.Intent.RequestJSON, &n.Revision, &n.CreateDispatched, &n.UID, &n.ResourceVersion, &state)
	if errors.Is(err, sql.ErrNoRows) && r.conflict != "" {
		// A shadowed dispatched row must NEVER become an Undispatched proof.
		// Recheck the original PK under the same lock before reporting absence.
		var exists int
		conflict := tx.QueryRowContext(ctx, r.conflict, r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name).Scan(&exists)
		if !errors.Is(conflict, sql.ErrNoRows) {
			return ResourceRecord{}, ErrJournal
		}
	}
	if err != nil {
		return ResourceRecord{}, err
	}
	switch state {
	case "creating":
		if n.UID != "" {
			return ResourceRecord{}, ErrJournal
		}
	case r.created:
		if n.UID == "" || !n.CreateDispatched {
			return ResourceRecord{}, ErrJournal
		}
	case "deleting":
		n.Deleting = true
		if n.UID == "" || !n.CreateDispatched {
			return ResourceRecord{}, ErrJournal
		}
	case "absent":
		n.Deleted = true
		if n.UID != "" || n.CreateDispatched {
			return ResourceRecord{}, ErrJournal
		}
	case "deleted":
		n.Deleted = true
		if n.UID == "" || !n.CreateDispatched {
			return ResourceRecord{}, ErrJournal
		}
	default:
		return ResourceRecord{}, ErrJournal // shared ownership_unknown/delete_failed needs its own resolver
	}
	return n, nil
}
func (r *MappedResourceRows) lifecycle(n ResourceRecord) string {
	if n.Deleted {
		if n.UID == "" {
			return "absent"
		}
		return "deleted"
	}
	if n.Deleting {
		return "deleting"
	}
	if n.UID != "" {
		return r.created
	}
	return "creating"
}
func exactlyOne(result sql.Result, err error) error {
	if err != nil {
		return ErrJournal
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrJournal
	}
	return nil
}
func (r *MappedResourceRows) Insert(ctx context.Context, tx *sql.Tx, n ResourceRecord) error {
	if r == nil || tx == nil {
		return ErrJournal
	}
	i := n.Intent
	args := append([]any{r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name, i.Identity.Owner, i.RequestSHA256, i.RequestJSON, n.Revision, n.CreateDispatched, n.UID, n.ResourceVersion, r.lifecycle(n)}, r.attemptArgs...)
	return exactlyOne(tx.ExecContext(ctx, r.insert, args...))
}
func (r *MappedResourceRows) CAS(ctx context.Context, tx *sql.Tx, oldRevision int64, n ResourceRecord) error {
	if r == nil || tx == nil {
		return ErrJournal
	}
	i := n.Intent
	args := append([]any{n.Revision, n.CreateDispatched, n.UID, n.ResourceVersion, r.lifecycle(n), r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name}, r.attemptArgs...)
	args = append(args, oldRevision, i.RequestSHA256)
	return exactlyOne(tx.ExecContext(ctx, r.update, args...))
}
