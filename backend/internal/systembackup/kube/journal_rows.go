package kube

import (
	"context"
	"database/sql"
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
	scope, created, load, insert, update string
}

var sqlColumn = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// NewMappedResourceRows generates parameterized MySQL statements against an
// explicit controller-owned schema mapping. "created" is for drill resources;
// "ready" is for staging resources. Job observation repositories may implement
// ResourceRows directly when their projection requires different SQL.
func NewMappedResourceRows(scope, table, created string, c ResourceColumns) (*MappedResourceRows, error) {
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
	r := &MappedResourceRows{scope: scope, created: created}
	r.load = "SELECT " + strings.Join(names[4:], ",") + " FROM " + table + " WHERE " + key + " FOR UPDATE"
	r.insert = "INSERT INTO " + table + " (" + strings.Join(names, ",") + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
	r.update = "UPDATE " + table + " SET " + names[7] + " = ?, " + names[8] + " = ?, " + names[9] + " = ?, " + names[10] + " = ?, " + names[11] + " = ? WHERE " + key + " AND " + names[7] + " = ? AND " + names[5] + " = ?"
	return r, nil
}
func (r *MappedResourceRows) Load(ctx context.Context, tx *sql.Tx, i ResourceIntent) (ResourceRecord, error) {
	if r == nil || tx == nil {
		return ResourceRecord{}, ErrJournal
	}
	n := ResourceRecord{Intent: ResourceIntent{Identity: Identity{Namespace: i.Identity.Namespace, Name: i.Identity.Name}, Kind: i.Kind}}
	var state string
	err := tx.QueryRowContext(ctx, r.load, r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name).Scan(&n.Intent.Identity.Owner, &n.Intent.RequestSHA256, &n.Intent.RequestJSON, &n.Revision, &n.CreateDispatched, &n.UID, &n.ResourceVersion, &state)
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
	return exactlyOne(tx.ExecContext(ctx, r.insert, r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name, i.Identity.Owner, i.RequestSHA256, i.RequestJSON, n.Revision, n.CreateDispatched, n.UID, n.ResourceVersion, r.lifecycle(n)))
}
func (r *MappedResourceRows) CAS(ctx context.Context, tx *sql.Tx, oldRevision int64, n ResourceRecord) error {
	if r == nil || tx == nil {
		return ErrJournal
	}
	i := n.Intent
	return exactlyOne(tx.ExecContext(ctx, r.update, n.Revision, n.CreateDispatched, n.UID, n.ResourceVersion, r.lifecycle(n), r.scope, i.Kind, i.Identity.Namespace, i.Identity.Name, oldRevision, i.RequestSHA256))
}
