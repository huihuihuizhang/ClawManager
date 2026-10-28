package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// This concrete adapter covers the four task owners in published 067. Other
// owners require their own reviewed sources; no task deadline or installation
// is invented for staging, promotion, catalog or system evidence.
type SQLTaskDownloadOwnersConfig struct {
	Registry          SQLRegistry
	Sessions          *sec.SQLLoginSessions
	RegistryDirectory string
}
type SQLTaskDownloadOwners struct {
	c            SQLTaskDownloadOwnersConfig
	producer     bool
	producerRoot string
}

const taskDownloadPreviewCreatedSQL = `SELECT created_at FROM system_backup_v2_evidence WHERE public_id=? AND origin_installation_id=?`

var _ DownloadAdmissionOwners = (*SQLTaskDownloadOwners)(nil)
var _ SQLPolicy = (*SQLTaskDownloadOwners)(nil)

func NewSQLTaskDownloadOwners(c SQLTaskDownloadOwnersConfig) (*SQLTaskDownloadOwners, error) {
	if c.Registry.DB == nil || !installationPattern.MatchString(c.Registry.Installation) || c.Registry.ServerUUID == "" || c.Registry.Database == "" || c.Sessions == nil || !filepath.IsAbs(c.RegistryDirectory) || filepath.Clean(c.RegistryDirectory) != c.RegistryDirectory {
		return nil, ErrDownloadAdmissionNotReady
	}
	return &SQLTaskDownloadOwners{c: c}, nil
}

// Registry returns a purpose-specific download registry. It has no producer,
// deletion or audit-writing grant; those use separate reviewed policies.
func (s *SQLTaskDownloadOwners) Registry() SQLRegistry {
	if s == nil {
		return SQLRegistry{}
	}
	r := s.c.Registry
	r.Policy = s
	return r
}

func taskDownloadIdentity(r SQLRegistry, i Identity) bool {
	p := ownerPatterns[i.OwnerType]
	return taskTable(i.OwnerType) != "" && p != nil && p.MatchString(i.OwnerID) && i.Installation == r.Installation && idPattern.MatchString(i.ID)
}
func (s *SQLTaskDownloadOwners) checkDB(ctx context.Context, tx *sql.Tx) error {
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil {
		return ErrDownloadAdmissionNotReady
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != s.c.Registry.ServerUUID || database != s.c.Registry.Database {
		return ErrDownloadAdmissionNotReady
	}
	return nil
}
func (s *SQLTaskDownloadOwners) current(ctx context.Context, tx *sql.Tx, a sec.RegistrationActor) (*sec.SensitiveDownloadConfig, error) {
	if s.checkDB(ctx, tx) != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	r := s.c.Registry
	scope, err := sec.LockSensitiveDownloadNonceScope(ctx, tx, sec.DatabaseIdentity{ServerUUID: r.ServerUUID, Database: r.Database}, r.Installation)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	c, err := scope.LoadConfig(ctx, tx)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	a.SessionIssuedAt = a.SessionIssuedAt.UTC()
	a.SessionExpiresAt = a.SessionExpiresAt.UTC()
	if err = s.c.Sessions.CheckConfigMutationSession(ctx, tx, r.Installation, a, c.ObservedAt()); err != nil {
		if errors.Is(err, sec.ErrRegistrationPermission) {
			return nil, ErrDenied
		}
		return nil, ErrDownloadAdmissionNotReady
	}
	return c, nil
}
func (s *SQLTaskDownloadOwners) permissions(a sec.RegistrationActor, c *sec.SensitiveDownloadConfig, classification string) error {
	var pin sec.BootstrapRegistryRef
	for _, p := range c.Values().Registries() {
		if p.Kind == "rbac_bindings" {
			pin = p
		}
	}
	if pin.Kind == "" || permissions(classification) == nil {
		return ErrDownloadAdmissionNotReady
	}
	raw, err := (sec.RegistrationFiles{RegistryDirectory: s.c.RegistryDirectory}).RegistryBytes(pin.Kind, pin.Version, pin.SHA256)
	if err != nil {
		return ErrDownloadAdmissionNotReady
	}
	defer wipe(raw)
	if sec.AuthorizeEvidencePermissions(raw, pin.SHA256, pin.Version, s.c.Registry.Installation, a, permissions(classification)) != nil {
		return ErrDenied
	}
	return nil
}

type taskDownloadOwnerFacts struct {
	id, version                          int64
	installation, publicID, kind, schema string
	deadline, created                    time.Time
	manualHold, promotionHold            bool
}
type taskDownloadScanner interface{ Scan(...any) error }

func taskDownloadOwnerProjection(t taskDownloadTable) string {
	q := "id,origin_installation_id,public_id,task_type,schema_version,deadline_at,created_at,row_version,"
	if t.kind == "backup" {
		return q + "manual_hold,promotion_hold"
	}
	return q + "FALSE,FALSE"
}
func scanTaskDownloadOwner(row taskDownloadScanner, kind string) (taskDownloadOwnerFacts, error) {
	var f taskDownloadOwnerFacts
	if row.Scan(&f.id, &f.installation, &f.publicID, &f.kind, &f.schema, &f.deadline, &f.created, &f.version, &f.manualHold, &f.promotionHold) != nil {
		return f, ErrDenied
	}
	p := ownerPatterns[kind]
	if f.id < 1 || f.version < 1 || f.version > 9007199254740991 || f.kind != kind || f.schema != "system-backup-task.v1" || p == nil || !p.MatchString(f.publicID) || !installationPattern.MatchString(f.installation) || !downloadAdmissionContentTime(f.created) || !downloadAdmissionContentTime(f.deadline) || !f.created.Before(f.deadline) {
		return f, ErrIntegrity
	}
	return f, nil
}
func (s *SQLTaskDownloadOwners) task(ctx context.Context, tx *sql.Tx, i Identity) (taskDownloadOwnerFacts, error) {
	if !taskDownloadIdentity(s.c.Registry, i) {
		return taskDownloadOwnerFacts{}, ErrDownloadAdmissionNotReady
	}
	var table taskDownloadTable
	for _, t := range taskDownloadTables() {
		if t.kind == i.OwnerType {
			table = t
		}
	}
	f, err := scanTaskDownloadOwner(tx.QueryRowContext(ctx, "SELECT "+taskDownloadOwnerProjection(table)+" FROM "+table.table+" WHERE origin_installation_id=? AND public_id=?", i.Installation, i.OwnerID), table.kind)
	if err != nil {
		return f, err
	}
	if f.installation != i.Installation || f.publicID != i.OwnerID {
		return f, ErrDenied
	}
	return f, nil
}

func (s *SQLTaskDownloadOwners) owner(ctx context.Context, tx *sql.Tx, i Identity) (taskDownloadOwnerFacts, error) {
	if s.producer && i.OwnerType == "system" {
		h, err := s.producerOwner(ctx, tx, i, false, new(int))
		if err != nil {
			return taskDownloadOwnerFacts{}, err
		}
		created, _ := h.CreatedAt.Time()
		deadline, _ := h.OwnerWriteExpiresAt.Time()
		return taskDownloadOwnerFacts{created: created, deadline: deadline}, nil
	}
	return s.task(ctx, tx, i)
}

func (s *SQLTaskDownloadOwners) downloadIdentity(i Identity) bool {
	return taskDownloadIdentity(s.c.Registry, i) || s.producer && i.OwnerType == "system" && i.OwnerID == s.c.Registry.Installation && i.Installation == s.c.Registry.Installation && idPattern.MatchString(i.ID)
}

func (s *SQLTaskDownloadOwners) Preview(ctx context.Context, tx *sql.Tx, installation string, a sec.RegistrationActor, id string) (Record, error) {
	if s == nil || installation != s.c.Registry.Installation {
		return Record{}, ErrDenied
	}
	c, err := s.current(ctx, tx, a)
	if err != nil {
		return Record{}, err
	}
	if err = s.permissions(a, c, "public"); err != nil {
		return Record{}, err
	}
	if _, err = checkTaskDownloadReferenceSchema(ctx, tx); err != nil {
		return Record{}, err
	}
	// Read in the same snapshot as the manifest. Reject impossible owner/evidence
	// chronology before the manifest loader reaches chunk metadata.
	var created time.Time
	if tx.QueryRowContext(ctx, taskDownloadPreviewCreatedSQL, id, installation).Scan(&created) != nil || !downloadAdmissionContentTime(created) {
		return Record{}, ErrDenied
	}
	r, err := s.c.Registry.previewDownloadEvidence(ctx, tx, id, func(ctx context.Context, tx *sql.Tx, i Identity) (time.Time, error) {
		if err := s.permissions(a, c, i.Classification); err != nil {
			return time.Time{}, err
		}
		f, err := s.owner(ctx, tx, i)
		if err == nil && created.Before(f.created) {
			return time.Time{}, ErrIntegrity
		}
		return f.deadline, err
	}, false)
	if err != nil {
		return Record{}, err
	}
	f, err := s.owner(ctx, tx, r.Manifest.Identity)
	if err != nil {
		return Record{}, err
	}
	if !r.CreatedAt.Equal(created) || r.CreatedAt.Before(f.created) || !r.OwnerDeadline.Equal(f.deadline) {
		return Record{}, ErrIntegrity
	}
	if r.Manifest.Identity.OwnerType == "system" && s.matchProducer(ctx, tx, r) != nil {
		return Record{}, ErrIntegrity
	}
	return r, nil
}

func taskDownloadOwnerLockSQL(t taskDownloadTable, owner bool, locking bool) string {
	conditions := []string{}
	if owner {
		conditions = append(conditions, "public_id=?")
	}
	for _, c := range t.columns {
		conditions = append(conditions, c+"=?")
	}
	if len(conditions) == 0 {
		return ""
	}
	q := "SELECT " + taskDownloadOwnerProjection(t) + " FROM " + t.table + " WHERE origin_installation_id=? AND (" + strings.Join(conditions, " OR ") + ") ORDER BY id LIMIT 10001"
	if locking {
		q += " FOR UPDATE"
	}
	return q
}
func (s *SQLTaskDownloadOwners) lockTasks(ctx context.Context, tx *sql.Tx, i Identity, want, created time.Time, locking bool, count *int) error {
	found := s.producer && i.OwnerType == "system"
	for _, t := range taskDownloadTables() {
		own := t.kind == i.OwnerType
		q := taskDownloadOwnerLockSQL(t, own, locking)
		if q == "" {
			continue
		}
		args := []any{i.Installation}
		if own {
			args = append(args, i.OwnerID)
		}
		for range t.columns {
			args = append(args, i.ID)
		}
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return ErrDownloadAdmissionNotReady
		}
		var previous int64
		for rows.Next() {
			f, err := scanTaskDownloadOwner(rows, t.kind)
			if err != nil || f.installation != i.Installation || f.id <= previous || *count >= maxTaskDownloadReferences {
				rows.Close()
				return ErrIntegrity
			}
			previous = f.id
			*count++
			if own && f.publicID == i.OwnerID {
				if found || !want.IsZero() && !want.Equal(f.deadline) || !created.IsZero() && created.Before(f.created) {
					rows.Close()
					return ErrState
				}
				found = true
			}
		}
		err, closed := rows.Err(), rows.Close()
		if err != nil || closed != nil {
			return ErrDownloadAdmissionNotReady
		}
	}
	if !found {
		return ErrDenied
	}
	return nil
}
func (s *SQLTaskDownloadOwners) evidenceKey(ctx context.Context, tx *sql.Tx, i Identity) (int64, string, error) {
	if !s.downloadIdentity(i) {
		return 0, "", ErrDownloadAdmissionNotReady
	}
	var id int64
	var installation sql.NullString
	var owner, public, classification string
	if tx.QueryRowContext(ctx, taskDownloadEvidenceKeySQL, i.ID).Scan(&id, &installation, &owner, &public, &classification) != nil || id < 1 || !installation.Valid || installation.String != i.Installation || owner != i.OwnerType || public != i.OwnerID || permissions(classification) == nil || i.Classification != "" && i.Classification != classification {
		return 0, "", ErrDenied
	}
	return id, classification, nil
}
func (s *SQLTaskDownloadOwners) references(ctx context.Context, tx *sql.Tx, i Identity, want, created time.Time, locking bool) error {
	if s.checkDB(ctx, tx) != nil {
		return ErrDownloadAdmissionNotReady
	}
	id, _, err := s.evidenceKey(ctx, tx, i)
	if err != nil {
		return err
	}
	producers, err := checkTaskDownloadReferenceSchema(ctx, tx)
	if err != nil {
		return err
	}
	count := 0
	if err = lockTaskDownloadReferenceStage(ctx, tx, 3, i.Installation, i.ID, id, locking, &count); err != nil {
		return err
	}
	if err = s.producerReferenceStage(ctx, tx, producers, i, 3, locking, &count); err != nil {
		return err
	}
	if i.OwnerType == "system" {
		h, err := s.producerOwner(ctx, tx, i, locking, &count)
		if err != nil {
			return err
		}
		deadline, _ := h.OwnerWriteExpiresAt.Time()
		at, _ := h.CreatedAt.Time()
		if !want.IsZero() && !deadline.Equal(want) || !created.IsZero() && !at.Equal(created) {
			return ErrState
		}
	} else if err = s.producerReferenceStage(ctx, tx, producers, i, 4, locking, &count); err != nil {
		return err
	}
	if err = s.lockTasks(ctx, tx, i, want, created, locking, &count); err != nil {
		return err
	}
	if err = lockTaskDownloadReferenceStage(ctx, tx, 5, i.Installation, i.ID, id, locking, &count); err != nil {
		return err
	}
	return s.producerReferenceStage(ctx, tx, producers, i, 5, locking, &count)
}
func (s *SQLTaskDownloadOwners) LockOwnerReferences(ctx context.Context, tx *sql.Tx, r Record) error {
	if s == nil || !downloadAdmissionContentTime(r.OwnerDeadline) || !downloadAdmissionContentTime(r.CreatedAt) {
		return ErrDownloadAdmissionNotReady
	}
	if err := s.references(ctx, tx, r.Manifest.Identity, r.OwnerDeadline, r.CreatedAt, true); err != nil {
		return err
	}
	if r.Manifest.Identity.OwnerType == "system" {
		return s.matchProducer(ctx, tx, r)
	}
	return nil
}
func (s *SQLTaskDownloadOwners) Recheck(ctx context.Context, tx *sql.Tx, a sec.RegistrationActor, r Record) error {
	c, err := s.current(ctx, tx, a)
	if err != nil {
		return err
	}
	if err = s.permissions(a, c, r.Manifest.Identity.Classification); err != nil {
		return err
	}
	f, err := s.owner(ctx, tx, r.Manifest.Identity)
	if err != nil {
		return err
	}
	if r.CreatedAt.Before(f.created) || !r.OwnerDeadline.Equal(f.deadline) {
		return ErrState
	}
	if r.Manifest.Identity.OwnerType == "system" && s.matchProducer(ctx, tx, r) != nil {
		return ErrIntegrity
	}
	// No new owner/reference locks after evidence: these are independent reads
	// of the prefix ranges already held by LockOwnerReferences/LockScope.
	return s.references(ctx, tx, r.Manifest.Identity, r.OwnerDeadline, r.CreatedAt, false)
}

func (s *SQLTaskDownloadOwners) LockScope(ctx context.Context, tx *sql.Tx, installation string, i Identity) error {
	if s == nil || installation != s.c.Registry.Installation {
		return ErrDenied
	}
	a, ok := verifiedDownloadActorFrom(ctx, s.c.Registry)
	if !ok {
		return ErrDenied
	}
	c, err := s.current(ctx, tx, a)
	if err != nil {
		return err
	}
	_, classification, err := s.evidenceKey(ctx, tx, i)
	if err != nil {
		return err
	}
	if err = s.permissions(a, c, classification); err != nil {
		return err
	}
	return s.references(ctx, tx, i, time.Time{}, time.Time{}, true)
}
func (s *SQLTaskDownloadOwners) OwnerDeadline(ctx context.Context, tx *sql.Tx, i Identity) (time.Time, error) {
	if s.checkDB(ctx, tx) != nil {
		return time.Time{}, ErrDownloadAdmissionNotReady
	}
	f, err := s.owner(ctx, tx, i)
	return f.deadline, err
}
func (s *SQLTaskDownloadOwners) Authorize(ctx context.Context, tx *sql.Tx, a Actor, r Record, required []string) error {
	if s == nil {
		return ErrDenied
	}
	actor, ok := verifiedDownloadActorFrom(ctx, s.c.Registry)
	if !ok || downloadActor(actor) != a || !reflect.DeepEqual(required, permissions(r.Manifest.Identity.Classification)) {
		return ErrDenied
	}
	return s.Recheck(ctx, tx, actor, r)
}
func (*SQLTaskDownloadOwners) Admit(context.Context, *sql.Tx, Record, time.Time) error {
	return ErrDenied
}
func (*SQLTaskDownloadOwners) Deletable(context.Context, *sql.Tx, Record, time.Time) error {
	return ErrDenied
}
func (*SQLTaskDownloadOwners) Audit(context.Context, *sql.Tx, Audit) error { return ErrDenied }
