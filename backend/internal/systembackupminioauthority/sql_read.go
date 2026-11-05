package systembackupminioauthority

import (
	"context"
	"database/sql"
	"reflect"
	"time"
)

// SQLReader is the caller's ORIGINAL controlled transaction/read view. It
// exposes no Exec/commit/network/provider capability and must not be replaced
// with a new DB connection. The concrete A guard owns context/tx sequencing.
type SQLReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type SQLRowState struct {
	State      string
	RowVersion uint64
}

// SQLCurrentSnapshot is current ORIGINAL SQL metadata, not physical resource
// readiness/admission. Verified declarations remain private and detached facts
// are copied. No provider evidence or ready bit can be supplied by a caller.
type SQLCurrentSnapshot struct {
	records   *SQLRecordSet
	expected  SQLExpected
	checkedAt time.Time
}

func (*SQLCurrentSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrRecord }
func (*SQLCurrentSnapshot) String() string               { return "OriginalMinIOSQLSnapshot" }

func sampleSQL(ctx context.Context, q SQLReader) (string, string, string, time.Time, error) {
	var account, server, database string
	var now time.Time
	if ctx == nil || ctx.Err() != nil || nilSQLReader(q) {
		return "", "", "", time.Time{}, ErrRecord
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return "", "", "", time.Time{}, ErrRecord
	}
	if controlled, ok := q.(ControlledSQLReader); ok {
		return sampleControlledSQL(ctx, controlled)
	}
	if q.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&account, &server, &database, &now) != nil || !validTime(now) {
		return "", "", "", time.Time{}, ErrRecord
	}
	return account, server, database, now, nil
}

func nilSQLReader(q SQLReader) bool {
	if q == nil {
		return true
	}
	v := reflect.ValueOf(q)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// ReadSQLCurrent is the concrete SELECT-only consumer source. All seven
// exact original rows use FOR SHARE, NEVER FOR UPDATE. It does no provider
// work, credential read/hash, transaction creation/completion or mutation.
func ReadSQLCurrent(ctx context.Context, q SQLReader, pin SQLTrustPin) (*SQLCurrentSnapshot, error) {
	return readSQLCurrent(ctx, q, pin, false)
}

// ReadSQLCurrentForInstaller retains the same FOR SHARE reader after the
// actual authenticated offline Installer has acquired the ordered exclusive
// locks. Its authenticated SQL account must match signed ORIGINAL installer
// identity, which differs from the consumer account. It cannot elevate a
// consumer's SQL account or acquire write locks on that consumer's behalf.
func ReadSQLCurrentForInstaller(ctx context.Context, q SQLReader, pin SQLTrustPin) (*SQLCurrentSnapshot, error) {
	return readSQLCurrent(ctx, q, pin, true)
}

func readSQLCurrent(ctx context.Context, q SQLReader, pin SQLTrustPin, installer bool) (*SQLCurrentSnapshot, error) {
	return readSQLCurrentRuntime(ctx, q, pin, installer, nil)
}
func readSQLCurrentRuntime(ctx context.Context, q SQLReader, pin SQLTrustPin, installer bool, use *runtimeMetadataSQLUse) (*SQLCurrentSnapshot, error) {
	if !validPin(pin) {
		return nil, ErrRecord
	}
	account, server, database, before, e := sampleSQL(ctx, q)
	if e != nil || server != pin.Target.ServerUUID || database != pin.Target.Database {
		return nil, ErrRecord
	}
	expectedAccount := pin.Target.ConsumerDatabaseAccount
	if use != nil {
		if installer || use.ctx != ctx || use.view != q || use.authority == nil || use.authority.CheckLocal() != nil || !reflect.DeepEqual(use.authority.descriptor.Pin, pin) {
			return nil, ErrRecord
		}
		expectedAccount = use.authority.record.RuntimeDatabaseAccount
	}
	if !installer && account != expectedAccount {
		return nil, ErrRecord
	}
	var revision, epoch, selectedRevision, headRow uint64
	var selectedID, state string
	var headSHA Digest
	var head, headSignature []byte
	if q.QueryRowContext(ctx, `SELECT head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version FROM system_backup_minio_owner_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? FOR SHARE`, pin.Target.InstallationID, pin.Enrollment.ID, pin.AuthorityID).Scan(&revision, &epoch, &selectedID, &selectedRevision, &headSHA, &head, &headSignature, &state, &headRow) != nil || !counter(headRow) || digest(head) != headSHA || selectedID != pin.GrantID || selectedRevision != pin.GrantRevision || len(head) > 262144 {
		return nil, ErrRecord
	}
	var grantEpoch, grantRow uint64
	var grantState string
	var grantSHA Digest
	var grant, grantSignature []byte
	if q.QueryRowContext(ctx, `SELECT permission_epoch,record_sha256,signed_record,signature,grant_state,row_version FROM system_backup_minio_owner_grants WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? FOR SHARE`, pin.Target.InstallationID, pin.Enrollment.ID, pin.AuthorityID, selectedID, selectedRevision).Scan(&grantEpoch, &grantSHA, &grant, &grantSignature, &grantState, &grantRow) != nil || !counter(grantRow) || digest(grant) != grantSHA || grantSHA != pin.GrantSHA256 || grantState != state || grantEpoch != epoch || len(grant) > 262144 {
		return nil, ErrRecord
	}
	refs := []SQLSignedReference{}
	refRows := []SQLReferenceCAS{}
	for _, purpose := range purposes() {
		var descriptor, provider, scope, identity, refSHA Digest
		var version, refState string
		var row uint64
		var raw, signature []byte
		if q.QueryRowContext(ctx, `SELECT descriptor_sha256,provider_identity_hash,scope_hash,identity_hash,identity_version,ref_sha256,signed_ref,signature,ref_state,row_version FROM system_backup_minio_owner_refs WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? AND purpose=? FOR SHARE`, pin.Target.InstallationID, pin.Enrollment.ID, pin.AuthorityID, selectedID, selectedRevision, string(purpose)).Scan(&descriptor, &provider, &scope, &identity, &version, &refSHA, &raw, &signature, &refState, &row) != nil || !counter(row) || digest(raw) != refSHA || refState != state || len(raw) > 65536 {
			return nil, ErrRecord
		}
		var r SQLReferenceRecord
		if decode(raw, 65536, &r) != nil || r.Reference.Purpose != purpose || r.Reference.DescriptorSHA256 != descriptor || r.Reference.ProviderIdentityHash != provider || r.Reference.ScopeSHA256 != scope || r.Reference.IdentityHash != identity || r.Reference.IdentityVersion != version {
			return nil, ErrRecord
		}
		refs = append(refs, SQLSignedReference{purpose, raw, signature})
		refRows = append(refRows, SQLReferenceCAS{purpose, refSHA, row})
	}
	records, e := VerifySQLRecordSet(pin, grant, grantSignature, head, headSignature, refs)
	if e != nil {
		return nil, ErrRecord
	}
	g, h := records.grant, records.head
	if h.HeadRevision != revision || h.PermissionEpoch != epoch || h.CurrentGrantID != selectedID || h.CurrentGrantRevision != selectedRevision || h.State != state || g.PermissionEpoch != grantEpoch {
		return nil, ErrRecord
	}
	if installer && account != g.Actor.InstallerDatabaseAccount {
		return nil, ErrRecord
	}
	// The original local actor's current identity is checked through the SAME
	// controlled transaction. A's current-admin/RBAC prefix already owns this
	// row before calling us; this is a same-row reread, not a new lock range.
	var username, role, provider string
	var active bool
	if q.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, g.Actor.LocalAdminUserID).Scan(&username, &role, &active, &provider) != nil || username != g.Actor.LocalAdminUsername || role != "admin" || !active || provider != "local" {
		return nil, ErrRecord
	}
	afterAccount, afterServer, afterDatabase, after, e := sampleSQL(ctx, q)
	if e != nil || account != afterAccount || server != afterServer || database != afterDatabase || after.Before(before) || ctx.Err() != nil {
		return nil, ErrRecord
	}
	return &SQLCurrentSnapshot{records: records, expected: SQLExpected{HeadRevision: revision, PermissionEpoch: epoch, HeadRowVersion: headRow, CurrentGrantID: selectedID, CurrentGrantRevision: selectedRevision, GrantRowVersion: grantRow, HeadSHA256: headSHA, GrantSHA256: grantSHA, ReferenceSetSHA256: g.ReferenceSetSHA256, State: state, ReferenceRows: refRows}, checkedAt: after}, nil
}

// Comparison returns detached exact CAS/state facts only. SQL live identity
// authorization and physical-observation deadlines remain separate decisions.
func (s *SQLCurrentSnapshot) Comparison() (SQLExpected, time.Time, error) {
	if s == nil || s.records == nil {
		return SQLExpected{}, time.Time{}, ErrRecord
	}
	e := s.expected
	e.ReferenceRows = append([]SQLReferenceCAS(nil), e.ReferenceRows...)
	return e, s.checkedAt, nil
}

func (s *SQLCurrentSnapshot) Declarations() (SQLGrant, SQLHead, []SQLReferenceRecord, error) {
	if s == nil || s.records == nil {
		return SQLGrant{}, SQLHead{}, nil, ErrRecord
	}
	return s.records.Detached()
}

// RequireCurrent checks CURRENT signed SQL identity/windows. It is not a
// fresh resource-use admission: Prepare's real private native capability and
// freshness observation must additionally be enforced by the concrete owner.
func (s *SQLCurrentSnapshot) RequireCurrent(now time.Time) error {
	if s == nil || s.records == nil || !validTime(now) || now.Before(s.checkedAt) || s.expected.State != StateActive {
		return ErrRecord
	}
	g, h := s.records.grant, s.records.head
	if now.Before(g.NotBefore) || !now.Before(g.Until) || now.Before(h.NotBefore) || !now.Before(h.Until) {
		return ErrRecord
	}
	for _, r := range s.records.references {
		if now.Before(r.Reference.NotBefore) || !now.Before(r.Reference.Until) || !now.Before(r.Reference.ProtectedUntil) {
			return ErrRecord
		}
	}
	return nil
}
