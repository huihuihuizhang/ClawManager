package systembackupconfig

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// Location is a locked SQL observation, never a historical provider read grant.
// Resolve the exact retained evidence_store/KEK purpose mappings independently;
// do not select a default/current key or trust manifest assertions as authority.
type ConfigMutationResponseLocation struct{ snapshot responseReplaySnapshot }

func (l ConfigMutationResponseLocation) External() bool { return l.snapshot.State == "ready" }
func (l ConfigMutationResponseLocation) Manifest() ev.Manifest {
	m := l.snapshot.Manifest
	m.Chunks = append([]ev.Chunk(nil), m.Chunks...)
	return m
}
func (l ConfigMutationResponseLocation) Reference() ev.Ref { return l.snapshot.Ref }
func (l ConfigMutationResponseLocation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrConfigMutation
}

type ConfigMutationResponseReadResources struct {
	Root       string
	Store, KEK ev.KeyRef
	Reader     ev.VerifiedObjectReader
	Keys       ev.Keys
}

// Prepare performs any provider/policy resolution outside SQL locks. Recheck
// must verify the same current read/session/revocation and historical-purpose
// authority using only the supplied transaction, without network I/O or commit.
// A typed preparation or SQL Location cannot substitute for this live guard.
type ConfigMutationResponseReplayAuthority interface {
	Prepare(context.Context, sec.ConfigMutationResponseReplayPreparation, ConfigMutationResponseLocation) (ConfigMutationResponseReadAccess, error)
}
type ConfigMutationResponseReadAccess interface {
	Resources() ConfigMutationResponseReadResources
	ValidUntil() time.Time
	Recheck(context.Context, *sql.Tx, time.Time) error
}

type SQLConfigMutationResponseReader struct {
	db           *sql.DB
	database     sec.DatabaseIdentity
	installation string
	authority    ConfigMutationResponseReplayAuthority
}

func NewSQLConfigMutationResponseReader(db *sql.DB, database sec.DatabaseIdentity, installation string, authority ConfigMutationResponseReplayAuthority) (*SQLConfigMutationResponseReader, error) {
	if db == nil || !validDatabase(database) || !installationIDPattern.MatchString(installation) || isNil(authority) {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &SQLConfigMutationResponseReader{db, database, installation, authority}, nil
}

// All fields, including SQL NULL shape, row version and complete chunk index,
// are frozen for final equality. This is not a public serialization profile.
type responseReplaySnapshot struct {
	OperationStarted, OperationCreated, OperationFinished                      time.Time
	OperationRowVersion                                                        int64
	ID                                                                         int64
	Schema, PublicID, OwnerType, Owner, Kind, State, Failure, Health           string
	Inline                                                                     []byte
	Checksum                                                                   string
	Size                                                                       int64
	Media, Classification, Encryption                                          string
	Expires, Created                                                           time.Time
	RowVersion                                                                 int64
	Role, StoreIdentity, StoreVersion, RelativeKey, RelativeKeyHash, Immutable sql.NullString
	ObjectHash                                                                 sql.NullString
	ObjectSize, ChunkSize                                                      sql.NullInt64
	Count                                                                      int64
	Root, Framing, KEKIdentity, KEKVersion, Envelope                           sql.NullString
	Manifest                                                                   ev.Manifest
	Ref                                                                        ev.Ref
}

func (s responseReplaySnapshot) fingerprint() string {
	raw, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return registrationHash(string(raw))
}

func responseReplayClock(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	var offset int64
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&now, &offset) != nil || now.IsZero() || offset != 0 || time.Since(now) > 5*time.Second || time.Until(now) > 5*time.Second {
		return time.Time{}, sec.ErrRegistrationUnavailable
	}
	return now.UTC(), nil
}
func loadResponseReplaySnapshot(ctx context.Context, tx *sql.Tx, in sec.ConfigMutationResponseReplayPreparation, now time.Time) (responseReplaySnapshot, error) {
	f := in.Facts()
	s := responseReplaySnapshot{}
	fail := func() (responseReplaySnapshot, error) {
		return responseReplaySnapshot{}, sec.ErrRegistrationUnavailable
	}
	if ctx == nil || ctx.Err() != nil || tx == nil || !sessionAt(f.Actor, now) || now.Before(f.AuthorizedAt) || !now.Before(f.ValidUntil) || checkDatabase(ctx, tx, f.Database) != nil {
		return fail()
	}
	var operation, hash, status, responseHash, targetType, targetID, kind string
	var code, version, evidenceID int64
	err := tx.QueryRowContext(ctx, `SELECT public_id,request_hash,status,http_status,result_config_version,redacted_response_evidence_id,redacted_response_sha256,target_type,target_public_id,operation_type,started_at,created_at,finished_at,row_version FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? AND public_id=? FOR UPDATE`, f.Installation, strconv.FormatInt(f.Actor.UserID, 10), f.Endpoint, f.IdempotencyKey, f.Operation).Scan(&operation, &hash, &status, &code, &version, &evidenceID, &responseHash, &targetType, &targetID, &kind, &s.OperationStarted, &s.OperationCreated, &s.OperationFinished, &s.OperationRowVersion)
	if err != nil || operation != f.Operation || hash != f.RequestHash || status != "succeeded" || code != 200 || version != f.Version || evidenceID != f.EvidenceID || responseHash != f.ResponseHash || targetType != "system" || targetID != f.Installation || kind != "config_update" || s.OperationStarted.IsZero() || !s.OperationStarted.Equal(s.OperationCreated) || s.OperationFinished.Before(s.OperationStarted) || s.OperationFinished.After(now) || s.OperationRowVersion < 1 {
		return fail()
	}
	s.OperationStarted, s.OperationCreated, s.OperationFinished = s.OperationStarted.UTC(), s.OperationCreated.UTC(), s.OperationFinished.UTC()
	err = tx.QueryRowContext(ctx, `SELECT id,schema_version,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,evidence_failure_code,observed_health,inline_payload,content_checksum,content_size_bytes,media_type,redaction_classification,encryption,expires_at,created_at,row_version,storage_provider_role,storage_identity_hash,storage_ref_version,storage_relative_key,storage_relative_key_hash,storage_immutable_version,object_checksum,object_size_bytes,plaintext_chunk_size_bytes,chunk_count,chunk_list_root,envelope_framing_version,kek_identity_hash,kek_version,envelope_hash FROM system_backup_v2_evidence WHERE id=? FOR UPDATE`, f.EvidenceID).Scan(
		&s.ID, &s.Schema, &s.PublicID, &s.OwnerType, &s.Owner, &s.Kind, &s.State, &s.Failure, &s.Health, &s.Inline, &s.Checksum, &s.Size, &s.Media, &s.Classification, &s.Encryption, &s.Expires, &s.Created, &s.RowVersion, &s.Role, &s.StoreIdentity, &s.StoreVersion, &s.RelativeKey, &s.RelativeKeyHash, &s.Immutable, &s.ObjectHash, &s.ObjectSize, &s.ChunkSize, &s.Count, &s.Root, &s.Framing, &s.KEKIdentity, &s.KEKVersion, &s.Envelope)
	if err != nil || s.ID != f.EvidenceID || s.Schema != "system-backup-evidence.v1" || !evidenceIDPattern.MatchString(s.PublicID) || s.OwnerType != "system" || s.Owner != f.Installation || s.Kind != "diagnostic" || s.Failure != "none" || s.Health != "healthy" || s.Checksum != f.ResponseHash || s.Size < 2 || s.Size > configMutationResponseMaxBytes || s.Media != "application/json" || s.Classification != "internal" || s.RowVersion < 1 || s.Created.IsZero() || s.Created.After(now) || !now.Before(s.Expires) {
		return fail()
	}
	s.Created, s.Expires = s.Created.UTC(), s.Expires.UTC()
	s.Manifest.Identity = ev.Identity{Installation: f.Installation, ID: s.PublicID, OwnerType: s.OwnerType, OwnerID: s.Owner, Type: s.Kind, Media: s.Media, Classification: s.Classification, ContentHash: s.Checksum, ContentSize: s.Size}
	rows, err := tx.QueryContext(ctx, `SELECT chunk_index,plaintext_offset,plaintext_length,plaintext_sha256,object_frame_offset,object_frame_length,ciphertext_sha256,gcm_nonce,gcm_tag FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE`, s.ID)
	if err != nil {
		return fail()
	}
	defer rows.Close()
	for rows.Next() {
		if len(s.Manifest.Chunks) >= 1 {
			return fail()
		}
		ch := ev.Chunk{EvidenceID: s.PublicID}
		var nonce, tag []byte
		if rows.Scan(&ch.Index, &ch.PlainOffset, &ch.PlainLength, &ch.PlainHash, &ch.FrameOffset, &ch.FrameLength, &ch.CipherHash, &nonce, &tag) != nil {
			return fail()
		}
		ch.Nonce, ch.Tag = base64.RawURLEncoding.EncodeToString(nonce), base64.RawURLEncoding.EncodeToString(tag)
		s.Manifest.Chunks = append(s.Manifest.Chunks, ch)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return fail()
	}
	if s.State == "inline" {
		if s.Size > 8192 || int64(len(s.Inline)) != s.Size || registrationHash(string(s.Inline)) != s.Checksum || s.Encryption != "none" || s.Count != 0 || len(s.Manifest.Chunks) != 0 ||
			s.Role.Valid || s.StoreIdentity.Valid || s.StoreVersion.Valid || s.RelativeKey.Valid || s.RelativeKeyHash.Valid || s.Immutable.Valid || s.ObjectHash.Valid || s.ObjectSize.Valid || s.ChunkSize.Valid || s.Root.Valid || s.Framing.Valid || s.KEKIdentity.Valid || s.KEKVersion.Valid || s.Envelope.Valid {
			return fail()
		}
	} else if s.State == "ready" {
		if s.Size <= 8192 || s.Inline != nil || s.Encryption != "envelope_v1" || s.Role.String != "evidence" || !s.StoreIdentity.Valid || !s.StoreVersion.Valid || !s.RelativeKey.Valid || !s.Immutable.Valid || s.Immutable.String == "" || s.Immutable.String == "null" || len(s.Immutable.String) > 256 || !configMutationResponseRelativeKey(s.RelativeKey.String) || s.RelativeKeyHash.String != registrationHash(s.RelativeKey.String) || !s.ObjectHash.Valid || !s.ObjectSize.Valid || !s.ChunkSize.Valid || s.ChunkSize.Int64 != ev.ChunkSize || s.Count != 1 || len(s.Manifest.Chunks) != 1 || !s.Root.Valid || s.Framing.String != ev.Framing || !s.KEKIdentity.Valid || !s.KEKVersion.Valid || !s.Envelope.Valid {
			return fail()
		}
		s.Manifest.Key = ev.KeyRef{Identity: s.KEKIdentity.String, Version: s.KEKVersion.String}
		s.Manifest.EnvelopeHash, s.Manifest.ObjectHash, s.Manifest.ObjectSize, s.Manifest.ChunkRoot = s.Envelope.String, s.ObjectHash.String, s.ObjectSize.Int64, s.Root.String
		s.Manifest.HeaderSize = s.Manifest.Chunks[0].FrameOffset
		s.Ref = ev.Ref{Identity: s.StoreIdentity.String, Version: s.StoreVersion.String, RelativeKey: s.RelativeKey.String, ImmutableVersion: s.Immutable.String}
	} else {
		return fail()
	}
	if ctx.Err() != nil || s.fingerprint() == "" {
		return fail()
	}
	return s, nil
}

type verifiedConfigMutationResponseRead struct {
	input              sec.ConfigMutationResponseReplayPreparation
	snapshot           responseReplaySnapshot
	access             ConfigMutationResponseReadAccess
	accessUntil, until time.Time
	raw                []byte
}

func (r *verifiedConfigMutationResponseRead) Bytes() []byte         { return append([]byte(nil), r.raw...) }
func (r *verifiedConfigMutationResponseRead) ValidUntil() time.Time { return r.until }
func (r *verifiedConfigMutationResponseRead) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || now.Before(r.input.Facts().AuthorizedAt) || !now.Before(r.until) || !time.Now().Before(r.until) || r.access.Recheck(ctx, tx, now) != nil || !r.access.ValidUntil().Equal(r.accessUntil) {
		return sec.ErrRegistrationUnavailable
	}
	s, err := loadResponseReplaySnapshot(ctx, tx, r.input, now)
	if err != nil || s.fingerprint() != r.snapshot.fingerprint() || r.access.Recheck(ctx, tx, now) != nil || !r.access.ValidUntil().Equal(r.accessUntil) || ctx.Err() != nil || !time.Now().Before(r.until) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

// Read releases its own snapshot transaction before authority/provider work.
// The returned read must be rechecked in the writer's FINAL authorized replay
// transaction; a caller must not serve Bytes merely because this method passed.
func (r *SQLConfigMutationResponseReader) Read(ctx context.Context, input sec.ConfigMutationResponseReplayPreparation) (sec.PreparedConfigMutationResponseRead, error) {
	f := input.Facts()
	fail := func() (sec.PreparedConfigMutationResponseRead, error) { return nil, sec.ErrRegistrationUnavailable }
	if r == nil || ctx == nil || ctx.Err() != nil || r.db == nil || f.Database != r.database || f.Installation != r.installation || isNil(r.authority) {
		return fail()
	}
	if _, err := sec.NewConfigMutationResponseReplayPreparation(f); err != nil {
		return fail()
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fail()
	}
	now, err := responseReplayClock(ctx, tx)
	var snap responseReplaySnapshot
	if err == nil {
		snap, err = loadResponseReplaySnapshot(ctx, tx, input, now)
	}
	release := tx.Rollback()
	if err != nil || release != nil {
		return fail()
	}
	access, err := r.authority.Prepare(ctx, input, ConfigMutationResponseLocation{snap})
	if err != nil || isNil(access) {
		return fail()
	}
	accessUntil := access.ValidUntil()
	until := f.ValidUntil
	for _, bound := range []time.Time{snap.Expires, accessUntil} {
		if bound.Before(until) {
			until = bound
		}
	}
	if accessUntil.IsZero() || !now.Before(until) || !time.Now().Before(until) {
		return fail()
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	read := &verifiedConfigMutationResponseRead{input: input, snapshot: snap, access: access, accessUntil: accessUntil, until: until}
	tx, err = r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fail()
	}
	now, err = responseReplayClock(ctx, tx)
	if err == nil {
		err = read.Recheck(ctx, tx, now)
	}
	release = tx.Rollback()
	if err != nil || release != nil {
		return fail()
	}
	var raw []byte
	if snap.State == "inline" {
		raw = append([]byte(nil), snap.Inline...)
	} else {
		resources := access.Resources()
		if resources.Store != (ev.KeyRef{Identity: snap.Ref.Identity, Version: snap.Ref.Version}) || resources.KEK != snap.Manifest.Key {
			return fail()
		}
		scope := ConfigMutationResponseReadScope{Installation: f.Installation, Actor: f.Actor, Now: now, ValidUntil: until, Root: resources.Root, Store: resources.Store, KEK: resources.KEK}
		raw, err = ReadPublishedConfigMutationResponse(ctx, scope, snap.Manifest, snap.Ref, resources.Reader, resources.Keys)
	}
	if err != nil {
		wipe(raw)
		return fail()
	}
	dto, _, created, err := decodeConfigMutationResponseResource(f.Installation, strconv.FormatInt(f.Actor.UserID, 10), raw)
	if err != nil || int64(dto.Version) != f.Version || !created.Equal(snap.OperationStarted) || created.After(snap.Created) || registrationHash(string(raw)) != f.ResponseHash || !access.ValidUntil().Equal(accessUntil) || ctx.Err() != nil || !time.Now().Before(until) {
		wipe(raw)
		return fail()
	}
	read.raw = raw
	return read, nil
}
