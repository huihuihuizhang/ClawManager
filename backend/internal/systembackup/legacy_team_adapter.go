package systembackup

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/team"
)

// LegacyTeamReference comes from the public operation's trusted source mapping,
// never a browser endpoint, latest-key default or an S3 LIST absence inference.
type LegacyTeamReference struct {
	Origin   string          `json:"origin_installation_id"`
	BackupID string          `json:"backup_id"`
	Commit   ObjectReference `json:"commit"`
}
type LegacyTeamAccess struct {
	Reference         LegacyTeamReference
	PublicOperationID string
	Action            string
	SigningVersion    string // untrusted discovery hint, not a key authorization
}
type HistoricalTeamKeys struct {
	PublicKey      ed25519.PublicKey
	SigningVersion string
	Wrapper        DataKeyWrapper
}

func (HistoricalTeamKeys) String() string               { return "HistoricalTeamKeys" }
func (HistoricalTeamKeys) GoString() string             { return "HistoricalTeamKeys" }
func (HistoricalTeamKeys) MarshalJSON() ([]byte, error) { return nil, errors.New("permission_denied") }

// A owns original-job mapping, purpose/permission checks, historical versions
// and revocation. C does not substitute an in-process/current-key fallback.
type HistoricalTeamAuthority interface {
	AuthorizeHistoricalTeam(context.Context, LegacyTeamAccess) error
	ResolveHistoricalTeam(context.Context, LegacyTeamAccess) (HistoricalTeamKeys, error)
}
type HistoricalTeamArtifact struct {
	artifact  PublishedArtifact
	store     ImmutableObjectStore
	access    LegacyTeamAccess
	keys      HistoricalTeamKeys
	authority HistoricalTeamAuthority
}

func (*HistoricalTeamArtifact) String() string   { return "HistoricalTeamArtifact" }
func (*HistoricalTeamArtifact) GoString() string { return "HistoricalTeamArtifact" }
func (*HistoricalTeamArtifact) MarshalJSON() ([]byte, error) {
	return nil, errors.New("permission_denied")
}

var publicRecoveryOperation = regexp.MustCompile(`^(sop|sdr)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func missingHistoricalAuthority(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice:
		return r.IsNil()
	}
	return false
}

func OpenHistoricalTeamArtifact(ctx context.Context, store ImmutableObjectStore, ref LegacyTeamReference, operation, action string, authority HistoricalTeamAuthority) (*HistoricalTeamArtifact, error) {
	if ctx == nil || ctx.Err() != nil || missingHistoricalAuthority(authority) {
		return nil, errors.New("not_ready")
	}
	if !publicRecoveryOperation.MatchString(operation) ||
		(action != "verify" && action != "download" && action != "restore") || (action == "restore" && operation[:4] != "sdr_") ||
		!validPartIdentity(ref.Origin, ref.BackupID, "mysql") || ref.Commit.Key != artifactPrefix(ref.Origin, ref.BackupID)+"_COMMITTED" ||
		ref.Commit.VersionID == "" || !validHash(ref.Commit.SHA256) || ref.Commit.Bytes < 1 || ref.Commit.Bytes > MaxImmutableObjectBytes {
		return nil, errors.New("validation_failed")
	}
	access := LegacyTeamAccess{Reference: ref, PublicOperationID: operation, Action: action}
	if err := authority.AuthorizeHistoricalTeam(ctx, access); err != nil {
		return nil, err
	}
	raw, err := store.Read(ctx, ref.Commit)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var commit SignedCommit
	if strictDecode(raw, &commit) != nil || commit.Signature.KeyVersion == "" {
		return nil, errors.New("signature_invalid")
	}
	access.SigningVersion = commit.Signature.KeyVersion
	keys, err := authority.ResolveHistoricalTeam(ctx, access)
	if err != nil {
		return nil, err
	}
	if len(keys.PublicKey) != ed25519.PublicKeySize || keys.SigningVersion != access.SigningVersion || missingHistoricalAuthority(keys.Wrapper) {
		return nil, errors.New("encryption_key_unavailable")
	}
	artifact, err := openPublishedCommit(ctx, store, ref.Origin, ref.BackupID, raw, ref.Commit, keys.PublicKey, keys.SigningVersion)
	if err != nil {
		return nil, err
	}
	if artifact.Manifest.Payload.Purpose != "team_data" || artifact.Manifest.Payload.Consistency != "best_effort" {
		return nil, errors.New("artifact_conflict")
	}
	if err = authority.AuthorizeHistoricalTeam(ctx, access); err != nil {
		return nil, err
	}
	keys.PublicKey = append(ed25519.PublicKey(nil), keys.PublicKey...)
	return &HistoricalTeamArtifact{artifact: artifact, store: store, access: access, keys: keys, authority: authority}, nil
}

// Descriptor never upgrades a legacy Team artifact to formal acceptance.
func (h *HistoricalTeamArtifact) Descriptor() (PublishedArtifact, error) {
	if h == nil {
		return PublishedArtifact{}, errors.New("not_ready")
	}
	raw, err := json.Marshal(h.artifact)
	if err != nil {
		return PublishedArtifact{}, err
	}
	var copy PublishedArtifact
	if err = strictDecode(raw, &copy); err != nil {
		return PublishedArtifact{}, err
	}
	return copy, nil
}
func (h *HistoricalTeamArtifact) check(ctx context.Context, action string) error {
	if h == nil || missingHistoricalAuthority(h.authority) || h.access.Action != action {
		return errors.New("permission_denied")
	}
	return h.authority.AuthorizeHistoricalTeam(ctx, h.access)
}
func (h *HistoricalTeamArtifact) Verify(ctx context.Context, maxBytes int64) error {
	if err := h.check(ctx, "verify"); err != nil {
		return err
	}
	if err := VerifyPublishedArtifact(ctx, h.store, h.artifact, h.keys.Wrapper, maxBytes); err != nil {
		return err
	}
	return h.check(ctx, "verify")
}

// Consume supplies authenticated, bounded original part bytes to the existing
// public worker adapter. Target identity/evidence custody belong to its grant.
// Consumer errors propagate; no retry, private task or source write is made.
func (h *HistoricalTeamArtifact) Consume(ctx context.Context, name string, maxBytes int64, consume func(io.Reader) error) error {
	if h == nil || consume == nil || (h.access.Action != "restore" && h.access.Action != "download") {
		return errors.New("permission_denied")
	}
	if err := h.check(ctx, h.access.Action); err != nil {
		return err
	}
	if err := ConsumePublishedPart(ctx, h.store, h.artifact, name, h.keys.Wrapper, maxBytes, func(r io.Reader) error { return consume(historicalAuthorizedReader{h: h, ctx: ctx, r: r}) }); err != nil {
		return err
	}
	return h.check(ctx, h.access.Action)
}

type historicalAuthorizedReader struct {
	h   *HistoricalTeamArtifact
	ctx context.Context
	r   io.Reader
}

type LegacyStagingAccess struct {
	Source  LegacyTeamAccess
	Part    string
	Name    string
	Binding staging.Binding
}
type LegacyStagingAuthority interface {
	AuthorizeLegacyStaging(context.Context, LegacyStagingAccess) error
}

// Stage writes only a grant-bound encrypted handoff to the existing workers.
// It does not publish a backup, create a task or authorize a restore target.
// D supplies the original job/staging custody and A the task-scoped key grant.
func (h *HistoricalTeamArtifact) Stage(ctx context.Context, part string, maxBytes int64, root *os.Root, name string, key []byte, binding staging.Binding, authority LegacyStagingAuthority) (staging.Receipt, error) {
	var zero staging.Receipt
	if h == nil || h.access.Action != "restore" || root == nil || missingHistoricalAuthority(authority) || len(key) != 32 {
		return zero, errors.New("not_ready")
	}
	access := LegacyStagingAccess{Source: h.access, Part: part, Name: name, Binding: binding}
	if err := authority.AuthorizeLegacyStaging(ctx, access); err != nil {
		return zero, err
	}
	receipt, err := staging.SealFile(ctx, root, name, key, binding, func(dst io.Writer) error {
		return staging.Compress(dst, func(plain io.Writer) error {
			return h.Consume(ctx, part, maxBytes, func(src io.Reader) error {
				if err := authority.AuthorizeLegacyStaging(ctx, access); err != nil {
					return err
				}
				_, err := io.Copy(plain, src)
				return err
			})
		})
	})
	if err != nil {
		return zero, err
	}
	if err = authority.AuthorizeLegacyStaging(ctx, access); err != nil {
		return zero, err
	}
	return receipt, nil
}

func (r historicalAuthorizedReader) Read(p []byte) (int, error) {
	if err := r.h.check(r.ctx, r.h.access.Action); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

const LegacyTeamSQLFormat = "legacy-team-sql.v1"

// DecodeLegacyTeamSQL bridges only data, never source DDL or task state. All
// current-profile tables and row bytes survive; missing/unknown scope fails.
// FK/unique-key metadata must later come from the observed isolated target.
func DecodeLegacyTeamSQL(ctx context.Context, r io.Reader, limits domain.Limits) (out domain.Snapshot, err error) {
	if ctx == nil || ctx.Err() != nil || limits.MaxBytes <= 0 || limits.MaxRows <= 0 {
		return out, errors.New("validation_failed")
	}
	expected, err := BuiltinSchema()
	if err != nil {
		return out, err
	}
	known := map[string]SQLTable{}
	for _, t := range expected {
		known[t.Name] = t
	}
	out.Version = domain.Version
	bounded := &io.LimitedReader{R: r, N: limits.MaxBytes + 1}
	var rows int64
	result, err := ReadSQLSnapshot(bounded, func(t SQLTable) error {
		base, ok := known[t.Name]
		if !ok || validateTeamDataTable(t, base) != nil {
			return errors.New("unsupported_schema")
		}
		mapped := domain.Table{Name: t.Name, Engine: "InnoDB", PrimaryKey: append([]string(nil), t.PrimaryKey...), Rows: []domain.Row{}}
		for _, c := range t.Columns {
			// The frozen current schema above authenticates generated metadata.
			// Keep its bytes; the public normalizer still rejects unsupported
			// generated-column restore policies before any target write.
			mapped.Columns = append(mapped.Columns, domain.Column{Name: c.Name, Type: c.Type, Nullable: c.Nullable == "YES", Extra: c.Extra})
		}
		out.Tables = append(out.Tables, mapped)
		return ctx.Err()
	}, func(_ SQLTable, row team.Row) error {
		rows++
		if rows > limits.MaxRows {
			return errors.New("capacity_exceeded")
		}
		mapped := domain.Row{}
		for k, v := range row {
			mapped[k] = domain.Cell{Null: v.IsNull, Bytes: append([]byte(nil), v.Data...)}
		}
		out.Tables[len(out.Tables)-1].Rows = append(out.Tables[len(out.Tables)-1].Rows, mapped)
		return ctx.Err()
	})
	if err == nil && (limits.MaxBytes+1-bounded.N > limits.MaxBytes || len(result.Tables) != len(known)) {
		err = errors.New("unsupported_schema")
	}
	if err != nil {
		for _, t := range out.Tables {
			for _, r := range t.Rows {
				for _, v := range r {
					clear(v.Bytes)
				}
			}
		}
		return domain.Snapshot{}, err
	}
	return out, nil
}
