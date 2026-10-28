package systembackupevidence

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"clawreef/internal/systembackupsecurity"
)

// All environment methods are deployment-owned SQL/local boundaries. They
// neither commit/rollback, do provider/network I/O nor refresh original limits.
// Prepare runs at L2: check real current sessions/credentials/revocation, RBAC
// and target access, and load a non-locking immutable evidence hint plus pinned
// A signing/HMAC materials for ALL versions. It must not acquire L3+ locks.
// Missing real owner/material/capacity adapters are NOT replaced with fixtures.
type DownloadAdmissionEnvironment interface {
	Prepare(context.Context, *sql.Tx, systembackupsecurity.RegistrationActor, *systembackupsecurity.SensitiveDownloadConfig, string, []string) (PreparedDownloadAdmission, error)
}
type PreparedDownloadAdmission interface {
	Preview() Record
	Issuer() string
	ProofConfig() systembackupsecurity.VerifyConfig
	ValidUntil() time.Time
	MinimumRetainUntil() time.Time
	LockOwnerReferences(context.Context, *sql.Tx) error                                // remaining L3 refs, L4 owners, then L5 refs; before nonce
	Reserve(context.Context, *sql.Tx, time.Time) (DownloadAdmissionReservation, error) // L6, real physical/index/audit/nonce budget and storage slots
	Recheck(context.Context, *sql.Tx, systembackupsecurity.RegistrationActor, Record, time.Time) error
	Close() // release/wipe only; no SQL, provider work or authority extension
}
type DownloadAdmissionReservation interface {
	ValidUntil() time.Time
	Recheck(context.Context, *sql.Tx, time.Time) error
}

var (
	ErrDownloadAdmissionCommitUnknown    = errors.New("download_admission_commit_unknown")
	ErrDownloadAdmissionCommittedExpired = errors.New("download_admission_committed_but_expired")
)

type DownloadAdmissionService struct {
	registry    SQLRegistry
	secret      []byte
	environment DownloadAdmissionEnvironment
}

func (*DownloadAdmissionService) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*DownloadAdmissionService) String() string               { return "DownloadAdmissionService" }
func (*DownloadAdmissionService) GoString() string             { return "DownloadAdmissionService" }

func NewDownloadAdmissionService(registry SQLRegistry, jwtSecret []byte, environment DownloadAdmissionEnvironment) (*DownloadAdmissionService, error) {
	if registry.DB == nil || nilSystemAdapter(registry.Policy) || !installationPattern.MatchString(registry.Installation) || registry.ServerUUID == "" || registry.Database == "" || len(jwtSecret) < 32 || nilSystemAdapter(environment) {
		return nil, ErrDownloadAdmissionNotReady
	}
	return &DownloadAdmissionService{registry: registry, secret: append([]byte(nil), jwtSecret...), environment: environment}, nil
}

// CommittedDownloadAdmission is emitted ONLY after a known successful commit.
// It is internal metadata, not a provider credential or proof the client read
// bytes. Provider access/plaintext still need current authority and claim checks.
type CommittedDownloadAdmission struct {
	state                  *committedDownloadState
	service                *DownloadAdmissionService
	record                 Record
	actor                  systembackupsecurity.RegistrationActor
	request                systembackupsecurity.SensitiveDownloadRequest
	rows                   committedDownloadRows
	configVersion          int64
	configSHA256           string
	operationID            string
	intentAuditID          int64
	admittedAt, deadlineAt time.Time
	localDeadline          time.Time
}

func (*CommittedDownloadAdmission) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CommittedDownloadAdmission) String() string               { return "CommittedDownloadAdmission" }
func (*CommittedDownloadAdmission) GoString() string             { return "CommittedDownloadAdmission" }
func (a *CommittedDownloadAdmission) Record() Record {
	if a == nil {
		return Record{}
	}
	r := a.record
	r.Manifest.Chunks = append([]Chunk(nil), r.Manifest.Chunks...)
	return r
}
func (a *CommittedDownloadAdmission) OperationPublicID() string {
	if a == nil {
		return ""
	}
	return a.operationID
}

// Range is the original normalized/signed request, never a new header parse.
func (a *CommittedDownloadAdmission) Range() (int64, int64, bool) {
	if a == nil {
		return 0, 0, false
	}
	return a.request.Range()
}

func newDownloadAdmissionOperationID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", ErrDownloadAdmissionNotReady
	}
	id[6] = (id[6] & 15) | 64
	id[8] = (id[8] & 63) | 128
	return fmt.Sprintf("sop_%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), nil
}
func maxDownloadAdmissionRetention(limits ...time.Time) time.Time {
	var until time.Time
	for _, v := range limits {
		if v.After(until) {
			until = v
		}
	}
	floor := until.UTC().Truncate(time.Microsecond)
	if floor.Before(until) {
		floor = floor.Add(time.Microsecond)
	}
	return floor
}

// Admit owns the fresh RepeatableRead transaction and UNIQUE commit. It does
// not implement the legacy evidence-row-first callback, retry or provider I/O.
// The environment must supply reviewed real adapters before mounting a runtime;
// this constructor does not enable production/schema or waive A/B/C reviews.
func (s *DownloadAdmissionService) Admit(request *http.Request) (*CommittedDownloadAdmission, error) {
	return s.admit(request, false)
}

// Only the unified HTTP dispatcher may hand an authorized non-sensitive hint
// to the legacy reader, which independently rejects private classifications
// under its actual evidence lock. This branch performs no admission effects.
var errDownloadAdmissionPublic = errors.New("download_non_sensitive")

func (s *DownloadAdmissionService) admit(request *http.Request, allowPublic bool) (*CommittedDownloadAdmission, error) {
	if s == nil || s.registry.DB == nil || nilSystemAdapter(s.environment) || request == nil || request.URL == nil || request.TLS == nil || request.Context().Err() != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.RawPath != "" || request.URL.Fragment != "" || !strings.HasPrefix(request.URL.Path, Path) || request.ContentLength != 0 || request.Body != nil && request.Body != http.NoBody || len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 {
		return nil, ErrInvalid
	}
	id := strings.TrimPrefix(request.URL.Path, Path)
	if !idPattern.MatchString(id) {
		return nil, ErrInvalid
	}
	headers := request.Header.Clone()
	if len(sensitiveDownloadHeaderValues(headers, "Authorization")) != 1 {
		return nil, ErrAuth
	}
	actor, err := (systembackupsecurity.JWTRegistrationAuthenticator{Secret: s.secret}).Authenticate(request)
	if err != nil {
		return nil, ErrAuth
	}
	// JWT NumericDate may carry the host's Location. Normalize trusted instants
	// without rounding or extending either original token bound.
	actor.SessionIssuedAt = actor.SessionIssuedAt.UTC()
	actor.SessionExpiresAt = actor.SessionExpiresAt.UTC()
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	ctx = withVerifiedDownloadActor(ctx, s.registry, actor)
	tx, now, err := s.registry.begin(ctx)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	defer tx.Rollback()
	scope, err := systembackupsecurity.LockSensitiveDownloadNonceScope(ctx, tx, systembackupsecurity.DatabaseIdentity{ServerUUID: s.registry.ServerUUID, Database: s.registry.Database}, s.registry.Installation)
	if err != nil {
		return nil, err
	}
	config, err := scope.LoadConfig(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !downloadAdmissionContentTime(config.ObservedAt()) {
		return nil, ErrDownloadAdmissionNotReady
	}
	now, err = downloadIntentNow(ctx, tx, config.ObservedAt())
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	if !downloadAdmissionActorAt(actor, now) {
		return nil, ErrAuth
	}
	prepared, err := s.environment.Prepare(ctx, tx, actor, config, id, scope.RequiredVersions())
	if !nilSystemAdapter(prepared) {
		defer prepared.Close()
	}
	if err != nil {
		return nil, err
	}
	if nilSystemAdapter(prepared) {
		return nil, ErrDownloadAdmissionNotReady
	}
	hint := prepared.Preview()
	frozen, err := snapshotReadManifest(hint.Manifest)
	if err != nil || frozen.Identity.Installation != s.registry.Installation || frozen.Identity.ID != id ||
		hint.RowVersion < 1 || hint.RowVersion >= 9007199254740991 || hint.State != "ready" || hint.Failure != "none" || !hint.Ref.valid(true) {
		return nil, ErrState
	}
	hint.Manifest = frozen
	if oneOf(frozen.Identity.Classification, "public", "internal") {
		if allowPublic {
			return nil, errDownloadAdmissionPublic
		}
		return nil, ErrState
	}
	originalAuthority := prepared.ValidUntil()
	minimumRetention := prepared.MinimumRetainUntil()
	if !downloadAdmissionContentTime(originalAuthority) || !downloadAdmissionContentTime(minimumRetention) || config.ControlRetention() <= 0 {
		return nil, ErrDownloadAdmissionNotReady
	}
	cfg := prepared.ProofConfig()
	// Own copies are wiped without changing the source's material snapshot.
	keys := make(map[string][]byte, len(cfg.NonceHMACKeys))
	for v, k := range cfg.NonceHMACKeys {
		keys[v] = append([]byte(nil), k...)
	}
	defer func() {
		for _, k := range keys {
			wipe(k)
		}
	}()
	cfg.NonceHMACKeys = keys
	if cfg.ExpectedSubject != actor.Subject || cfg.ExpectedSession != actor.Session || cfg.ActiveNonceHMACKeyVersion != scope.ActiveVersion() {
		return nil, ErrDownloadAdmissionNotReady
	}
	if !downloadAdmissionContentTime(cfg.Now) || cfg.Now.Before(now) {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = config.Recheck(ctx, tx); err != nil {
		return nil, err
	}
	floor := now
	if cfg.Now.After(floor) {
		floor = cfg.Now
	}
	if observed := config.ObservedAt(); observed.After(floor) {
		floor = observed
	}
	now, err = downloadIntentNow(ctx, tx, floor)
	if err != nil || !now.Before(originalAuthority) {
		return nil, ErrDownloadAdmissionNotReady
	}
	cfg.Now, cfg.MaxAge, cfg.ClockSkew, cfg.RequiredNonceHMACKeyVersions = now, config.MaxAge(), config.ClockSkew(), scope.RequiredVersions()
	proof, err := VerifySensitiveDownloadRequestHeader(actor, hint.Manifest, headers, prepared.Issuer(), cfg)
	if err != nil {
		return nil, err
	}
	operationID, err := newDownloadAdmissionOperationID()
	if err != nil {
		return nil, err
	}
	key, err := LockDownloadAdmissionKey(ctx, tx, actor, proof, operationID)
	if err != nil {
		return nil, err
	}
	if err = prepared.LockOwnerReferences(ctx, tx); err != nil {
		return nil, err
	}
	if err = scope.LockCandidates(ctx, tx, proof); err != nil {
		return nil, err
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	reservation, err := prepared.Reserve(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	if nilSystemAdapter(reservation) {
		return nil, ErrDownloadAdmissionNotReady
	}
	capacityUntil := reservation.ValidUntil()
	if !downloadAdmissionContentTime(capacityUntil) {
		return nil, ErrDownloadAdmissionNotReady
	}
	authorityUntil := earlier(originalAuthority, capacityUntil)
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil || !now.Before(authorityUntil) {
		return nil, ErrDownloadAdmissionNotReady
	}
	claim, err := claimID()
	if err != nil {
		return nil, err
	}
	claimUntil := key.observedAt.Add(30 * time.Second)
	retainUntil := maxDownloadAdmissionRetention(now.Add(config.ControlRetention()), proof.ProofExpiresAt().Add(config.ControlRetention()), minimumRetention, hint.ProtectedUntil, claimUntil.Add(time.Microsecond))
	if !downloadAdmissionContentTime(retainUntil) {
		return nil, ErrDownloadAdmissionNotReady
	}
	start, end, present := proof.Request().Range()
	intent := DownloadAdmissionIntent{Installation: s.registry.Installation, OperationID: operationID, EvidenceID: id, ActorID: actor.UserID, RequestHash: proof.Request().RequestHash(), ManifestSHA256: proof.Request().ManifestSHA256(), Claim: claim, EvidenceRowVersion: hint.RowVersion + 1, Start: start, End: end, RangePresent: present}
	audit, err := (SQLDownloadAdmissionAudits{}).StageIntent(ctx, tx, intent)
	if err != nil {
		return nil, err
	}
	claimed, err := s.registry.StageDownloadAdmissionClaim(ctx, tx, key, hint, claim, claimUntil)
	if err != nil {
		return nil, err
	}
	current := claimed.Record()
	binding, err := BindDownloadAdmissionContent(ctx, tx, audit, DownloadAdmissionContentFacts{Actor: actor, Record: current, Intent: intent, Proof: proof, AuthorityUntil: authorityUntil})
	if err != nil {
		return nil, err
	}
	records, err := StageDownloadAdmissionRecords(ctx, tx, key, binding, current, retainUntil)
	if err != nil {
		return nil, err
	}
	nonce, err := records.StageNonce(ctx, tx, scope, actor, current)
	if err != nil {
		return nil, err
	}
	// Every callback precedes the final independent SQL row/byte rechecks.
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = prepared.Recheck(ctx, tx, actor, current, now); err != nil {
		return nil, err
	}
	if err = reservation.Recheck(ctx, tx, now); err != nil {
		return nil, err
	}
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = prepared.Recheck(ctx, tx, actor, current, now); err != nil {
		return nil, err
	}
	if err = config.Recheck(ctx, tx); err != nil {
		return nil, err
	}
	if err = claimed.Recheck(ctx, tx); err != nil {
		return nil, err
	}
	if err = nonce.Recheck(ctx, tx, actor, current); err != nil {
		return nil, err
	}
	// Start the monotonic stopwatch BEFORE the final SQL sample, so response
	// latency cannot make a known late commit into a usable download capability.
	guardStarted := time.Now()
	now, err = downloadIntentNow(ctx, tx, now)
	if err != nil || !now.Before(binding.DeadlineAt()) || !downloadAdmissionActorAt(actor, now) || proof.RecheckProofAt(now) != nil || ctx.Err() != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	if err = tx.Commit(); err != nil {
		return nil, ErrDownloadAdmissionCommitUnknown
	}
	if ctx.Err() != nil || !now.Add(time.Since(guardStarted)).Before(binding.DeadlineAt()) {
		return nil, ErrDownloadAdmissionCommittedExpired
	}
	rows := sealCommittedDownloadRows(records, nonce)
	return &CommittedDownloadAdmission{state: &committedDownloadState{}, service: s, record: current, actor: actor, request: proof.Request(), rows: rows,
		configVersion: config.Version(), configSHA256: config.Values().SHA256(), operationID: operationID, intentAuditID: audit.id,
		admittedAt: binding.receipt.AdmittedAt, deadlineAt: binding.DeadlineAt(), localDeadline: guardStarted.Add(binding.DeadlineAt().Sub(now))}, nil
}
