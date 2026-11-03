package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const OriginalAdoptionReservationVersion = "original-adoption-maintenance-reservation.v1"

// Frozen native-observer correlation DATA, never authentication/write/stop
// authority. ReservationID is Agent RuntimeBackupRequest.OperationID. The
// global OperationID owns the original maintenance gate; neither is a task ID.
// AcquisitionEpoch/RowVersion are frozen at the real acquiring gate. Normal
// held/releasing epoch is AcquisitionEpoch+1 by AdvanceGateHeld's actual CAS.
type OriginalAdoptionReservation struct {
	Version               string    `json:"version"`
	OperationID           string    `json:"operation_id"`
	ReservationID         string    `json:"reservation_id"`
	InstallationID        string    `json:"installation_id"`
	ServerUUID            string    `json:"server_uuid"`
	Database              string    `json:"database"`
	Scope                 string    `json:"scope"`
	GateOwner             string    `json:"gate_owner"`
	GateGeneration        uint64    `json:"gate_generation"`
	AcquisitionEpoch      uint64    `json:"acquisition_epoch"`
	AcquisitionRowVersion uint64    `json:"acquisition_row_version"`
	Phase                 GateState `json:"phase"`
	WriterID              string    `json:"writer_id"`
	SourceWritersSHA256   string    `json:"source_writers_sha256"`
	AgentRequestSHA256    string    `json:"agent_request_sha256"`
	ControlKind           string    `json:"control_kind"`
	NativeRequestSHA256   string    `json:"native_request_sha256"`
	NotBefore             time.Time `json:"not_before"`
	ExpiresAt             time.Time `json:"expires_at"`
}

// Selected from the original Installer plan, NOT from a native observer body.
type OriginalAdoptionDatabasePin struct{ ServerUUID, Database, Account string }

func validOriginalAdoptionReservation(r OriginalAdoptionReservation) bool {
	token := func(s string) bool {
		b, e := hex.DecodeString(s)
		return e == nil && len(b) == 16 && hex.EncodeToString(b) == s
	}
	hash := regexp.MustCompile(`^[0-9a-f]{64}$`)
	return r.Version == OriginalAdoptionReservationVersion && token(r.OperationID) && token(r.ReservationID) && installationIDPattern.MatchString(r.InstallationID) && regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(r.ServerUUID) && regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(r.Database) && r.Scope == CaptureGateScope && r.GateOwner == "adoption:"+r.OperationID && r.GateGeneration > 0 && r.AcquisitionEpoch < ^uint64(0) && r.AcquisitionRowVersion > 0 && (r.Phase == GateAcquiring || r.Phase == GateHeld || r.Phase == GateReleasing) && (len(r.WriterID) > 0 && len(r.WriterID) <= 1024 && utf8.ValidString(r.WriterID) && !strings.ContainsAny(r.WriterID, "\x00\r\n")) && hash.MatchString(r.SourceWritersSHA256) && validOriginalAdoptionNativeRequest(r) && !r.NotBefore.IsZero() && r.NotBefore.Nanosecond()%1000 == 0 && r.ExpiresAt.Nanosecond()%1000 == 0 && r.NotBefore.Before(r.ExpiresAt)
}

// Exact fixed field order/encoding for B's original request/checkpoint anchor.
// A hash match is correlation only; LockOriginalAdoptionReservation below must
// check the actual current ORIGINAL gate. There is no JSON-to-held conversion.
func validOriginalAdoptionNativeRequest(r OriginalAdoptionReservation) bool {
	h := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !h.MatchString(r.NativeRequestSHA256) {
		return false
	}
	switch r.ControlKind {
	case "agent-durable-reservation":
		return h.MatchString(r.AgentRequestSHA256)
	case "platform-quiesce", "original-stopped-native":
		return r.AgentRequestSHA256 == ""
	default:
		return false
	}
}

// B's baseline/checkpoint anchor uses this STABLE identity. Actual phase is
// separately verified by current SQL; it is not permission encoded in a hash.
func OriginalAdoptionReservationIdentitySHA256(r OriginalAdoptionReservation) (string, error) {
	if !validOriginalAdoptionReservation(r) {
		return "", ErrGateFenceLost
	}
	r.Phase = ""
	raw, e := json.Marshal(r)
	if e != nil {
		return "", ErrGateFenceLost
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

func OriginalAdoptionReservationSHA256(r OriginalAdoptionReservation) (string, error) {
	if !validOriginalAdoptionReservation(r) {
		return "", ErrGateFenceLost
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return "", ErrGateFenceLost
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

type originalAdoptionGateRow struct {
	State                                    GateState
	Generation, Epoch, RowVersion            uint64
	Owner                                    string
	Lease, AcquisitionDeadline, HoldDeadline sql.NullTime
}

// Private construction from a live same-transaction SQL check. This object
// authenticates a gate observation, NOT a complete writer census/stop proof.
type VerifiedOriginalAdoptionReservation struct {
	mu           sync.Mutex
	origin       *VerifiedOriginalAdoptionReservation
	ctx          context.Context
	tx           *sql.Tx
	pin          OriginalAdoptionDatabasePin
	claim        OriginalAdoptionReservation
	row          originalAdoptionGateRow
	until, floor time.Time
	failed       bool
}

func (*VerifiedOriginalAdoptionReservation) MarshalJSON() ([]byte, error) {
	return nil, ErrGateFenceLost
}

func readOriginalAdoptionGate(ctx context.Context, tx *sql.Tx, pin OriginalAdoptionDatabasePin, claim OriginalAdoptionReservation) (originalAdoptionGateRow, time.Time, time.Time, error) {
	var row originalAdoptionGateRow
	var account, uuid, name, zone string
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6),@@session.time_zone").Scan(&account, &uuid, &name, &now, &zone) != nil || account != pin.Account || uuid != pin.ServerUUID || name != pin.Database || zone != "+00:00" || now.IsZero() || now.Before(claim.NotBefore) || !now.Before(claim.ExpiresAt) {
		return row, time.Time{}, time.Time{}, ErrGateFenceLost
	}
	if tx.QueryRowContext(ctx, `SELECT gate_state,generation,fencing_token,COALESCE(lock_owner,''),row_version,lease_expires_at,acquisition_deadline_at,absolute_hold_deadline_at FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? AND lock_name='system_backup_capture_gate' FOR SHARE`, claim.InstallationID, claim.Scope).Scan(&row.State, &row.Generation, &row.Epoch, &row.Owner, &row.RowVersion, &row.Lease, &row.AcquisitionDeadline, &row.HoldDeadline) != nil {
		return row, time.Time{}, time.Time{}, ErrGateFenceLost
	}
	wantEpoch := claim.AcquisitionEpoch
	if claim.Phase != GateAcquiring {
		wantEpoch++
	}
	if row.State != claim.Phase || row.Generation != claim.GateGeneration || row.Epoch != wantEpoch || row.Owner != claim.GateOwner || row.RowVersion < claim.AcquisitionRowVersion || !row.Lease.Valid || !now.Before(row.Lease.Time) || !row.AcquisitionDeadline.Valid {
		return row, time.Time{}, time.Time{}, ErrGateFenceLost
	}
	until := claim.ExpiresAt
	if row.Lease.Time.Before(until) {
		until = row.Lease.Time
	}
	if claim.Phase == GateAcquiring {
		if row.HoldDeadline.Valid || !now.Before(row.AcquisitionDeadline.Time) {
			return row, time.Time{}, time.Time{}, ErrGateFenceLost
		}
		if row.AcquisitionDeadline.Time.Before(until) {
			until = row.AcquisitionDeadline.Time
		}
	} else {
		if !row.HoldDeadline.Valid || !now.Before(row.HoldDeadline.Time) {
			return row, time.Time{}, time.Time{}, ErrGateFenceLost
		}
		if row.HoldDeadline.Time.Before(until) {
			until = row.HoldDeadline.Time
		}
	}
	return row, now, until, nil
}

// Call in the original caller tx BEFORE participant/source/evidence/KEK locks.
// No gate creation/transition, renewal, native IO, new tx or commit occurs here.
func LockOriginalAdoptionReservation(ctx context.Context, tx *sql.Tx, pin OriginalAdoptionDatabasePin, claim OriginalAdoptionReservation) (*VerifiedOriginalAdoptionReservation, error) {
	if absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || tx == nil || !validOriginalAdoptionReservation(claim) || pin.ServerUUID != claim.ServerUUID || pin.Database != claim.Database || pin.Account == "" || len(pin.Account) > 256 || strings.Count(pin.Account, "@") != 1 {
		return nil, ErrGateFenceLost
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrGateFenceLost
	}
	row, observed, until, e := readOriginalAdoptionGate(ctx, tx, pin, claim)
	if e != nil {
		return nil, e
	}
	if deadline.Before(until) {
		until = deadline
	}
	if !time.Now().Before(until) {
		return nil, ErrGateFenceLost
	}
	p := &VerifiedOriginalAdoptionReservation{ctx: ctx, tx: tx, pin: pin, claim: claim, row: row, until: until, floor: observed}
	p.origin = p
	return p, nil
}

func (p *VerifiedOriginalAdoptionReservation) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed {
		return time.Time{}
	}
	return p.until
}
func (p *VerifiedOriginalAdoptionReservation) Data() OriginalAdoptionReservation {
	if p == nil {
		return OriginalAdoptionReservation{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed {
		return OriginalAdoptionReservation{}
	}
	return p.claim
}
func (p *VerifiedOriginalAdoptionReservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return ErrGateFenceLost
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fail := func() error { p.failed = true; return ErrGateFenceLost }
	if p.origin != p || p.failed || absentExecutionDependency(ctx) || !reflect.TypeOf(ctx).Comparable() || ctx != p.ctx || ctx.Err() != nil || tx != p.tx || now.IsZero() || now.Before(p.claim.NotBefore) || !p.floor.IsZero() && now.Before(p.floor) || !now.Before(p.until) || !time.Now().Before(p.until) {
		return fail()
	}
	row, sampled, until, e := readOriginalAdoptionGate(ctx, tx, p.pin, p.claim)
	if e != nil || row != p.row || until.Before(p.until) || sampled.Before(now) || sampled.Before(p.floor) {
		return fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(sampled) || tail.Before(now) || !p.floor.IsZero() && tail.Before(p.floor) || !tail.Before(p.until) || ctx.Err() != nil {
		return fail()
	}
	p.floor = tail
	return nil
}
