package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func originalReservationFixture() OriginalAdoptionReservation {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return OriginalAdoptionReservation{Version: OriginalAdoptionReservationVersion, OperationID: strings.Repeat("a", 32), ReservationID: strings.Repeat("b", 32), InstallationID: "installation_original", ServerUUID: "12345678-1234-1234-1234-123456789abc", Database: "original_db", Scope: CaptureGateScope, GateOwner: "adoption:" + strings.Repeat("a", 32), GateGeneration: 4, AcquisitionEpoch: 5, AcquisitionRowVersion: 10, Phase: GateHeld, WriterID: "deployment/source/original-zero-replicas", SourceWritersSHA256: strings.Repeat("c", 64), ControlKind: "original-stopped-native", NativeRequestSHA256: strings.Repeat("d", 64), NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
}

func TestOriginalAdoptionReservationAnchorPreservesOriginalStoppedWithoutFakePID(t *testing.T) {
	r := originalReservationFixture()
	identity, e := OriginalAdoptionReservationIdentitySHA256(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, phase := range []GateState{GateAcquiring, GateHeld, GateReleasing} {
		r.Phase = phase
		h, e := OriginalAdoptionReservationIdentitySHA256(r)
		if e != nil || h != identity {
			t.Fatal("normal phase transition changed reservation identity")
		}
	}
	r.GateGeneration++
	h, e := OriginalAdoptionReservationIdentitySHA256(r)
	if e != nil || h == identity {
		t.Fatal("new generation retained old anchor")
	}
	r = originalReservationFixture()
	r.ControlKind = "agent-durable-reservation"
	if _, e := OriginalAdoptionReservationSHA256(r); e == nil {
		t.Fatal("Agent durable request fabricated without actual request hash")
	}
	r.AgentRequestSHA256 = strings.Repeat("e", 64)
	if _, e := OriginalAdoptionReservationSHA256(r); e != nil {
		t.Fatal(e)
	}
	r.ControlKind = "original-stopped-native"
	if _, e := OriginalAdoptionReservationSHA256(r); e == nil {
		t.Fatal("original stopped writer was relabelled as running Agent request")
	}
	if p, e := LockOriginalAdoptionReservation(context.Background(), nil, OriginalAdoptionDatabasePin{}, r); e == nil || p != nil {
		t.Fatal("DTO became actual SQL gate")
	}
}

// Deterministic SQL/source model only, not a native participant stop proof.
type originalReservationModel struct {
	claim OriginalAdoptionReservation
	now   time.Time
	owner string
	epoch uint64
}
type reservationConnector struct{ s *originalReservationModel }

func (c reservationConnector) Connect(context.Context) (driver.Conn, error) {
	return &reservationConn{s: c.s}, nil
}
func (c reservationConnector) Driver() driver.Driver { return reservationDriver{} }

type reservationDriver struct{}

func (reservationDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type reservationConn struct {
	s        *originalReservationModel
	readOnly bool
}

func (c *reservationConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("queryer only")
}
func (c *reservationConn) Close() error              { return nil }
func (c *reservationConn) Begin() (driver.Tx, error) { return reservationTx{}, nil }
func (c *reservationConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("original RR required")
	}
	c.readOnly = opts.ReadOnly
	return reservationTx{}, nil
}

type reservationTx struct{}

func (reservationTx) Commit() error   { return errors.New("read verifier may not commit") }
func (reservationTx) Rollback() error { return nil }

type reservationRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *reservationRows) Columns() []string { return r.columns }
func (r *reservationRows) Close() error      { return nil }
func (r *reservationRows) Next(v []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(v, r.values)
	return nil
}
func (c *reservationConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	if c.readOnly && strings.Contains(q, "FOR UPDATE") {
		return nil, errors.New("1792: locking read in READ ONLY transaction")
	}
	if strings.HasPrefix(q, "SELECT CURRENT_USER()") {
		return &reservationRows{columns: []string{"user", "uuid", "db", "now", "zone"}, values: []driver.Value{"installer@localhost", s.claim.ServerUUID, s.claim.Database, s.now, "+00:00"}}, nil
	}
	if strings.HasPrefix(q, "SELECT gate_state,") {
		var hold driver.Value
		if s.claim.Phase != GateAcquiring {
			hold = s.now.Add(40 * time.Second)
		}
		return &reservationRows{columns: []string{"state", "generation", "epoch", "owner", "version", "lease", "acquisition", "hold"}, values: []driver.Value{string(s.claim.Phase), int64(s.claim.GateGeneration), int64(s.epoch), s.owner, int64(s.claim.AcquisitionRowVersion + 1), s.now.Add(50 * time.Second), s.now.Add(20 * time.Second), hold}}, nil
	}
	if q == "SELECT UTC_TIMESTAMP(6)" {
		return &reservationRows{columns: []string{"now"}, values: []driver.Value{s.now}}, nil
	}
	return nil, errors.New("unexpected original query")
}

func TestOriginalAdoptionReservationChecksActualCurrentSQLIdentityAndEpoch(t *testing.T) {
	for _, fault := range []string{"unchanged", "owner-drift", "epoch-drift", "clock-rewind", "foreign-transaction", "read-only-transaction"} {
		t.Run(fault, func(t *testing.T) {
			claim := originalReservationFixture()
			now := time.Now().UTC().Truncate(time.Microsecond)
			state := &originalReservationModel{claim: claim, now: now, owner: claim.GateOwner, epoch: claim.AcquisitionEpoch + 1}
			db := sql.OpenDB(reservationConnector{state})
			defer db.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			opts := &sql.TxOptions{Isolation: sql.LevelRepeatableRead}
			if fault == "read-only-transaction" {
				opts.ReadOnly = true
			}
			tx, e := db.BeginTx(ctx, opts)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			pin := OriginalAdoptionDatabasePin{ServerUUID: claim.ServerUUID, Database: claim.Database, Account: "installer@localhost"}
			p, e := LockOriginalAdoptionReservation(ctx, tx, pin, claim)
			if e != nil {
				t.Fatal(e)
			}
			switch fault {
			case "owner-drift":
				state.owner = "adoption:" + strings.Repeat("f", 32)
			case "epoch-drift":
				state.epoch++
			case "clock-rewind":
				state.now = now.Add(-time.Microsecond)
			case "foreign-transaction":
				other, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				if e != nil {
					t.Fatal(e)
				}
				defer other.Rollback()
				tx = other
			}
			e = p.Recheck(ctx, tx, now)
			if (fault == "unchanged" || fault == "read-only-transaction") != (e == nil) {
				t.Fatal("actual gate decision", fault, e)
			}
			if fault != "unchanged" && fault != "read-only-transaction" && !p.ValidUntil().IsZero() {
				t.Fatal("failed current source remained usable")
			}
		})
	}
}
