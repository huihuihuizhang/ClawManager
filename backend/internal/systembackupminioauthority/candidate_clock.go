package systembackupminioauthority

import (
	"context"
	"time"
)

// ControlledSQLReader is structurally satisfied by the ORIGINAL
// systembackupproducer.BootstrapSQL/BootstrapReadSQL view. Unlike raw *sql.Tx,
// it shares that transaction's SampleTime floor and sticky failure state.
// Only the trusted terminal composition supplies this existing view.
type ControlledSQLReader interface {
	SQLReader
	SampleTime(context.Context) (time.Time, error)
}

// ReadSQLCurrentCandidate is the explicit candidate SELECT-only entry. A raw
// *sql.Tx cannot implement it, so this path cannot silently use a raw clock.
// All source queries retain original FOR SHARE and same-transaction semantics.
func ReadSQLCurrentCandidate(ctx context.Context, q ControlledSQLReader, pin SQLTrustPin) (*SQLCurrentSnapshot, error) {
	return readSQLCurrent(ctx, q, pin, false)
}

func sampleControlledSQL(ctx context.Context, q ControlledSQLReader) (string, string, string, time.Time, error) {
	var account, server, database string
	before, e := q.SampleTime(ctx)
	if e != nil || !validTime(before) || ctx.Err() != nil {
		return "", "", "", time.Time{}, ErrRecord
	}
	// SQL identity has no clock expression: ALL authoritative time goes through
	// the original guard. Never SELECT/bind a second raw UTC_TIMESTAMP here.
	if q.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE()`).Scan(&account, &server, &database) != nil {
		return "", "", "", time.Time{}, ErrRecord
	}
	after, e := q.SampleTime(ctx)
	if e != nil || !validTime(after) || after.Before(before) || ctx.Err() != nil {
		return "", "", "", time.Time{}, ErrRecord
	}
	return account, server, database, after, nil
}
