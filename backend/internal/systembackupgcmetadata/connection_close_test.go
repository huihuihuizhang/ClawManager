package systembackupgcmetadata

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Use the real database/sql pool-return path: an idle limit of zero makes
// Conn.Close invoke the physical driver's Close before Read can return.
type metadataCloseConnector struct {
	model *metadataModel
	close func(context.Context) error
}

func (c metadataCloseConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if _, err := c.model.Connect(ctx); err != nil {
		return nil, err
	}
	return &metadataCloseConn{metadataModel: c.model, close: func() error { return c.close(ctx) }}, nil
}
func (metadataCloseConnector) Driver() driver.Driver { return metadataDriver{} }

type metadataCloseConn struct {
	*metadataModel
	close func() error
}

func (c *metadataCloseConn) Close() error { return c.close() }

func TestProgramObservationAfterConnectionClose(t *testing.T) {
	for _, mode := range []string{"live", "canceled", "deadline", "close_error"} {
		t.Run(mode, func(t *testing.T) {
			m, s := fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			}
			defer cancel()
			closes := 0
			db := sql.OpenDB(metadataCloseConnector{model: m, close: func(readCtx context.Context) error {
				closes++
				if m.identityReads != 2 || m.grantReads != 2 || m.openRows != 0 {
					t.Error("close did not follow all final SQL checks")
				}
				if ctx.Err() != nil {
					t.Error("request expired before entering the close boundary")
				}
				switch mode {
				case "canceled":
					cancel()
				case "deadline":
					<-readCtx.Done()
				case "close_error":
					return errors.New("PRIVATE driver close failure")
				}
				return nil
			}})
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(0)
			t.Cleanup(func() { db.Close() })
			s.c.DB = db
			o, err := s.Read(ctx)
			if closes != 1 || db.Stats().OpenConnections != 0 || m.connects != 1 || m.begins != 0 || m.writes != 0 {
				t.Fatal("observer close changed ownership or issued work", closes, db.Stats())
			}
			// Pool return does not report a physical driver Close error. This
			// control observes data only; it proves no remote cleanup or lock release.
			if mode == "live" || mode == "close_error" {
				if err != nil || o == (Observation{}) || o.Digests().ViewCreates.Rows != 1 {
					t.Fatal("live observation was lost", err)
				}
				return
			}
			if !errors.Is(err, ErrUnavailable) || o != (Observation{}) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("late or failed close released an observation", err)
			}
			if mode == "canceled" && !errors.Is(ctx.Err(), context.Canceled) || mode == "deadline" && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("wrong cancellation cause", ctx.Err())
			}
		})
	}
}
