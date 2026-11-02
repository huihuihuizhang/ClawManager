package systembackupexecution

import (
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

func TestSourceObservationSQLClockPreservesRawDriverAndUTCPrecision(t *testing.T) {
	want := time.Date(2026, 11, 2, 20, 52, 20, 123456000, time.UTC)
	for _, value := range []any{want, []byte("2026-11-02 20:52:20.123456"), "2026-11-02 20:52:20.123456"} {
		actual, err := decodeSourceObservationSQLTime(value)
		if err != nil || !actual.Equal(want) || actual.Location() != time.UTC {
			t.Fatal("actual MySQL UTC clock representation rejected or changed", err)
		}
	}
	for _, value := range []any{nil, int64(20261102), time.Time{}, want.Add(time.Nanosecond), want.In(time.FixedZone("non-UTC", 3600)), []byte("2026-11-02 20:52:20"), "2026-11-02 20:52:20.12345", "2026-11-02 20:52:20.1234567", "2026-11-02T20:52:20.123456Z", "2026-11-02 20:52:20.123456+00:00", "2026-11-02 20:52:20,123456", "2026-02-30 20:52:20.123456", "0000-00-00 00:00:00.000000"} {
		if actual, err := decodeSourceObservationSQLTime(value); err != d.ErrNotReady || !actual.IsZero() {
			t.Fatal("ambiguous, non-UTC or non-microsecond clock accepted")
		}
	}
}
