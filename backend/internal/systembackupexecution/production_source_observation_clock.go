package systembackupexecution

import (
	"time"

	d "clawreef/internal/systembackupdispatch"
)

const sourceObservationSQLTimeLayout = "2006-01-02 15:04:05.000000"

// worker.OpenDatabase deliberately leaves ParseTime=false to preserve raw
// capture cells. UTC_TIMESTAMP(6) therefore arrives as MySQL DATETIME bytes,
// while other independently constructed source readers may return time.Time.
// Decode only this UTC microsecond SQL clock; do not change the source driver,
// raw row representation, signed original window or wall-clock deadline.
func decodeSourceObservationSQLTime(value any) (time.Time, error) {
	var observed time.Time
	switch clock := value.(type) {
	case time.Time:
		_, offset := clock.Zone()
		if offset != 0 || clock.Nanosecond()%1000 != 0 {
			return time.Time{}, d.ErrNotReady
		}
		observed = clock.UTC()
	case []byte:
		return decodeSourceObservationSQLTime(string(clock))
	case string:
		if len(clock) != len(sourceObservationSQLTimeLayout) {
			return time.Time{}, d.ErrNotReady
		}
		parsed, err := time.Parse(sourceObservationSQLTimeLayout, clock)
		if err != nil || parsed.Format(sourceObservationSQLTimeLayout) != clock {
			return time.Time{}, d.ErrNotReady
		}
		observed = parsed
	default:
		return time.Time{}, d.ErrNotReady
	}
	if observed.IsZero() || observed.Year() < 1000 || observed.Year() > 9999 {
		return time.Time{}, d.ErrNotReady
	}
	return observed, nil
}
