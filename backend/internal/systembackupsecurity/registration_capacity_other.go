//go:build !linux

package systembackupsecurity

import (
	"context"
	"database/sql"
)

func collectRegistrationCapacity(context.Context, *sql.Conn, CapacityCollectorConfig) (CapacityReport, error) {
	return CapacityReport{}, ErrRegistrationUnavailable
}
