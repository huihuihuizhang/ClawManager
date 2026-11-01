package systembackup

import (
	"errors"
	"log"

	"github.com/go-sql-driver/mysql"
)

// Reasons are code literals at the existing rejected acquisition boundaries.
// No owner, scope, claim, SQL text/arguments or driver Message is logged.
func logGateAcquisitionBusy(reason string, err error) {
	var number uint16
	state := ""
	var driver *mysql.MySQLError
	if errors.As(err, &driver) {
		number = driver.Number
		valid := true
		for _, b := range driver.SQLState {
			if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z') {
				valid = false
			}
		}
		if valid {
			state = string(driver.SQLState[:])
		}
	}
	log.Printf("[system-backup-gate] stage=begin-acquire-rejected reason=%s sql_number=%d sql_state=%s", reason, number, state)
}
