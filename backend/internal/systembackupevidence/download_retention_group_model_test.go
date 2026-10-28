package systembackupevidence

import (
	"database/sql/driver"
	"errors"
)

// Mirrors actual persisted projections, not a fabricated CommittedDownload
// capability. Tests can replace one independently returned SQL row, including
// a rehashed receipt, to exercise cold reconstruction and final rechecks.
func (d *admissionTxDB) retentionGroupQuery(q string, args []driver.NamedValue) (driver.Rows, bool, error) {
	var values []driver.Value
	switch q {
	case downloadRetentionOperationSQL:
		if d.ownerLocked || len(d.m.op) != 14 || len(args) != 2 || args[0].Value != d.m.op[1] || args[1].Value != d.m.op[0] {
			return nil, true, errors.New("group L3 operation scope/order")
		}
		d.opKeyLocked = true
		d.calls = append(d.calls, "group-L3")
		o := d.m.op
		values = []driver.Value{int64(73), o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[9], o[12], int64(1)}
	case downloadRetentionReceiptSQL:
		if len(d.m.receipt) != 16 || len(args) != 2 || args[0].Value != int64(73) || args[1].Value != d.m.op[1] {
			return nil, true, errors.New("group receipt scope")
		}
		values = append([]driver.Value(nil), d.m.receipt...)
	case downloadRetentionNonceSQL:
		if !d.ownerLocked || args[0].Value != int64(73) {
			return nil, true, errors.New("group nonce before original owner/ref or wrong operation")
		}
		d.calls = append(d.calls, "group-L5")
		if len(d.nonce) != 16 || d.groupFault == "nonce_missing" {
			return &admissionTxRows{width: 19}, true, nil
		}
		n := d.nonce
		values = []driver.Value{int64(95), n[0], n[1], n[2], n[3], n[4], n[5], "getSystemBackupEvidence", n[6], n[7], n[8], n[9], d.consumed, n[10], nil, n[11], n[12], d.consumed, "system-backup-strong-auth-nonce.v1"}
	case downloadRetentionAuditSQL:
		if !d.ownerLocked || d.groupReads[downloadRetentionNonceSQL] == 0 {
			return nil, true, errors.New("group audit before original L5")
		}
		d.calls = append(d.calls, "group-L7")
		switch args[0].Value {
		case d.id:
			values = []driver.Value{d.user, d.action, d.kind, d.resource, append([]byte(nil), d.body...), d.created}
		case int64(1730):
			values = []driver.Value{int64(42), "system_backup.evidence_download.result", "system_backup", nil, append([]byte(nil), d.resultBody...), d.resultCreated}
		default:
			return nil, true, errors.New("unexpected group audit ID")
		}
	default:
		return nil, false, nil
	}
	d.groupReads[q]++
	if d.groupFault == "sql_error" {
		return nil, true, errors.New("PRIVATE group SQL error")
	}
	if d.groupMutate != nil {
		values = d.groupMutate(q, d.groupReads[q], values)
	}
	if values == nil {
		return &admissionTxRows{width: 1}, true, nil
	}
	// Model the IF(OCTET_LENGTH) transport boundary before materialization.
	if q == downloadRetentionReceiptSQL {
		for _, index := range []int{6, 9} {
			if b, ok := values[index].([]byte); ok && (len(b) < 2 || len(b) > 8192) {
				values[index] = nil
			}
		}
	}
	if q == downloadRetentionAuditSQL {
		if b, ok := values[4].([]byte); ok && (len(b) < 2 || len(b) > 8192) {
			values[4] = nil
		}
	}
	if q == downloadRetentionNonceSQL && d.groupFault == "nonce_duplicate" {
		return &admissionTxRows{width: 19, data: [][]driver.Value{values, values}}, true, nil
	}
	return admissionTxRow(values...), true, nil
}
