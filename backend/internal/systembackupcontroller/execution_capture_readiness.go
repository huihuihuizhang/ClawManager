package systembackupcontroller

import (
	d "clawreef/internal/systembackupdispatch"
	"context"
)

// Ready checks the exact journal schema/read permissions before a scheduler
// claims anything. Missing new metadata is not discovered after source pause.
// It does not publish production readiness or grant capture/restore authority.
func (g SQLCaptureGate) Ready(ctx context.Context) error {
	if !g.ready() || g.AcquisitionTimeout%1000000000 != 0 || g.HoldTimeout%1000000000 != 0 {
		return d.ErrNotReady
	}
	for _, q := range []string{
		"SELECT gate_generation,acquire_token,held_token,registry_sha256,writers_json,collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE 1=0",
		"SELECT resource_kind,create_dispatched,request_sha256,binding_json,process_json,revoked,result_cipher,result_key_ref,result_sha256,stopped_at FROM system_backup_v2_runtime_resources WHERE 1=0",
		"SELECT writer_id,original_json,original_sha256,paused,resumed,row_version FROM system_backup_v2_runtime_writers WHERE 1=0",
		"SELECT pod_uid,proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE 1=0",
	} {
		rows, e := g.Authority.DB.QueryContext(ctx, q)
		if e != nil {
			return e
		}
		if e = rows.Close(); e != nil {
			return e
		}
	}
	return nil
}
