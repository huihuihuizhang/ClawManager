package domain

import (
	"context"
	"database/sql"
)

// SourceInstance is the credential-free discovery projection shared by the
// legacy lab wrapper and the public runner. It contains no task/control state.
type SourceInstance struct {
	ID, UserID, Generation                                              int
	Mode, Type, Backend, Variant, OS, Status, Pod, Namespace, Workspace string
}

// ReadSourceInstances performs only a bounded SELECT in the caller's existing
// read-only snapshot. It cannot create/claim tasks or commit the transaction.
func ReadSourceInstances(ctx context.Context, tx *sql.Tx) ([]SourceInstance, error) {
	if tx == nil {
		return nil, ErrSchema
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,user_id,instance_mode,type,runtime_type,COALESCE(runtime_variant,''),os_type,status,runtime_generation,COALESCE(pod_name,''),COALESCE(pod_namespace,''),COALESCE(workspace_path,'') FROM instances ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceInstance
	for rows.Next() {
		var i SourceInstance
		if err := rows.Scan(&i.ID, &i.UserID, &i.Mode, &i.Type, &i.Backend, &i.Variant, &i.OS, &i.Status, &i.Generation, &i.Pod, &i.Namespace, &i.Workspace); err != nil {
			return nil, err
		}
		out = append(out, i)
		if len(out) > 9998 {
			return nil, ErrCapacity
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
