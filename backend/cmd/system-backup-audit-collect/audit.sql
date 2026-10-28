SELECT JSON_OBJECT(
'server_uuid',@@server_uuid,'database',DATABASE(),
'operation',JSON_OBJECT('id',o.id,'public_id',o.public_id,'installation_id',o.origin_installation_id,'actor_id',o.actor_id,'operation_type',o.operation_type,'endpoint',o.endpoint,'status',o.status,'idempotency_key',o.idempotency_key,'request_hash',o.request_hash,'evidence_id',o.target_public_id),
'admission',JSON_OBJECT('operation_id',a.operation_id,'operation_public_id',a.operation_public_id,'installation_id',a.origin_installation_id,'evidence_id',a.evidence_public_id,'intent_audit_id',a.intent_audit_id,'size_bytes',a.receipt_size_bytes,'sha256',a.receipt_sha256,'body',CAST(a.receipt_canonical_json AS JSON)),
'intent',JSON_OBJECT('id',i.id,'user_id',i.user_id,'action',i.action,'resource_type',i.resource_type,'resource_id',i.resource_id,'body',i.details),
'result',JSON_OBJECT('id',r.id,'user_id',r.user_id,'action',r.action,'resource_type',r.resource_type,'resource_id',r.resource_id,'body',r.details),
'result_link',JSON_OBJECT('operation_id',l.operation_id,'operation_public_id',l.operation_public_id,'installation_id',l.origin_installation_id,'evidence_id',l.evidence_public_id,'intent_audit_id',l.intent_audit_id,'result_audit_id',l.result_audit_id,'size_bytes',l.result_size_bytes,'sha256',l.result_sha256),
'nonce_count',(SELECT COUNT(*) FROM system_backup_v2_strong_auth_nonces n WHERE n.operation_id=o.id AND n.audit_log_id=i.id AND n.origin_installation_id=o.origin_installation_id AND n.endpoint=o.endpoint AND n.idempotency_key=o.idempotency_key AND n.request_hash=o.request_hash AND n.subject_sha256=JSON_UNQUOTE(JSON_EXTRACT(CAST(a.receipt_canonical_json AS JSON),'$.subject_sha256')) AND n.session_sha256=JSON_UNQUOTE(JSON_EXTRACT(CAST(a.receipt_canonical_json AS JSON),'$.session_sha256')))
) FROM system_backup_v2_operations o
LEFT JOIN system_backup_v2_download_admission_receipts a ON a.operation_id=o.id
LEFT JOIN audit_logs i ON i.id=a.intent_audit_id
LEFT JOIN system_backup_v2_download_result_receipts l ON l.operation_id=o.id
LEFT JOIN audit_logs r ON r.id=l.result_audit_id
WHERE o.public_id=? LIMIT 2;
