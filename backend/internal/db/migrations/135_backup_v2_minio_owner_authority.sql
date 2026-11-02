-- ORIGINAL MinIO authority, distinct from capture signing/capability caches.
-- Additive schema only: no seed, approval, enabled-config or task rows.
-- Global lock order: admin/RBAC -> capture owner (if needed) -> MinIO head
-- -> selected grant -> refs in purpose ASCII order -> operation/config locks.
-- Issue/revoke uses the same prefix; never acquire an earlier lock afterward.
-- Consumer SELECT only; reviewed owner installer INSERT/UPDATE, never DELETE.
-- Signatures, canonical payload/index parity, exact five-ref membership, epoch
-- and CAS semantics are enforced by independently pinned owner/consumer code.
-- No network, credential read/hash, native probe, signing or commit inside L2.
CREATE TABLE system_backup_minio_owner_heads (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 head_revision BIGINT UNSIGNED NOT NULL,
 permission_epoch BIGINT UNSIGNED NOT NULL,
 current_grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 current_grant_revision BIGINT UNSIGNED NOT NULL,
 head_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_head MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 head_state ENUM('active','revoked') NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,enrollment_id,authority_id),
 CONSTRAINT sb_minio_head_data CHECK(installation_id<>'' AND enrollment_id<>'' AND authority_id<>'' AND current_grant_id<>'' AND head_revision>0 AND permission_epoch>0 AND current_grant_revision>0 AND row_version>0 AND head_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_head)>0 AND OCTET_LENGTH(signed_head)<=262144 AND JSON_VALID(CONVERT(signed_head USING utf8mb4)) AND head_sha256=LOWER(SHA2(signed_head,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE system_backup_minio_owner_grants (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_revision BIGINT UNSIGNED NOT NULL,
 permission_epoch BIGINT UNSIGNED NOT NULL,
 record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_record MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 grant_state ENUM('active','revoked') NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,enrollment_id,authority_id,grant_id,record_revision),
 CONSTRAINT sb_minio_grant_head FOREIGN KEY(installation_id,enrollment_id,authority_id) REFERENCES system_backup_minio_owner_heads(installation_id,enrollment_id,authority_id) ON DELETE RESTRICT,
 CONSTRAINT sb_minio_grant_data CHECK(grant_id<>'' AND record_revision>0 AND permission_epoch>0 AND row_version>0 AND record_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_record)>0 AND OCTET_LENGTH(signed_record)<=262144 AND JSON_VALID(CONVERT(signed_record USING utf8mb4)) AND record_sha256=LOWER(SHA2(signed_record,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE system_backup_minio_owner_refs (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_revision BIGINT UNSIGNED NOT NULL,
 purpose ENUM('artifact_delete','artifact_read','artifact_write','catalog_append','catalog_read') NOT NULL,
 descriptor_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 provider_identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 scope_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 identity_version VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 ref_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_ref MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 ref_state ENUM('active','revoked') NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 PRIMARY KEY(installation_id,enrollment_id,authority_id,grant_id,record_revision,purpose),
 CONSTRAINT sb_minio_ref_grant FOREIGN KEY(installation_id,enrollment_id,authority_id,grant_id,record_revision) REFERENCES system_backup_minio_owner_grants(installation_id,enrollment_id,authority_id,grant_id,record_revision) ON DELETE RESTRICT,
 CONSTRAINT sb_minio_ref_data CHECK(record_revision>0 AND row_version>0 AND identity_version<>'' AND descriptor_sha256 REGEXP '^[a-f0-9]{64}$' AND provider_identity_hash REGEXP '^[a-f0-9]{64}$' AND scope_hash REGEXP '^[a-f0-9]{64}$' AND identity_hash REGEXP '^[a-f0-9]{64}$' AND ref_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_ref)>0 AND OCTET_LENGTH(signed_ref)<=65536 AND JSON_VALID(CONVERT(signed_ref USING utf8mb4)) AND ref_sha256=LOWER(SHA2(signed_ref,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
