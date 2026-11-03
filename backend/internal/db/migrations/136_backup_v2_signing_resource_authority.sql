-- Original acceptance/catalog signer RESOURCE authority; never capture/task authority.
-- Additive schema only. No login, seed, permission approval, config or task rows.
-- Installer: original admin/RBAC -> purpose head -> exact grant FOR UPDATE.
-- Two-purpose work locks acceptance_record then catalog_record, head -> grant.
-- Consumer: existing capture/MinIO prefixes first, same purpose order FOR SHARE.
-- All provider/network/signature operations stay outside SQL transactions.
CREATE TABLE system_backup_signing_resource_heads (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 purpose ENUM('acceptance_record','catalog_record') CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
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
 PRIMARY KEY(installation_id,enrollment_id,authority_id,purpose),
 CONSTRAINT sb_signer_head_data CHECK(installation_id<>'' AND enrollment_id<>'' AND authority_id<>'' AND current_grant_id<>'' AND permission_epoch=1 AND current_grant_revision=1 AND row_version>0 AND row_version<=9007199254740991 AND ((head_state='active' AND head_revision=1) OR (head_state='revoked' AND head_revision=2)) AND head_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_head)>0 AND OCTET_LENGTH(signed_head)<=65536 AND JSON_VALID(CONVERT(signed_head USING utf8mb4)) AND head_sha256=LOWER(SHA2(signed_head,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE system_backup_signing_resource_grants (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 purpose ENUM('acceptance_record','catalog_record') CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_revision BIGINT UNSIGNED NOT NULL,
 permission_epoch BIGINT UNSIGNED NOT NULL,
 record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_record MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 grant_state ENUM('active','revoked') NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,enrollment_id,authority_id,purpose,grant_id,record_revision),
 CONSTRAINT sb_signer_grant_head FOREIGN KEY(installation_id,enrollment_id,authority_id,purpose) REFERENCES system_backup_signing_resource_heads(installation_id,enrollment_id,authority_id,purpose) ON DELETE RESTRICT,
 CONSTRAINT sb_signer_grant_data CHECK(grant_id<>'' AND record_revision=1 AND permission_epoch=1 AND row_version>0 AND row_version<=9007199254740991 AND record_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_record)>0 AND OCTET_LENGTH(signed_record)<=262144 AND JSON_VALID(CONVERT(signed_record USING utf8mb4)) AND record_sha256=LOWER(SHA2(signed_record,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
