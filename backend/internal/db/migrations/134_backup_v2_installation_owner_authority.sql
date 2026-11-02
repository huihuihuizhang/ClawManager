-- Source-owner ledger, NOT config admission. No bootstrap seed/approval rows.
-- Independently enrolled issuer pins are deployed outside these tables.
-- Original L2 order: current users/admin -> exact owner head -> exact grant.
-- Owner revocation uses head -> grant and never locks producer/config afterward.
-- Bootstrap role: SELECT only on these two tables (MySQL 8.4 FOR SHARE).
-- Installer role: reviewed INSERT/UPDATE, no DELETE, schema or GRANT privilege;
-- revoke/issue writers must verify signatures and CAS row/head revisions.
CREATE TABLE system_backup_installation_owner_heads (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 head_revision BIGINT UNSIGNED NOT NULL,
 head_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_head MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 head_state ENUM('active','revoked') NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,enrollment_id),
 CONSTRAINT sb_owner_head_data CHECK(head_revision>0 AND row_version>0 AND head_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_head)>0 AND OCTET_LENGTH(signed_head)<=262144 AND JSON_VALID(CONVERT(signed_head USING utf8mb4)) AND head_sha256=LOWER(SHA2(signed_head,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE system_backup_installation_owner_grants (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 enrollment_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 grant_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_revision BIGINT UNSIGNED NOT NULL,
 record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_record MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 grant_state ENUM('active','revoked') NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,enrollment_id,grant_id,record_revision),
 CONSTRAINT sb_owner_grant_head FOREIGN KEY(installation_id,enrollment_id) REFERENCES system_backup_installation_owner_heads(installation_id,enrollment_id) ON DELETE RESTRICT,
 CONSTRAINT sb_owner_grant_data CHECK(record_revision>0 AND row_version>0 AND record_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_record)>0 AND OCTET_LENGTH(signed_record)<=262144 AND JSON_VALID(CONVERT(signed_record USING utf8mb4)) AND record_sha256=LOWER(SHA2(signed_record,256)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
