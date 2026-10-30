-- Original installation-owner facts. Config/bootstrap writers must never seed
-- these tables from candidate JSON or committed config. Owner updates take the
-- same installation KEK fence as admission, then atomically append history,
-- CAS the current record and advance the fence epoch.
CREATE TABLE IF NOT EXISTS system_backup_installation_kek_authority (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_record MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 record_revision VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,identity_hash,registry_version),
 CONSTRAINT sb_install_kek_fence FOREIGN KEY(installation_id) REFERENCES system_backup_v2_kek_fences(installation_id) ON DELETE RESTRICT,
 CONSTRAINT sb_install_kek_data CHECK(row_version>0 AND identity_hash REGEXP '^[a-f0-9]{64}$' AND record_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_record)<=65536 AND JSON_VALID(CONVERT(signed_record USING utf8mb4)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_backup_installation_kek_authority_history (
 installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 identity_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 registry_version VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 row_version BIGINT UNSIGNED NOT NULL,
 record_revision VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 record_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 signed_record MEDIUMBLOB NOT NULL,
 signature VARBINARY(64) NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 PRIMARY KEY(installation_id,identity_hash,registry_version,row_version),
 UNIQUE KEY sb_install_kek_revision(installation_id,identity_hash,registry_version,record_revision),
 CONSTRAINT sb_install_kek_history_fence FOREIGN KEY(installation_id) REFERENCES system_backup_v2_kek_fences(installation_id) ON DELETE RESTRICT,
 CONSTRAINT sb_install_kek_history_data CHECK(row_version>0 AND identity_hash REGEXP '^[a-f0-9]{64}$' AND record_sha256 REGEXP '^[a-f0-9]{64}$' AND OCTET_LENGTH(signature)=64 AND OCTET_LENGTH(signed_record)<=65536 AND JSON_VALID(CONVERT(signed_record USING utf8mb4)))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
