-- D-owned registration authentication and metadata reservation runtime.
-- Migration runner exclusion/capture gates apply. No user enrollment, session,
-- registry, configuration or signing identity is created by this migration.
-- Schema metadata only: never dump/restore seeds, sessions, revocations or
-- live reservation counters as backup business data.
CREATE TABLE IF NOT EXISTS system_backup_admin_revocations (
 origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 user_id INT NOT NULL,
 revoked_before DATETIME(6) NOT NULL,
 PRIMARY KEY(origin_installation_id,user_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_totp_credentials (
 origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 user_id INT NOT NULL,
 encrypted_seed VARBINARY(128) NULL,
 credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 confirmed BOOLEAN NOT NULL DEFAULT FALSE,
 pending_until DATETIME(6) NULL,
 last_step BIGINT NOT NULL DEFAULT -1,
 failures INT UNSIGNED NOT NULL DEFAULT 0,
 locked_until DATETIME(6) NULL,
 PRIMARY KEY(origin_installation_id,user_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
-- Conservative, monotonic admission reserve. Reconciliation/reset requires a
-- quiesced measured baseline; automatic statistics refresh never clears it.
CREATE TABLE IF NOT EXISTS system_backup_metadata_reservations (
 id TINYINT PRIMARY KEY,
 sample_at DATETIME(6) NOT NULL,
 reserved_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
 CHECK(id=1)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS system_backup_admin_sessions (
 origin_installation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 session_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 user_id INT NOT NULL,
 subject VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 credential_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 expires_at DATETIME(6) NOT NULL,
 revoked BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(origin_installation_id,session_sha256),
 KEY idx_d_admin_sessions_user(user_id),
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
