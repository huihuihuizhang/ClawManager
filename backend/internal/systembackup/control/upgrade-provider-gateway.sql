-- Install explicitly in the provider gateway control DB. Never auto-installed.
-- Retain claims for the lifetime of the immutable provider root. Removing one
-- could replay a previously uncertain write after a gateway restart.
CREATE TABLE IF NOT EXISTS system_backup_gateway_dispatch (
  scope_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  action_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  request_json MEDIUMBLOB NOT NULL,
  reservation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  created_at_ms BIGINT NOT NULL,
  PRIMARY KEY (scope_hash, key_hash),
  UNIQUE KEY gateway_action (scope_hash, action_id)
) ENGINE=InnoDB;
