-- The first deployed 049_add_ldap_login_alias.sql did not include the local-only
-- username constraint. Its filename is already recorded in schema_migrations,
-- so a later edit to 049 cannot repair existing installations.
SET @stmt = IF(
  (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'local_username_key') = 0,
  'ALTER TABLE users ADD COLUMN local_username_key VARCHAR(255) GENERATED ALWAYS AS (CASE WHEN auth_provider = ''local'' THEN username ELSE NULL END) STORED',
  'SELECT 1'
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @stmt = IF(
  (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND INDEX_NAME = 'uk_users_local_username') = 0,
  'ALTER TABLE users ADD UNIQUE KEY uk_users_local_username (local_username_key)',
  'SELECT 1'
);
PREPARE stmt FROM @stmt;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
