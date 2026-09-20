CREATE TABLE IF NOT EXISTS system_image_settings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  instance_type VARCHAR(50) NOT NULL,
  runtime_type ENUM('desktop', 'shell', 'gateway') NOT NULL DEFAULT 'desktop',
  runtime_variant VARCHAR(32) NOT NULL DEFAULT '',
  display_name VARCHAR(255) NOT NULL,
  image VARCHAR(500) NOT NULL,
  is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_instance_type (instance_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @system_image_runtime_type_column_exists = (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_image_settings'
    AND COLUMN_NAME = 'runtime_type'
);
SET @system_image_runtime_type_column_sql = IF(
  @system_image_runtime_type_column_exists = 0,
  'ALTER TABLE system_image_settings ADD COLUMN runtime_type ENUM(''desktop'', ''shell'', ''gateway'') NOT NULL DEFAULT ''desktop'' AFTER instance_type',
  'SELECT 1'
);
PREPARE system_image_runtime_type_column_stmt FROM @system_image_runtime_type_column_sql;
EXECUTE system_image_runtime_type_column_stmt;
DEALLOCATE PREPARE system_image_runtime_type_column_stmt;

ALTER TABLE system_image_settings
  MODIFY COLUMN runtime_type ENUM('desktop', 'shell', 'gateway') NOT NULL DEFAULT 'desktop';

SET @system_image_runtime_variant_column_exists = (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_image_settings'
    AND COLUMN_NAME = 'runtime_variant'
);
SET @system_image_runtime_variant_column_sql = IF(
  @system_image_runtime_variant_column_exists = 0,
  'ALTER TABLE system_image_settings ADD COLUMN runtime_variant VARCHAR(32) NOT NULL DEFAULT '''' AFTER runtime_type',
  'SELECT 1'
);
PREPARE system_image_runtime_variant_column_stmt FROM @system_image_runtime_variant_column_sql;
EXECUTE system_image_runtime_variant_column_stmt;
DEALLOCATE PREPARE system_image_runtime_variant_column_stmt;

SET @system_image_is_enabled_column_exists = (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_image_settings'
    AND COLUMN_NAME = 'is_enabled'
);
SET @system_image_is_enabled_column_sql = IF(
  @system_image_is_enabled_column_exists = 0,
  'ALTER TABLE system_image_settings ADD COLUMN is_enabled BOOLEAN NOT NULL DEFAULT TRUE',
  'SELECT 1'
);
PREPARE system_image_is_enabled_column_stmt FROM @system_image_is_enabled_column_sql;
EXECUTE system_image_is_enabled_column_stmt;
DEALLOCATE PREPARE system_image_is_enabled_column_stmt;

SET @system_image_single_column_unique_index_name = (
  SELECT INDEX_NAME
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_image_settings'
    AND NON_UNIQUE = 0
    AND INDEX_NAME <> 'PRIMARY'
  GROUP BY INDEX_NAME
  HAVING COUNT(*) = 1
    AND SUM(COLUMN_NAME = 'instance_type') = 1
  LIMIT 1
);
SET @system_image_single_column_unique_index_sql = IF(
  @system_image_single_column_unique_index_name IS NOT NULL,
  CONCAT(
    'ALTER TABLE system_image_settings DROP INDEX `',
    REPLACE(@system_image_single_column_unique_index_name, '`', '``'),
    '`'
  ),
  'SELECT 1'
);
PREPARE system_image_single_column_unique_index_stmt FROM @system_image_single_column_unique_index_sql;
EXECUTE system_image_single_column_unique_index_stmt;
DEALLOCATE PREPARE system_image_single_column_unique_index_stmt;

SET @system_image_instance_type_index_exists = (
  SELECT COUNT(*)
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'system_image_settings'
    AND INDEX_NAME = 'idx_instance_type'
);
SET @system_image_instance_type_index_sql = IF(
  @system_image_instance_type_index_exists = 0,
  'CREATE INDEX idx_instance_type ON system_image_settings (instance_type)',
  'SELECT 1'
);
PREPARE system_image_instance_type_index_stmt FROM @system_image_instance_type_index_sql;
EXECUTE system_image_instance_type_index_stmt;
DEALLOCATE PREPARE system_image_instance_type_index_stmt;
