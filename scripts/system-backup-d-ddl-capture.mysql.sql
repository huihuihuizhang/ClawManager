-- Read-only MySQL 8.0/8.4 metadata capture. No business rows are selected.
-- AUTO_INCREMENT is intentionally excluded because it changes with data.

SELECT 'table_option', JSON_OBJECT(
  'table_name', t.TABLE_NAME,
  'engine', t.ENGINE,
  'table_collation', t.TABLE_COLLATION,
  'row_format', t.ROW_FORMAT,
  'create_options', t.CREATE_OPTIONS,
  'table_comment', t.TABLE_COMMENT
)
FROM information_schema.TABLES t
WHERE t.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = 'BASE TABLE'
UNION ALL
SELECT 'check', JSON_OBJECT(
  'table_name', tc.TABLE_NAME,
  'name', tc.CONSTRAINT_NAME,
  'clause', cc.CHECK_CLAUSE,
  'enforced', IF(tc.ENFORCED = 'YES', TRUE, FALSE)
)
FROM information_schema.TABLE_CONSTRAINTS tc
JOIN information_schema.CHECK_CONSTRAINTS cc
  ON cc.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA
 AND cc.CONSTRAINT_NAME = tc.CONSTRAINT_NAME
WHERE tc.TABLE_SCHEMA = DATABASE() AND tc.CONSTRAINT_TYPE = 'CHECK';
