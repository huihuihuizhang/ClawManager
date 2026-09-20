-- Read-only MySQL 8.0/8.4 capture for sha256-information-schema-canonical-v1.
-- Run against the selected application database with batch/raw/no-column-names output.
-- The two output columns are record_type and JSON payload; no business rows are read.

SELECT 'metadata', JSON_OBJECT(
  'server_version', @@version,
  'sql_mode', @@session.sql_mode
)
UNION ALL
SELECT 'table', JSON_OBJECT(
  'name', t.TABLE_NAME
)
FROM information_schema.TABLES t
WHERE t.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = 'BASE TABLE'
UNION ALL
SELECT 'column', JSON_OBJECT(
  'table_name', c.TABLE_NAME,
  'name', c.COLUMN_NAME,
  'ordinal_position', c.ORDINAL_POSITION,
  'normalized_type', c.COLUMN_TYPE,
  'nullable', IF(c.IS_NULLABLE = 'YES', TRUE, FALSE),
  'default', c.COLUMN_DEFAULT,
  'character_set', c.CHARACTER_SET_NAME,
  'collation', c.COLLATION_NAME,
  'extra', c.EXTRA,
  'generation_expression', NULLIF(c.GENERATION_EXPRESSION, '')
)
FROM information_schema.COLUMNS c
JOIN information_schema.TABLES ct
  ON ct.TABLE_SCHEMA = c.TABLE_SCHEMA
 AND ct.TABLE_NAME = c.TABLE_NAME
 AND ct.TABLE_TYPE = 'BASE TABLE'
WHERE c.TABLE_SCHEMA = DATABASE()
UNION ALL
SELECT 'index', JSON_OBJECT(
  'table_name', s.TABLE_NAME,
  'name', s.INDEX_NAME,
  'kind', CASE WHEN s.INDEX_NAME = 'PRIMARY' THEN 'primary' WHEN s.NON_UNIQUE = 0 THEN 'unique' ELSE 'ordinary' END,
  'index_type', s.INDEX_TYPE,
  'visible', IF(s.IS_VISIBLE = 'YES', TRUE, FALSE),
  'ordinal_position', s.SEQ_IN_INDEX,
  'column_name', s.COLUMN_NAME,
  'expression', s.EXPRESSION,
  'prefix_length', s.SUB_PART,
  'sort_direction', CASE s.COLLATION WHEN 'A' THEN 'asc' WHEN 'D' THEN 'desc' ELSE NULL END
)
FROM information_schema.STATISTICS s
WHERE s.TABLE_SCHEMA = DATABASE()
UNION ALL
SELECT 'foreign_key', JSON_OBJECT(
  'table_name', k.TABLE_NAME,
  'name', k.CONSTRAINT_NAME,
  'referenced_table_name', k.REFERENCED_TABLE_NAME,
  'update_rule', r.UPDATE_RULE,
  'delete_rule', r.DELETE_RULE,
  'match_option', r.MATCH_OPTION,
  'ordinal_position', k.ORDINAL_POSITION,
  'column_name', k.COLUMN_NAME,
  'referenced_column_name', k.REFERENCED_COLUMN_NAME
)
FROM information_schema.KEY_COLUMN_USAGE k
JOIN information_schema.REFERENTIAL_CONSTRAINTS r
  ON r.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA
 AND r.TABLE_NAME = k.TABLE_NAME
 AND r.CONSTRAINT_NAME = k.CONSTRAINT_NAME
WHERE k.TABLE_SCHEMA = DATABASE() AND k.REFERENCED_TABLE_NAME IS NOT NULL
UNION ALL
SELECT 'definition', JSON_OBJECT(
  'object_type', 'view',
  'name', v.TABLE_NAME,
  'definition', v.VIEW_DEFINITION
)
FROM information_schema.VIEWS v
WHERE v.TABLE_SCHEMA = DATABASE()
UNION ALL
SELECT 'definition', JSON_OBJECT(
  'object_type', 'trigger',
  'name', tr.TRIGGER_NAME,
  'definition', tr.ACTION_STATEMENT
)
FROM information_schema.TRIGGERS tr
WHERE tr.TRIGGER_SCHEMA = DATABASE()
UNION ALL
SELECT 'definition', JSON_OBJECT(
  'object_type', 'routine',
  'name', ro.ROUTINE_NAME,
  'definition', ro.ROUTINE_DEFINITION
)
FROM information_schema.ROUTINES ro
WHERE ro.ROUTINE_SCHEMA = DATABASE()
UNION ALL
SELECT 'definition', JSON_OBJECT(
  'object_type', 'mysql_event',
  'name', e.EVENT_NAME,
  'definition', e.EVENT_DEFINITION
)
FROM information_schema.EVENTS e
WHERE e.EVENT_SCHEMA = DATABASE();
