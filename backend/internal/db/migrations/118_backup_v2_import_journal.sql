-- Only the explicit isolated-copy importer writes this journal. It is not a
-- scheduler or an authorization to resume imported work.
CREATE TABLE IF NOT EXISTS system_backup_v2_import_journal (
 singleton_id TINYINT PRIMARY KEY,
 source_git_sha CHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 source_schema_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 state VARCHAR(24) NOT NULL,
 preservation_json LONGTEXT NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
 CONSTRAINT sbv2_import_singleton CHECK (singleton_id=1),
 CONSTRAINT sbv2_import_state CHECK (state IN ('prepared','renamed','migrated','verified')),
 CONSTRAINT sbv2_import_json CHECK (JSON_VALID(preservation_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
