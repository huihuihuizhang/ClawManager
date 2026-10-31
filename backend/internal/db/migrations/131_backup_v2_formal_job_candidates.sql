-- Unpublished formal worker reports belong to the ORIGINAL public Job.
-- This is not a completed module result, artifact, acceptance or task state.
ALTER TABLE system_backup_v2_runtime_resources
 ADD COLUMN candidate_cipher BLOB NULL,
 ADD COLUMN candidate_key_ref VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NULL,
 ADD COLUMN candidate_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 ADD CONSTRAINT sbv2_runtime_candidate CHECK (
   (candidate_cipher IS NULL AND candidate_key_ref IS NULL AND candidate_sha256 IS NULL)
   OR (resource_kind='Job' AND candidate_cipher IS NOT NULL
     AND OCTET_LENGTH(candidate_cipher) BETWEEN 2 AND 32768
     AND candidate_key_ref IS NOT NULL AND OCTET_LENGTH(candidate_key_ref) BETWEEN 1 AND 256
     AND candidate_sha256 IS NOT NULL AND candidate_sha256 REGEXP '^[a-f0-9]{64}$')
 );
