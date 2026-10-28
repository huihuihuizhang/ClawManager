-- Metadata only, observed through SHOW CREATE TABLE on 2026-10-26.
-- No source rows, credentials or migration commands are included.
-- This is reference DDL for isolated fixtures, NOT a production deployment script.
CREATE TABLE `workbuddy_linux_identities` (
  `instance_id` int NOT NULL,
  `user_id` int NOT NULL,
  `linux_uid` int NOT NULL,
  `created_at` datetime(6) NOT NULL,
  PRIMARY KEY (`instance_id`),
  UNIQUE KEY `linux_uid` (`linux_uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `workbuddy_linux_identity_allocator` (
  `id` int NOT NULL,
  `next_uid` int NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
