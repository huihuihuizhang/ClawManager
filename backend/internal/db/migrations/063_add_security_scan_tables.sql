CREATE TABLE IF NOT EXISTS security_scan_configs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  default_mode VARCHAR(20) NOT NULL DEFAULT 'quick',
  quick_analyzers_json LONGTEXT NOT NULL,
  deep_analyzers_json LONGTEXT NOT NULL,
  quick_timeout_seconds INT NOT NULL DEFAULT 30,
  deep_timeout_seconds INT NOT NULL DEFAULT 120,
  allow_fallback BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by INT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_security_scan_configs_singleton (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_scan_jobs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  asset_type VARCHAR(30) NOT NULL DEFAULT 'skill',
  scan_mode VARCHAR(20) NOT NULL DEFAULT 'quick',
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  requested_by INT NULL,
  scope_json LONGTEXT NULL,
  total_items INT NOT NULL DEFAULT 0,
  completed_items INT NOT NULL DEFAULT 0,
  failed_items INT NOT NULL DEFAULT 0,
  current_item_name VARCHAR(255) NULL,
  started_at TIMESTAMP NULL,
  finished_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_security_scan_jobs_status (status, created_at),
  INDEX idx_security_scan_jobs_asset_type (asset_type, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_scan_job_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  job_id INT NOT NULL,
  asset_type VARCHAR(30) NOT NULL DEFAULT 'skill',
  asset_id INT NOT NULL,
  asset_name VARCHAR(255) NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  progress_pct INT NOT NULL DEFAULT 0,
  risk_level VARCHAR(30) NULL,
  summary TEXT NULL,
  scan_result_id INT NULL,
  cached_result BOOLEAN NOT NULL DEFAULT FALSE,
  error_message TEXT NULL,
  started_at TIMESTAMP NULL,
  finished_at TIMESTAMP NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (job_id) REFERENCES security_scan_jobs(id) ON DELETE CASCADE,
  UNIQUE KEY uk_security_scan_job_items_job_asset (job_id, asset_type, asset_id),
  INDEX idx_security_scan_job_items_job (job_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_scan_reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  job_id INT NOT NULL,
  summary_json LONGTEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (job_id) REFERENCES security_scan_jobs(id) ON DELETE CASCADE,
  UNIQUE KEY uk_security_scan_reports_job (job_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
