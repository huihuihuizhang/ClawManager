-- For a throwaway isolated MySQL Pod only. The caller creates sbk_controller@%.
GRANT SELECT ON `clawmanager`.`schema_migrations` TO 'sbk_controller'@'%';
GRANT SELECT, UPDATE ON `clawmanager`.`system_backup_installation_state` TO 'sbk_controller'@'%';
GRANT SELECT ON `clawmanager`.`system_backup_configs` TO 'sbk_controller'@'%';
GRANT SELECT, INSERT, UPDATE ON `clawmanager`.`system_maintenance_locks` TO 'sbk_controller'@'%';
GRANT INSERT ON `clawmanager`.`system_backup_events` TO 'sbk_controller'@'%';
GRANT SELECT, INSERT, UPDATE ON `clawmanager`.`system_backup_alert_states` TO 'sbk_controller'@'%';
GRANT SELECT ON `clawmanager`.`system_backup_attempts` TO 'sbk_controller'@'%';
GRANT SELECT ON `clawmanager`.`system_backup_external_actions` TO 'sbk_controller'@'%';
GRANT SELECT ON `clawmanager`.`system_artifact_leases` TO 'sbk_controller'@'%';
GRANT SELECT, UPDATE ON `clawmanager`.`system_backups` TO 'sbk_controller'@'%';
GRANT SELECT, UPDATE ON `clawmanager`.`system_restore_drills` TO 'sbk_controller'@'%';
GRANT SELECT, UPDATE ON `clawmanager`.`system_backup_preflights` TO 'sbk_controller'@'%';
GRANT SELECT, UPDATE ON `clawmanager`.`system_backup_artifact_verifications` TO 'sbk_controller'@'%';
GRANT SELECT, UPDATE ON `clawmanager`.`system_backup_operations` TO 'sbk_controller'@'%';
