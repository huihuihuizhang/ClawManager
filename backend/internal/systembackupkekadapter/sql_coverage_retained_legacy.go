package systembackupkekadapter

import (
	reg "clawreef/internal/systembackupkekregistry"
	"sort"
	"strings"
)

// Exact35 preserved original table names from the reviewed original99/97
// upgrade profile. These are INCLUDED originals, never prefix exclusions.
// Their nonempty rows remain unclassified; the supported singleton branch
// rejects them instead of inferring release or fabricating key references.
func retainedOriginalLegacySources() map[string]reg.Partition {
	return map[string]reg.Partition{
		"dlegacy_01_system_artifact_lease_states":            reg.RetainedArtifacts, // system_artifact_lease_states
		"dlegacy_02_system_artifact_leases":                  reg.RetainedArtifacts, // system_artifact_leases
		"dlegacy_03_system_backup_admin_revocations":         reg.RetainedArtifacts, // system_backup_admin_revocations
		"dlegacy_04_system_backup_admin_sessions":            reg.RetainedArtifacts, // system_backup_admin_sessions
		"dlegacy_05_system_backup_alert_states":              reg.RetainedArtifacts, // system_backup_alert_states
		"dlegacy_06_system_backup_artifact_verifications":    reg.RetainedArtifacts, // system_backup_artifact_verifications
		"dlegacy_07_system_backup_attempts":                  reg.RetainedArtifacts, // system_backup_attempts
		"dlegacy_08_system_backup_check_results":             reg.RetainedArtifacts, // system_backup_check_results
		"dlegacy_09_system_backup_compact_tombstones":        reg.RetainedArtifacts, // system_backup_compact_tombstones
		"dlegacy_10_system_backup_configs":                   reg.RetainedArtifacts, // system_backup_configs
		"dlegacy_11_system_backup_dependency_health":         reg.RetainedArtifacts, // system_backup_dependency_health
		"dlegacy_12_system_backup_events":                    reg.RetainedArtifacts, // system_backup_events
		"dlegacy_13_system_backup_evidence":                  reg.RetainedArtifacts, // system_backup_evidence
		"dlegacy_14_system_backup_evidence_chunks":           reg.RetainedArtifacts, // system_backup_evidence_chunks
		"dlegacy_15_system_backup_external_actions":          reg.RetainedArtifacts, // system_backup_external_actions
		"dlegacy_16_system_backup_installation_state":        reg.RetainedArtifacts, // system_backup_installation_state
		"dlegacy_17_system_backup_job_observations":          reg.RetainedArtifacts, // system_backup_job_observations
		"dlegacy_18_system_backup_log_chunks":                reg.RetainedArtifacts, // system_backup_log_chunks
		"dlegacy_19_system_backup_metadata_reservations":     reg.RetainedArtifacts, // system_backup_metadata_reservations
		"dlegacy_20_system_backup_operations":                reg.RetainedArtifacts, // system_backup_operations
		"dlegacy_21_system_backup_preflights":                reg.RetainedArtifacts, // system_backup_preflights
		"dlegacy_22_system_backup_promotions":                reg.RetainedArtifacts, // system_backup_promotions
		"dlegacy_23_system_backup_provider_capabilities":     reg.RetainedArtifacts, // system_backup_provider_capabilities
		"dlegacy_24_system_backup_prune_items":               reg.RetainedArtifacts, // system_backup_prune_items
		"dlegacy_25_system_backup_prune_runs":                reg.RetainedArtifacts, // system_backup_prune_runs
		"dlegacy_26_system_backup_source_writer_check_state": reg.RetainedArtifacts, // system_backup_source_writer_check_states
		"dlegacy_27_system_backup_staging_resources":         reg.RetainedArtifacts, // system_backup_staging_resources
		"dlegacy_28_system_backup_strong_auth_nonces":        reg.RetainedArtifacts, // system_backup_strong_auth_nonces
		"dlegacy_29_system_backup_totp_credentials":          reg.RetainedArtifacts, // system_backup_totp_credentials
		"dlegacy_30_system_backups":                          reg.RetainedArtifacts, // system_backups
		"dlegacy_31_system_maintenance_locks":                reg.RetainedArtifacts, // system_maintenance_locks
		"dlegacy_32_system_maintenance_mutation_leases":      reg.RetainedArtifacts, // system_maintenance_mutation_leases
		"dlegacy_33_system_maintenance_participants":         reg.RetainedArtifacts, // system_maintenance_participants
		"dlegacy_34_system_restore_drill_resources":          reg.RetainedArtifacts, // system_restore_drill_resources
		"dlegacy_35_system_restore_drills":                   reg.RetainedArtifacts, // system_restore_drills
	}
}

// Comparison DATA only, not a census, proof, classification or permission.
// A genuine known-original consumer uses the actual scanner facts to require
// this entire preserved source layout rather than accepting missing aliases.
func RetainedOriginalLegacySourceTables() []string {
	m := retainedOriginalLegacySources()
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Optional only for genuinely fresh installations. A known original legacy
// consumer must independently require this full layout. Any actual partial
// retention or unreviewed dlegacy table is a refusal, not a smaller universe.
func includeRetainedOriginalLegacySources(sources map[string]reg.Partition, seen map[string]bool) error {
	legacy := retainedOriginalLegacySources()
	count := 0
	for name, present := range seen {
		if present && strings.HasPrefix(name, "dlegacy_") {
			if _, known := legacy[name]; !known {
				return ErrSQLCoverageCensus
			}
		}
	}
	for name := range legacy {
		if seen[name] {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	if count != len(legacy) {
		return ErrSQLCoverageCensus
	}
	for name, part := range legacy {
		sources[name] = part
	}
	return nil
}
