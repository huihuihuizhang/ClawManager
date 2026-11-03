package systembackupkekadapter

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	reg "clawreef/internal/systembackupkekregistry"
)

func TestRetainedOriginalLegacySourcesCompleteScope(t *testing.T) {
	original := strings.Fields(`system_artifact_lease_states system_artifact_leases system_backup_admin_revocations system_backup_admin_sessions system_backup_alert_states system_backup_artifact_verifications system_backup_attempts system_backup_check_results system_backup_compact_tombstones system_backup_configs system_backup_dependency_health system_backup_events system_backup_evidence system_backup_evidence_chunks system_backup_external_actions system_backup_installation_state system_backup_job_observations system_backup_log_chunks system_backup_metadata_reservations system_backup_operations system_backup_preflights system_backup_promotions system_backup_provider_capabilities system_backup_prune_items system_backup_prune_runs system_backup_source_writer_check_states system_backup_staging_resources system_backup_strong_auth_nonces system_backup_totp_credentials system_backups system_maintenance_locks system_maintenance_mutation_leases system_maintenance_participants system_restore_drill_resources system_restore_drills`)
	actual := RetainedOriginalLegacySourceTables()
	if len(original) != 35 || len(actual) != 35 {
		t.Fatal("complete original35 scope missing")
	}
	seen := map[string]bool{}
	for i, name := range original {
		if len(name) > 39 {
			name = name[:39]
		}
		alias := fmt.Sprintf("dlegacy_%02d_%s", i+1, name)
		if actual[i] != alias || seen[alias] {
			t.Fatal("retained source differs from reviewed original rename")
		}
		seen[alias] = true
	}
	sources, excluded := sqlCensusSources()
	before := len(sources)
	if includeRetainedOriginalLegacySources(sources, seen) != nil || len(sources) != before+35 {
		t.Fatal("original sources not added to actual table scan")
	}
	for _, alias := range actual {
		if sources[alias] != reg.RetainedArtifacts || excluded[alias] {
			t.Fatal("preserved source excluded or assigned a false release")
		}
	}
	actual[0] = "caller-modified"
	if reflect.DeepEqual(actual, RetainedOriginalLegacySourceTables()) {
		t.Fatal("comparison getter exposed mutable source map")
	}
}

func TestRetainedOriginalLegacySourcesRefusePartialAndUnknown(t *testing.T) {
	names := RetainedOriginalLegacySourceTables()
	for _, n := range []int{0, 1, 17, 34, 35} {
		t.Run(fmt.Sprintf("present_%d", n), func(t *testing.T) {
			seen := map[string]bool{}
			for _, name := range names[:n] {
				seen[name] = true
			}
			sources := map[string]reg.Partition{"existing": reg.HoldsAndCatalog}
			err := includeRetainedOriginalLegacySources(sources, seen)
			if n == 0 || n == 35 {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || len(sources) != 1 {
				t.Fatal("partial retention accepted or mutated source set")
			}
		})
	}
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprintf("unknown_with_full_%t", full), func(t *testing.T) {
			seen := map[string]bool{"dlegacy_unreviewed_history": true}
			if full {
				for _, name := range names {
					seen[name] = true
				}
			}
			if includeRetainedOriginalLegacySources(map[string]reg.Partition{}, seen) == nil {
				t.Fatal("unreviewed actual source silently omitted")
			}
		})
	}
}
