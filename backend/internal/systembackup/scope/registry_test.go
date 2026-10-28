package scope

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"clawreef/internal/models"
)

func TestRegistryCoversCurrentUserAndInstanceModels(t *testing.T) {
	if err := ValidateRegistry(TableRegistry(), CrossDomainDependencies()); err != nil {
		t.Fatal(err)
	}
	known := make(map[string]TableRule)
	for _, rule := range TableRegistry() {
		known[rule.Name] = rule
	}
	for _, model := range []interface{ TableName() string }{
		models.User{}, models.UserQuota{}, models.EnterpriseAuthSetting{}, models.Instance{},
		models.PersistentVolume{}, models.Backup{}, models.BackupSchedule{}, models.InstanceUsage{},
		models.InstanceAgent{}, models.InstanceRuntimeStatus{}, models.InstanceDesiredState{}, models.InstanceCommand{},
		models.InstanceBrowserWorker{},
		models.InstanceConfigRevision{}, models.InstanceRuntimeBinding{}, models.InstanceExternalAccess{},
		models.RuntimePod{}, models.RuntimeRollout{}, models.RuntimeUpgradeItem{}, models.RuntimeUpgradeAudit{},
		models.WorkspaceFileAudit{}, models.OpenClawConfigResource{}, models.OpenClawConfigBundle{},
		models.OpenClawConfigBundleItem{}, models.OpenClawConfigBundleSkill{}, models.OpenClawInjectionSnapshot{},
	} {
		if _, exists := known[model.TableName()]; !exists {
			t.Errorf("missing scope rule for current model: %s", model.TableName())
		}
	}
	if known["users"].RestoreAction != "preserve" || known["instance_runtime_bindings"].RestoreAction != "drop" || known["backup_schedules"].RestoreAction != "disable" || known["instance_browser_workers"].RestoreAction != "disable" {
		t.Fatal("credentials/business identity and replayable state need different restore rules")
	}
	if known["runtime_rollout_checkpoints"].RestoreAction != "reference_only" || known["instance_workspace_write_intents"].RestoreAction != "drop" {
		t.Fatal("source rollout progress and outstanding remote writes must not execute on target")
	}
}

func TestNewInstanceMigrationTablesRequireExplicitOwnership(t *testing.T) {
	known := make(map[string]bool)
	for _, rule := range TableRegistry() {
		known[rule.Name] = true
	}
	for _, dependency := range CrossDomainDependencies() {
		for _, table := range dependency.Tables {
			known[table] = true
		}
	}
	create := regexp.MustCompile("(?i)CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?`?([a-z_][a-z0-9_]*)")
	files, err := filepath.Glob(filepath.Join("..", "..", "db", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("cannot check embedded migrations: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range create.FindAllStringSubmatch(string(data), -1) {
			table := strings.ToLower(match[1])
			if strings.HasPrefix(table, "instance_") || strings.HasPrefix(table, "runtime_") || strings.HasPrefix(table, "openclaw_") {
				if !known[table] {
					t.Errorf("%s creates %s without a scope rule or explicit owner dependency", filepath.Base(file), table)
				}
			}
		}
	}
}

func TestRegistryRejectsUnassignedTablesAndDependencies(t *testing.T) {
	for _, rule := range []TableRule{
		{Name: "new_table", Domain: "unassigned", RestoreAction: "preserve", Reason: "test"},
		{Name: "new_table", Domain: Instances, RestoreAction: "", Reason: "test"},
		{Name: "new_table", Domain: Instances, RestoreAction: "preserve", Reason: "test", DependsOn: []string{"missing"}},
	} {
		if err := ValidateRegistry([]TableRule{rule}, nil); err == nil {
			t.Fatalf("unassigned rule accepted: %+v", rule)
		}
	}
}
