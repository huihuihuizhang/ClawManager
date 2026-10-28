package services

import (
	"strings"

	"clawreef/internal/models"
	"clawreef/internal/systembackup/scope"
)

// BuildUserInstanceBackupInventory adapts the existing platform runtime rules
// to the read-only domain planner. Callers must provide a complete database
// inventory and separately discovered storage mounts, not infer a shared PVC's
// instance directory from the container path. This function performs no K8s,
// filesystem, database or lifecycle mutations.
func BuildUserInstanceBackupInventory(
	orchestrator, profile string,
	totalUsers, totalInstances int,
	users []models.User,
	instances []models.Instance,
	mounts map[int][]scope.Mount,
) (*scope.Inventory, error) {
	input := scope.Input{
		Orchestrator: orchestrator, Profile: profile, TotalUsers: totalUsers, TotalInstances: totalInstances,
		Users: make([]scope.User, 0, len(users)), Instances: make([]scope.Instance, 0, len(instances)),
	}
	for _, user := range users {
		input.Users = append(input.Users, scope.User{
			ID: user.ID, Role: user.Role, AuthProvider: user.AuthProvider,
			HasPasswordHash: strings.TrimSpace(user.PasswordHash) != "",
		})
	}
	for _, instance := range instances {
		variant := instance.RuntimeVariant
		if strings.TrimSpace(variant) == "" {
			variant = managedRuntimeVariantForInstance(&instance)
		}
		input.Instances = append(input.Instances, scope.Instance{
			ID: instance.ID, UserID: instance.UserID,
			Runtime: scope.Runtime{Type: instance.Type, Mode: instance.InstanceMode, Backend: instance.RuntimeType, Variant: variant, OS: instance.OSType},
			Mounts:  mounts[instance.ID],
		})
	}
	return scope.BuildInventory(input)
}
