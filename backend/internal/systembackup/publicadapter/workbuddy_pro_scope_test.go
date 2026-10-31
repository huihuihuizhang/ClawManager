package publicadapter

import (
	"testing"

	"clawreef/internal/systembackup/domain"
)

func TestWorkBuddyProDoesNotReadOrBorrowLiteIdentity(t *testing.T) {
	_, cfg := usersInstancesModuleFixture(t)
	instance := &cfg.Source.Instances[0]
	instance.Type, instance.Mode, instance.Backend = "workbuddy", "pro", "desktop"
	policy := cfg.Workspaces[0].Request.Invocation.Request.RuntimePolicy
	policy.Runtime.Type, policy.Runtime.Mode, policy.Runtime.Backend = instance.Type, instance.Mode, instance.Backend
	if RequiresWorkBuddyUIDIdentity(*instance) {
		t.Fatal("Pro classified as Lite identity source")
	}
	if _, err := NewUsersInstancesModule(cfg); err != nil {
		t.Fatal("original supported Linux Pro module", err)
	}
	// The pure binder does not request nonexistent Lite tables for Pro. This
	// empty snapshot is not authentication and confers no capture authority.
	if _, err := WithWorkBuddyIdentities(cfg, domain.Snapshot{}); err != nil {
		t.Fatal("Pro required Lite SQL identity snapshot", err)
	}
	for _, issue := range DiagnoseUsersInstancesConfig(cfg).Issues {
		if issue.Code == "workbuddy_identity_required" {
			t.Fatal("Pro diagnosis required Lite identity")
		}
	}
	cfg.Workspaces[0].Request.Invocation.Request.WorkBuddyIdentity = &domain.WorkBuddyUIDIdentity{Schema: 1, InstanceID: instance.ID, UserID: instance.UserID, UID: 10007, GID: 10007}
	if _, err := NewUsersInstancesModule(cfg); err == nil {
		t.Fatal("Pro borrowed Lite identity")
	}
	found := false
	for _, issue := range DiagnoseUsersInstancesConfig(cfg).Issues {
		found = found || issue.Code == "workbuddy_identity_mismatch"
	}
	if !found {
		t.Fatal("Pro/Lite identity mismatch was not diagnosed")
	}
}

func TestWorkBuddyUIDScopeRejectsWindowsUnknownAndPro(t *testing.T) {
	valid := InstanceIdentity{Type: "workbuddy", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}
	if !RequiresWorkBuddyUIDIdentity(valid) {
		t.Fatal("original Lite scope omitted")
	}
	for _, fault := range []string{"blank-backend", "inferred-mode"} {
		instance := valid
		if fault == "blank-backend" {
			instance.Backend = ""
		} else {
			instance.Mode = ""
		}
		if !RequiresWorkBuddyUIDIdentity(instance) {
			t.Fatal("canonical Lite escaped UID scope", fault)
		}
	}
	for _, fault := range []string{"windows", "unknown", "pro", "foreign-backend"} {
		instance := valid
		switch fault {
		case "windows":
			instance.OS = "windows"
		case "unknown":
			instance.Variant = "unknown"
		case "pro":
			instance.Mode, instance.Backend = "pro", "desktop"
		case "foreign-backend":
			instance.Backend = "unknown"
		}
		if RequiresWorkBuddyUIDIdentity(instance) {
			t.Fatal("outside original UID scope", fault)
		}
	}
}
