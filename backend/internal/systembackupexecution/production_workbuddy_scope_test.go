package systembackupexecution

import (
	"encoding/json"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
)

func TestProductionWorkBuddyProAndLiteUseTheirOwnIdentityScope(t *testing.T) {
	for _, fault := range []string{"pro", "pro-with-lite-identity", "lite", "lite-missing", "lite-wrong-owner", "lite-wrong-instance", "lite-wrong-gid", "lite-outside-range"} {
		t.Run(fault, func(t *testing.T) {
			in, source, hold, writers, operations := productionModuleFixture(t)
			instance := &source.Instances[1]
			instance.Type, instance.Mode, instance.Backend = "workbuddy", "lite", "gateway"
			if fault == "pro" || fault == "pro-with-lite-identity" {
				instance.Mode, instance.Backend = "pro", "desktop"
			}
			var metadata productionCaptureMetadata
			if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
				t.Fatal("metadata")
			}
			for index := range metadata.Mounts {
				mount := &metadata.Mounts[index]
				if mount.InstanceID != instance.ID {
					continue
				}
				mount.Policy.Runtime = scope.Runtime{Type: instance.Type, Mode: instance.Mode, Backend: instance.Backend, Variant: instance.Variant, OS: instance.OS}
				mount.WorkBuddy = &domain.WorkBuddyUIDIdentity{Schema: 1, InstanceID: instance.ID, UserID: instance.UserID, UID: 10007, GID: 10007}
				switch fault {
				case "pro", "lite-missing":
					mount.WorkBuddy = nil
				case "lite-wrong-owner":
					mount.WorkBuddy.UserID++
				case "lite-wrong-instance":
					mount.WorkBuddy.InstanceID++
				case "lite-wrong-gid":
					mount.WorkBuddy.GID++
				case "lite-outside-range":
					mount.WorkBuddy.UID, mount.WorkBuddy.GID = 9999, 9999
				}
				if mount.Policy.Validate() != nil {
					t.Fatal("original supported runtime policy")
				}
			}
			source.CaptureMetadata, _ = json.Marshal(metadata)
			modules, err := productionCaptureModules(in, source, hold, writers, operations, "workbuddy-scope")
			var partsOK bool
			if err == nil {
				parts, buildErr := modules.BuildParts(in, source, hold)
				err = buildErr
				for _, part := range parts {
					if part.Part != "instance_9_workspace" {
						continue
					}
					var invocation worker.Invocation
					if json.Unmarshal(part.InvocationJSON, &invocation) != nil {
						t.Fatal("invocation")
					}
					partsOK = invocation.Request.RuntimePolicy.Runtime.Mode == instance.Mode && (invocation.Request.WorkBuddyIdentity == nil) == (fault == "pro")
				}
			}
			want := fault == "pro" || fault == "lite"
			if (err == nil && partsOK) != want || !want && err == nil {
				t.Fatal("original Pro/Lite identity scope", fault, err, partsOK)
			}
		})
	}
}
