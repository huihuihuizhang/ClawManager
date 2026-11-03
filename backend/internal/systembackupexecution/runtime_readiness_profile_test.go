package systembackupexecution

import (
	"context"
	"os"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
)

// These components use original signed grants, immutable Kubernetes owner
// objects and the concrete C readers. They verify the D profile selection;
// they do not claim a combined SQL/source/publisher readiness publication.
func TestRuntimeReadinessExplicitProfileUsesOriginalSignedOwner(t *testing.T) {
	for _, profile := range []string{ma.PermissionProfile, ma.SeptemberPermissionProfile} {
		t.Run(profile, func(t *testing.T) {
			var f *minioTerminalComponent
			if profile == ma.PermissionProfile {
				f = newMinioTerminalComponent(t, "")
			} else {
				f = newMinioSeptemberTerminalComponent(t, "")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			input := RuntimeReadinessInput{Profile: profile, Source: f.input.PermissionSource}
			reader, err := newRuntimeReadinessPermissionReader(input)
			if err != nil {
				t.Fatal("explicit original source constructor", err)
			}
			owner, err := minioCurrentProfileOwner(reader, profile, ctx, f.kube, time.Now().UTC())
			if err != nil || owner.stamp == "" || owner.grant.ConfigSHA256 != f.config.SHA256() {
				t.Fatal("selected source did not authenticate original owner", err)
			}
			before := f.requests.Load()
			other := ma.PermissionProfile
			if profile == other {
				other = ma.SeptemberPermissionProfile
			}
			for _, rejected := range []string{"", "unknown", other} {
				bad := input
				bad.Profile = rejected
				if r, err := newRuntimeReadinessPermissionReader(bad); err == nil || r != nil {
					t.Fatal("missing, unknown or cross-profile source accepted", rejected)
				}
			}
			if f.requests.Load() != before {
				t.Fatal("invalid profile reached native provider")
			}
			// The same selected file is pinned again at the later boundary.
			file, err := os.OpenFile(input.Source.File, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := file.Write([]byte("\n"))
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal(writeErr, closeErr)
			}
			if r, err := newRuntimeReadinessPermissionReader(input); err == nil || r != nil {
				t.Fatal("changed source accepted under original pin")
			}
		})
	}
}

func TestRuntimeReadinessEnvironmentRequiresExplicitProfile(t *testing.T) {
	t.Setenv("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_FILE", "")
	t.Setenv("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_SHA256", "")
	t.Setenv("SYSTEM_BACKUP_READINESS_MINIO_PROFILE", "")
	if inputs := RuntimeReadinessInputsFromEnvironment(); len(inputs) != 0 {
		t.Fatal("absent source became a selected profile")
	}
	t.Setenv("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_FILE", "/original/source.json")
	t.Setenv("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_SHA256", "original-pin")
	inputs := RuntimeReadinessInputsFromEnvironment()
	if len(inputs) != 1 || inputs[0].Profile != "" {
		t.Fatal("missing profile silently defaulted")
	}
	if err := (&DeploymentService{Config: DeploymentConfig{CaptureScope: "six-part"}}).attachRuntimeReadiness(inputs); err == nil {
		t.Fatal("missing explicit profile accepted")
	}
}
