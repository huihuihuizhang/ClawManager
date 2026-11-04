package systembackupexecution

import (
	"context"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
)

func TestMinIOSeptemberNativeServerContractDoesNotRelaxAprilReader(t *testing.T) {
	f := minioPermissionFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := f.reader.serverSeptember(ctx); err == nil {
		t.Fatal("April server accepted by September adapter")
	}
	profile, _ := ma.NativeProfile(ma.SeptemberPermissionProfile)
	f.responses["server"] = map[string]any{"deploymentID": "deployment", "region": "us-east-1", "servers": []any{map[string]any{"state": "online", "version": profile.ServerVersion, "commitID": profile.ServerCommit}}}
	if _, err := f.reader.serverSeptember(ctx); err != nil {
		t.Fatal("explicit September native contract model", err)
	}
	server := f.responses["server"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	for _, state := range []string{"ok", "offline", "initializing", "", "ONLINE", "unknown"} {
		t.Run("reject-state-"+state, func(t *testing.T) {
			server["state"] = state
			if _, err := f.reader.serverSeptember(ctx); err == nil {
				t.Fatal("non-online state entered fixed September profile")
			}
		})
	}
	server["state"] = "online"
	for _, field := range []string{"version", "commitID"} {
		old := server[field]
		server[field] = "unknown"
		if _, err := f.reader.serverSeptember(ctx); err == nil {
			t.Fatal("online bypassed fixed", field)
		}
		server[field] = old
	}
	for _, field := range []string{"region", "deploymentID"} {
		top := f.responses["server"].(map[string]any)
		old := top[field]
		top[field] = "foreign"
		if _, err := f.reader.serverSeptember(ctx); err == nil {
			t.Fatal("online bypassed original", field)
		}
		top[field] = old
	}
	top := f.responses["server"].(map[string]any)
	top["servers"] = []any{server, server}
	if _, err := f.reader.serverSeptember(ctx); err == nil {
		t.Fatal("online bypassed single original server")
	}
	top["servers"] = []any{server}
	if _, err := f.reader.server(ctx); err == nil {
		t.Fatal("September server entered unchanged April native adapter")
	}
	f.responses["server"].(map[string]any)["servers"].([]any)[0].(map[string]any)["commitID"] = minioPermissionCommit
	if _, err := f.reader.serverSeptember(ctx); err == nil {
		t.Fatal("September timestamp accepted with April commit")
	}
}

func TestMinIOSeptemberSourceCannotEnterAprilV2Reader(t *testing.T) {
	f := newMinioSeptemberTerminalComponent(t, "")
	if _, err := NewMinIOEffectivePublicationPermissionV2Reader(f.input.PermissionSource); err == nil {
		t.Fatal("separate September source entered April constructor")
	}
	reader, err := NewMinIOSeptemberEffectivePublicationPermissionReader(f.input.PermissionSource)
	if err != nil {
		t.Fatal("explicit original September source constructor", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before := f.requests.Load()
	if _, err := minioCurrentProfileOwner(reader, ma.PermissionProfile, ctx, f.kube, time.Now()); err == nil || f.requests.Load() != before {
		t.Fatal("mixed source/profile reached native observation")
	}
}
