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
	f.responses["server"] = map[string]any{"deploymentID": "deployment", "region": "us-east-1", "servers": []any{map[string]any{"state": "ok", "version": profile.ServerVersion, "commitID": profile.ServerCommit}}}
	if _, err := f.reader.serverSeptember(ctx); err != nil {
		t.Fatal("explicit September native contract model", err)
	}
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
