package publicadapter

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestActualFormalDatabaseJobRetainsOriginalReadonlyMaterials(t *testing.T) {
	for _, mode := range []string{"static-permit", "delivered-permit", "missing-materials", "invalid-material-mount", "source-filesystem"} {
		t.Run(mode, func(t *testing.T) {
			f, cfg := usersInstancesModuleFixture(t)
			r := cfg.Database
			r.Workload.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "original-database-formal", Inputs: []kube.FormalInputMount{
				{Volume: "formal-database-source", Kind: "Secret", Name: "original-database-reader", Directory: "/run/backup/materials/database-source", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}},
				{Volume: "formal-provider-jwt", Kind: "Secret", Name: "original-provider-jwt", Directory: "/run/backup/materials/provider-jwt", Items: []corev1.KeyToPath{{Key: "jwt", Path: "jwt"}}},
				{Volume: "formal-provider-ca", Kind: "ConfigMap", Name: "original-provider-ca", Directory: "/run/backup/materials/provider-ca", Items: []corev1.KeyToPath{{Key: "ca", Path: "ca.pem"}}},
			}}
			r.Invocation.FormalCapture = &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), EnvelopeName: "database.envelope", MaxFrames: 8, SourceConfigSHA256: f.in.Authority.ConfigSHA256}
			binding := r.Invocation.Request.Binding
			r.Invocation.ProviderKey = &k.Access{Operation: k.Generate, Endpoint: "https://bao.invalid", KeyName: "backup-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("a", 64), RegistryVersion: "r1", ProviderKeyID: "backup-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: f.in.Authority.InstallationID, BackupPublicID: binding.BackupID, AttemptNo: binding.Attempt, Phase: "capture", Part: binding.Path, PartIndex: strconv.FormatUint(uint64(binding.PartIndex), 10), EnvelopeID: binding.EnvelopeID, CaptureContextHash: binding.CaptureContextHash}}}
			if mode != "static-permit" {
				r.Invocation.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("b", 64)}
			}
			if !worker.ValidateRecordedInvocation(r.Invocation) {
				t.Fatal("formal DB invocation invalid before builder")
			}
			switch mode {
			case "missing-materials":
				r.Workload.FormalMaterials = nil
			case "invalid-material-mount":
				r.Workload.FormalMaterials.Inputs[0].Directory = "/workspace"
			case "source-filesystem":
				r.Workload.Source = corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "source"}}}
			}
			result, err := BuildCapturePart(f.in, f.x.HoldUntil, r)
			if mode != "static-permit" && mode != "delivered-permit" {
				if err == nil || len(result.Intent.SpecJSON) != 0 {
					t.Fatal("bad formal DB material became a Job", mode)
				}
				return
			}
			var job batchv1.Job
			if err != nil || json.Unmarshal(result.Intent.SpecJSON, &job) != nil || len(job.Spec.Template.Spec.Containers) != 1 {
				t.Fatal("actual formal DB Job failed", err)
			}
			container := job.Spec.Template.Spec.Containers[0]
			command := strings.Join(append(append([]string{}, container.Command...), container.Args...), " ")
			if !strings.Contains(command, "--formal-config /run/backup/formal/materials.json") {
				t.Fatal("formal DB CLI route lost")
			}
			mounts := map[string]corev1.VolumeMount{}
			for _, mount := range container.VolumeMounts {
				mounts[mount.Name] = mount
				if mount.MountPath == "/workspace" || mount.MountPath == "/evidence" {
					t.Fatal("formal capture gained source/evidence filesystem")
				}
			}
			for _, name := range []string{"formal-mapping", "formal-database-source", "formal-provider-jwt", "formal-provider-ca"} {
				mount, exists := mounts[name]
				if !exists || !mount.ReadOnly || mount.SubPath != "" {
					t.Fatal("original readonly material mount lost", name)
				}
			}
			if mounts["staging"].SubPath != f.in.Authority.TaskPublicID || mounts["staging"].ReadOnly {
				t.Fatal("original task staging scope lost")
			}
			volumes := map[string]corev1.Volume{}
			for _, volume := range job.Spec.Template.Spec.Volumes {
				volumes[volume.Name] = volume
				if volume.HostPath != nil || volume.NFS != nil || volume.PersistentVolumeClaim != nil && volume.Name != "staging" {
					t.Fatal("DB capture gained source volume")
				}
			}
			if volumes["formal-mapping"].ConfigMap == nil || volumes["formal-mapping"].ConfigMap.Name != "original-database-formal" || volumes["formal-database-source"].Secret == nil || volumes["formal-database-source"].Secret.SecretName != "original-database-reader" || volumes["formal-provider-jwt"].Secret == nil || volumes["formal-provider-ca"].ConfigMap == nil {
				t.Fatal("original material references lost")
			}
			if f.ensures != 0 || len(f.events) != 0 {
				t.Fatal("pure builder dispatched source effects")
			}
		})
	}
}
