package install

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// Actual site launch coordinates as DATA models, not an original source hold.
// Exercise the bridge consumed by the finite producer, rather than only its
// lower-level classifier; the prior bridge rejected the real site tag.
func TestOriginalBackupViewStartupActualSiteAndImmutableTemplate(t *testing.T) {
	for _, name := range []string{"actual_site_tag", "immutable_runtime", "immutable_retired_template"} {
		t.Run(name, func(t *testing.T) {
			pod := originalFix18ProfilePodModel()
			pod.Spec.Containers[0].Image = "10.130.14.23:5000/clawmanager:backup-test-zh-fix18"
			status := &pod.Status.ContainerStatuses[0]
			if name != "actual_site_tag" {
				pod.Spec.Containers[0].Image = "10.130.14.23:5000/clawmanager@" + originalFix18PlatformManifest
			}
			if name == "immutable_retired_template" {
				status = nil
			}
			got, err := classifyOriginalBackupViewStartup(&pod.Spec, &pod.Spec.Containers[0], status, false)
			if err != nil || got.kind != "original_non_backup_consumer" || !got.requiresOriginalLegacyLayout || !digestPattern.MatchString(got.sourceSHA256) {
				t.Fatal("real site launch or immutable template lost at producer bridge", err)
			}
		})
	}
}

func TestOriginalBackupViewStartupDistinguishesUnknownPeerAndUnsafeKnownImage(t *testing.T) {
	for _, name := range []string{"same_repository_peer", "another_repository", "known_shell", "known_init", "tag_only_template", "known_code_overlay"} {
		t.Run(name, func(t *testing.T) {
			pod := originalFix18ProfilePodModel()
			pod.Spec.Containers[0].Image = "10.130.14.23:5000/clawmanager:backup-test-zh-fix18"
			status := &pod.Status.ContainerStatuses[0]
			init := false
			unknown := false
			switch name {
			case "same_repository_peer":
				pod.Spec.Containers[0].Image = "10.130.14.23:5000/clawmanager@sha256:1ba8cc47f468610e6875117f75fe42ce9fdb15e1cd2e6f877ac8ff2f99e2baa0"
				status.ImageID = pod.Spec.Containers[0].Image
				unknown = true
			case "another_repository":
				pod.Spec.Containers[0].Image = "redis:7-alpine"
				status.ImageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				unknown = true
			case "known_shell":
				pod.Spec.Containers[0].Command = []string{"sh", "-c", "unclassified-backup"}
			case "known_init":
				init = true
			case "tag_only_template":
				status = nil
			case "known_code_overlay":
				pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "code", MountPath: "/usr/local/bin"}}
			}
			_, err := classifyOriginalBackupViewStartup(&pod.Spec, &pod.Spec.Containers[0], status, init)
			if err == nil || errors.Is(err, errOriginalBackupConsumerUnclassified) != unknown {
				t.Fatal("unsafe known launch fell through or unrelated peer was intercepted", err)
			}
		})
	}
}
