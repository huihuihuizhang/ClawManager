package systembackupexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Stage declaration enters the original core before its hash/signatures. The
// native Linux SQL fixture keeps the real host stage; no post-capture repair.
func aOriginalCompleteStagingOptions(o *dOriginalSixPartFixtureOptions) {
	after := o.AfterOwnerReady
	o.AfterOwnerReady = func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) error {
		if after != nil {
			if err := after(ctx, t, f); err != nil {
				return err
			}
		}
		cfg := f.service.Config
		client := f.owner.Client.(*fake.Clientset)
		node, claim, pv := publicationStagingFixtureObjects(t, cfg)
		oldNode, err := client.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
		if err != nil || oldNode.UID != node.UID {
			return fmt.Errorf("original stage node identity: %w", err)
		}
		node.ResourceVersion = oldNode.ResourceVersion
		if _, err = client.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{}); err != nil {
			return err
		}
		if old, e := client.CoreV1().PersistentVolumeClaims(cfg.Namespace).Get(ctx, claim.Name, metav1.GetOptions{}); e == nil {
			if old.UID != claim.UID {
				return fmt.Errorf("stage claim replaced")
			}
			claim.ResourceVersion = old.ResourceVersion
			_, err = client.CoreV1().PersistentVolumeClaims(cfg.Namespace).Update(ctx, claim, metav1.UpdateOptions{})
		} else if apierrors.IsNotFound(e) {
			_, err = client.CoreV1().PersistentVolumeClaims(cfg.Namespace).Create(ctx, claim, metav1.CreateOptions{})
		} else {
			return e
		}
		if err != nil {
			return err
		}
		if old, e := client.CoreV1().PersistentVolumes().Get(ctx, pv.Name, metav1.GetOptions{}); e == nil {
			if old.UID != pv.UID {
				return fmt.Errorf("stage PV replaced")
			}
			pv.ResourceVersion = old.ResourceVersion
			_, err = client.CoreV1().PersistentVolumes().Update(ctx, pv, metav1.UpdateOptions{})
		} else if apierrors.IsNotFound(e) {
			_, err = client.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{})
		} else {
			return e
		}
		if err != nil {
			return err
		}
		pod, err := client.CoreV1().Pods(cfg.Namespace).Get(ctx, "d-platform-pod", metav1.GetOptions{})
		if err != nil || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != cfg.StagingLocation.Container {
			return fmt.Errorf("original controller stage container: %w", err)
		}
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: cfg.StagingLocation.Volume, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: cfg.StagingClaim}}})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: cfg.StagingLocation.Volume, MountPath: cfg.StagingDirectory})
		_, err = client.CoreV1().Pods(cfg.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
		return err
	}
}

func (x *aOriginalForwardFixture) completeNonDRPublisher(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, p *PublisherVerifierMaterials) error {
	pin, err := originalFailureDomainsPin(f.config)
	if err != nil {
		return err
	}
	policy := originalPublicationPolicy{Version: originalPublicationPolicyVersion, Installation: p.Binding.InstallationID, ConfigSHA256: hash(f.config), FailureDomains: pin, Target: publicationManifestTarget{Class: f.profile.TargetClass, Domain: f.profile.FailureDomain, Risks: append([]string{}, f.profile.TargetRisks...)}, RecoveryEvidenceStatus: "not_provided"}
	if policy.validate() != nil {
		return fmt.Errorf("original non-DR policy")
	}
	raw, err := ce.Canonical(policy)
	if err != nil {
		return err
	}
	file := filepath.Join(f.directory, "original-complete-non-dr-policy.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		return err
	}
	p.RecoveryTrust = nil
	f.service.captureMaterials.Discovery.PublicationPolicy = &originalPublicationPolicyReference{Protocol: originalPublicationPolicyVersion, Path: file, SHA256: hash(raw)}
	f.repinOriginalMetadataSource(t)
	targetRaw, err := json.Marshal(x.store.config)
	if err != nil {
		return err
	}
	if err = f.service.loadPublicationTargetInput([]PublicationTargetInput{{File: f.service.Config.PublicationTarget.Path, SHA256: hash(targetRaw)}}); err != nil {
		return err
	}
	return f.owner.Client.(*fake.Clientset).Tracker().Add(&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: f.service.Config.Namespace, Name: f.service.Config.PublicationWorker.ServiceAccountName, UID: types.UID(f.service.Config.PublicationWorker.ServiceAccountUID)}})
}
