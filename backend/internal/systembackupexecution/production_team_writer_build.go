package systembackupexecution

import (
	d "clawreef/internal/systembackupdispatch"
	"context"
	"encoding/hex"
	"encoding/json"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"sort"
	"strings"
)

// Existing Materials metadata scope signs each original business release pin.
// BuildCommit identifies that release; linked reader buildinfo is separate.
type productionTeamWriterImage struct{ Container, Image, ConfigDigest, BuildCommit string }
type productionTeamWriterBuild struct {
	Deployment, DeploymentUID, Container, Kind, Image, ConfigDigest, BuildCommit, TemplateSHA256 string
	Pods                                                                                         []productionTeamWriterPod
}
type productionTeamWriterPod struct{ UID, ImageID string }

func teamWriterImageDigest(image string) string {
	i := strings.LastIndex(image, "@sha256:")
	if i < 1 || !formalCandidateDigest(image[i+8:]) {
		return ""
	}
	return image[i+1:]
}
func validTeamWriterImage(pin productionTeamWriterImage) bool {
	commit, e := hex.DecodeString(pin.BuildCommit)
	return pin.Container != "" && teamWriterImageDigest(pin.Image) != "" && strings.HasPrefix(pin.ConfigDigest, "sha256:") && formalCandidateDigest(strings.TrimPrefix(pin.ConfigDigest, "sha256:")) && e == nil && len(commit) == 20 && strings.ToLower(pin.BuildCommit) == pin.BuildCommit
}
func teamWriterContentID(id string, pin productionTeamWriterImage) bool {
	for _, digest := range []string{teamWriterImageDigest(pin.Image), pin.ConfigDigest} {
		if digest != "" && (strings.HasSuffix(id, "@"+digest) || id == digest || id == "containerd://"+digest || id == "docker://"+digest) {
			return true
		}
	}
	return false
}

// Every ordinary/init container has its own original release pin. WorkerImage
// belongs to another role and must never supply a business writer expectation.
func observeTeamWriterBuild(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, m productionCaptureMaterials, saved *productionTeamZeroCensus) ([]productionTeamWriterBuild, error) {
	if api == nil || m.Discovery == nil || len(m.Discovery.TeamPlatformUnits) == 0 || len(m.Discovery.TeamWriterImages) != len(m.Discovery.TeamPlatformUnits) {
		return nil, d.ErrNotReady
	}
	ids := []string{}
	for id := range m.Discovery.TeamPlatformUnits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := []productionTeamWriterBuild{}
	for _, id := range ids {
		parts := strings.Split(id, "/")
		if len(parts) != 3 || parts[0] != "deployment" || parts[1] != cfg.Namespace {
			return nil, d.ErrNotReady
		}
		originalUID := ""
		writerCount := 0
		for _, writer := range cfg.Writers {
			if writer.Namespace == parts[1] && writer.Name == parts[2] {
				originalUID = writer.UID
				writerCount++
			}
		}
		if originalUID == "" || writerCount != 1 {
			return nil, d.ErrNotReady
		}
		deployment, err := api.AppsV1().Deployments(parts[1]).Get(ctx, parts[2], metav1.GetOptions{})
		if err != nil || string(deployment.UID) != originalUID || deployment.DeletionTimestamp != nil || deployment.Spec.Selector == nil || len(deployment.Spec.Template.Spec.EphemeralContainers) != 0 {
			return nil, d.ErrNotReady
		}
		templateRaw, err := json.Marshal(deployment.Spec.Template)
		if err != nil {
			return nil, d.ErrNotReady
		}
		templateSHA := hash(templateRaw)
		pins := m.Discovery.TeamWriterImages[id]
		if len(pins) == 0 || len(pins) > 128 {
			return nil, d.ErrNotReady
		}
		expected := map[string]productionTeamWriterImage{}
		for _, pin := range pins {
			if !validTeamWriterImage(pin) || expected[pin.Container].Container != "" {
				return nil, d.ErrNotReady
			}
			expected[pin.Container] = pin
		}
		observed := map[string]*productionTeamWriterBuild{}
		for kind, containers := range map[string][]corev1.Container{"container": deployment.Spec.Template.Spec.Containers, "init": deployment.Spec.Template.Spec.InitContainers} {
			for _, container := range containers {
				pin, ok := expected[container.Name]
				if !ok || observed[container.Name] != nil || container.Image != pin.Image {
					return nil, d.ErrNotReady
				}
				observed[container.Name] = &productionTeamWriterBuild{Deployment: id, DeploymentUID: originalUID, Container: container.Name, Kind: kind, Image: pin.Image, ConfigDigest: pin.ConfigDigest, BuildCommit: pin.BuildCommit, TemplateSHA256: templateSHA, Pods: []productionTeamWriterPod{}}
			}
		}
		if len(observed) != len(expected) || len(deployment.Spec.Template.Spec.Containers) == 0 {
			return nil, d.ErrNotReady
		}
		selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
		if err != nil || selector.Empty() {
			return nil, d.ErrNotReady
		}
		continuation := ""
		version := ""
		tokens := map[string]bool{}
		seenPods := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 100 {
				return nil, d.ErrNotReady
			}
			pods, err := api.CoreV1().Pods(parts[1]).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 1000, Continue: continuation})
			if err != nil || pods.ResourceVersion == "" || len(pods.Items) > 1000 {
				return nil, d.ErrNotReady
			}
			if page == 0 {
				version = pods.ResourceVersion
			} else if version != pods.ResourceVersion {
				return nil, d.ErrNotReady
			}
			for _, pod := range pods.Items {
				uid := string(pod.UID)
				if uid == "" || seenPods[uid] || pod.DeletionTimestamp != nil || !selector.Matches(labels.Set(pod.Labels)) || len(pod.Spec.EphemeralContainers) != 0 {
					return nil, d.ErrNotReady
				}
				seenPods[uid] = true
				owner := metav1.GetControllerOf(&pod)
				if owner == nil || owner.Kind != "ReplicaSet" {
					return nil, d.ErrNotReady
				}
				rs, err := api.AppsV1().ReplicaSets(parts[1]).Get(ctx, owner.Name, metav1.GetOptions{})
				if err != nil || rs.UID != owner.UID {
					return nil, d.ErrNotReady
				}
				parent := metav1.GetControllerOf(rs)
				if parent == nil || parent.Kind != "Deployment" || parent.UID != deployment.UID || parent.Name != deployment.Name {
					return nil, d.ErrNotReady
				}
				seenContainers := map[string]bool{}
				for kind, containers := range map[string][]corev1.Container{"container": pod.Spec.Containers, "init": pod.Spec.InitContainers} {
					statuses := pod.Status.ContainerStatuses
					if kind == "init" {
						statuses = pod.Status.InitContainerStatuses
					}
					if len(statuses) != len(containers) {
						return nil, d.ErrNotReady
					}
					for _, container := range containers {
						entry := observed[container.Name]
						if entry == nil || seenContainers[container.Name] || entry.Kind != kind || entry.Image != container.Image {
							return nil, d.ErrNotReady
						}
						seenContainers[container.Name] = true
						count := 0
						imageID := ""
						for _, status := range statuses {
							if status.Name == container.Name {
								count++
								imageID = status.ImageID
							}
						}
						if count != 1 || !teamWriterContentID(imageID, expected[container.Name]) {
							return nil, d.ErrNotReady
						}
						entry.Pods = append(entry.Pods, productionTeamWriterPod{UID: uid, ImageID: imageID})
					}
				}
				if len(seenContainers) != len(expected) {
					return nil, d.ErrNotReady
				}
			}
			continuation = pods.Continue
			if continuation == "" {
				break
			}
			if tokens[continuation] {
				return nil, d.ErrNotReady
			}
			tokens[continuation] = true
		}
		for _, entry := range observed {
			if len(entry.Pods) == 0 {
				// At original pause only the same authenticated frozen observation supplies
				// Pods, while current UID, template and original release pins still match.
				if saved == nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 {
					return nil, d.ErrNotReady
				}
				count := 0
				for _, old := range saved.Writers {
					if old.Deployment == entry.Deployment && old.DeploymentUID == entry.DeploymentUID && old.Container == entry.Container && old.Kind == entry.Kind && old.Image == entry.Image && old.ConfigDigest == entry.ConfigDigest && old.BuildCommit == entry.BuildCommit && old.TemplateSHA256 == entry.TemplateSHA256 {
						entry.Pods = append(entry.Pods, old.Pods...)
						count++
					}
				}
				if count != 1 || len(entry.Pods) == 0 {
					return nil, d.ErrNotReady
				}
			}
			sort.Slice(entry.Pods, func(i, j int) bool { return entry.Pods[i].UID < entry.Pods[j].UID })
			result = append(result, *entry)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Deployment != result[j].Deployment {
			return result[i].Deployment < result[j].Deployment
		}
		return result[i].Container < result[j].Container
	})
	return result, nil
}
