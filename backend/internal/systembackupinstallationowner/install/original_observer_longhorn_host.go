package install

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"clawreef/internal/systembackup/quiesce"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// This has the exact JSON shape of runtime_sources.longhorn_hold. Pins refer
// to original input bytes; the existing controller material copier must map
// them to its read-only mount without changing their SHA256 values.
type OriginalObserverLonghornHoldConfig struct {
	Observer  OriginalObserverLonghornObserverConfig
	Materials []BootstrapSourceFilePin
}

type OriginalObserverLonghornObserverConfig struct {
	CAFile, CASHA256, CertificateFile, CertificateSHA256, KeyFile, KeySHA256 string
	Endpoints                                                                map[string]quiesce.ProofEndpoint
}

func originalLonghornObserverNodeSelected(pin BootstrapSourceFilePin, node, uid string) (bool, error) {
	if pin == (BootstrapSourceFilePin{}) {
		return false, nil
	}
	raw, err := readObserverHostFile(pin, 1<<20)
	var material quiesce.LonghornExt4Materials
	if err != nil || decodeExact(raw, &material) != nil || material.Version != quiesce.LonghornExt4Protocol {
		return false, ErrInstall
	}
	selected := false
	check := func(b quiesce.ObservationBinding) error {
		if b.Node != node {
			return nil
		}
		if b.NodeUID != uid {
			return ErrInstall
		}
		selected = true
		return nil
	}
	for _, source := range material.Sources {
		if check(source.Binding) != nil {
			return false, ErrInstall
		}
	}
	for _, client := range material.Clients {
		if check(client.Binding) != nil {
			return false, ErrInstall
		}
	}
	return selected, nil
}

func originalObserverLonghornControllerConfig(def OriginalObserverHostDefinition, pki GeneratedOriginalObserverPKI) (*OriginalObserverLonghornHoldConfig, error) {
	if def.LonghornVolumes == (BootstrapSourceFilePin{}) {
		return nil, nil
	}
	raw, err := readObserverHostFile(def.LonghornVolumes, 1<<20)
	var material quiesce.LonghornExt4Materials
	if err != nil || decodeExact(raw, &material) != nil || material.Version != quiesce.LonghornExt4Protocol || material.RecoveryURI != pki.ClientURI || def.SharedRuntime == nil {
		return nil, ErrInstall
	}
	endpoints := map[string]quiesce.ProofEndpoint{}
	nodes := map[string]string{}
	for _, ep := range pki.Endpoints {
		if ep.Kind == "shared" {
			endpoints[ep.Node], nodes[ep.Node] = ep.Endpoint, ep.NodeUID
		}
	}
	for _, s := range material.Sources {
		if nodes[s.Binding.Node] == "" || nodes[s.Binding.Node] != s.Binding.NodeUID {
			return nil, ErrInstall
		}
	}
	for _, c := range material.Clients {
		if nodes[c.Binding.Node] == "" || nodes[c.Binding.Node] != c.Binding.NodeUID {
			return nil, ErrInstall
		}
	}
	if len(endpoints) == 0 {
		return nil, ErrInstall
	}
	return &OriginalObserverLonghornHoldConfig{Observer: OriginalObserverLonghornObserverConfig{
		CAFile: pki.CA.File, CASHA256: pki.CA.SHA256,
		CertificateFile: pki.ClientCertificate.File, CertificateSHA256: pki.ClientCertificate.SHA256,
		KeyFile: pki.ClientKey.File, KeySHA256: pki.ClientKey.SHA256, Endpoints: endpoints},
		Materials: []BootstrapSourceFilePin{def.LonghornVolumes}}, nil
}

// Called inside the existing authenticated observer material producer's
// before/after check, before this same file enters any private Node bundle.
func (i *Installer) validateOriginalLonghornObserverVolumes(ctx context.Context, pin BootstrapSourceFilePin) error {
	return i.validateOriginalLonghornObserverVolumesWithTenant(ctx, pin, nil)
}

func (i *Installer) validateOriginalLonghornObserverVolumesWithTenant(ctx context.Context, pin BootstrapSourceFilePin, tenant func(quiesce.LonghornExt4SourceCoordinates) error) error {
	raw, err := readObserverHostFile(pin, 1<<20)
	var material quiesce.LonghornExt4Materials
	if err != nil || decodeExact(raw, &material) != nil || material.Version != quiesce.LonghornExt4Protocol ||
		len(material.Sources)+len(material.Clients) == 0 || len(material.Sources) > 8 || len(material.Clients) > 128 {
		return ErrInstall
	}
	for _, c := range material.Sources {
		if c.Binding.Kind != quiesce.LonghornExt4Protocol || c.Claim != (quiesce.LonghornExt4Claim{}) || c.Attempt != 0 || c.Binding.OperationID != "" ||
			c.Binding.Generation != 0 || c.Binding.InventorySHA256 != "" || !c.Binding.ExpiresAt.IsZero() {
			return ErrInstall
		}
		if c.Binding.Namespace != i.plan.Target.Namespace {
			if tenant == nil || tenant(c) != nil {
				return ErrInstall
			}
		} else if err := i.validateOriginalLonghornObserverClaim(ctx, c.Binding, c.PVCName, c.PVCUID, c.PVUID, c.VolumeHandle); err != nil {
			return err
		}
		if _, err := i.originalLonghornObserverVolume(ctx, c.LonghornNamespace, c.ProviderNamespaceUID, c.VolumeHandle); err != nil {
			return err
		}
		identity, err := quiesce.LonghornExt4SourceIdentity(c.OriginalSourceSHA256, c.ProviderNamespaceUID, c.Binding.NodeUID)
		if err != nil || c.Identity != "" && c.Identity != identity {
			return ErrInstall
		}
		pod, err := i.kube.CoreV1().Pods(c.ProviderNamespace).Get(ctx, c.ProviderPodName, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil || string(pod.UID) != c.ProviderPodUID || pod.Spec.NodeName != c.Binding.Node {
			return ErrInstall
		}
		found := false
		for _, status := range pod.Status.ContainerStatuses {
			if status.ContainerID == c.ProviderContainerID && status.State.Running != nil {
				found = true
			}
		}
		if !found {
			return ErrInstall
		}
	}
	for _, c := range material.Clients {
		if c.Binding.Kind != quiesce.LonghornExt4Protocol || c.Claim != (quiesce.LonghornExt4Claim{}) || c.Attempt != 0 || c.Binding.OperationID != "" || c.Binding.Generation != 0 ||
			c.Binding.InventorySHA256 != "" || !c.Binding.ExpiresAt.IsZero() ||
			c.PodName != "" || c.PodUID != "" || c.ContainerID != "" || c.Binding.Namespace != c.PodNamespace {
			return ErrInstall
		}
		if err := i.validateOriginalLonghornObserverClaim(ctx, c.Binding, c.PVCName, c.PVCUID, c.PVUID, c.VolumeHandle); err != nil {
			return err
		}
		// Provider namespace is explicit in the NFS URL authority's trusted
		// Longhorn source. Resolve it only from the selected source entries.
		providerNS := ""
		for _, source := range material.Sources {
			if source.VolumeHandle == c.VolumeHandle && source.ProviderNamespaceUID == c.ProviderNamespaceUID {
				if providerNS != "" && providerNS != source.LonghornNamespace {
					return ErrInstall
				}
				providerNS = source.LonghornNamespace
			}
		}
		if providerNS == "" {
			return ErrInstall
		}
		volume, err := i.originalLonghornObserverVolume(ctx, providerNS, c.ProviderNamespaceUID, c.VolumeHandle)
		if err != nil {
			return err
		}
		endpoint, _, _ := unstructured.NestedString(volume.Object, "status", "shareEndpoint")
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "nfs" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" {
			return ErrInstall
		}
		host := u.Hostname()
		if host != c.Endpoint {
			name := strings.Split(host, ".")[0]
			if !strings.HasSuffix(host, "."+providerNS+".svc.cluster.local") {
				return ErrInstall
			}
			service, err := i.kube.CoreV1().Services(providerNS).Get(ctx, name, metav1.GetOptions{})
			if err != nil || service.DeletionTimestamp != nil || service.Spec.ClusterIP != c.Endpoint {
				return ErrInstall
			}
		}
		if c.NFSSource != host+":"+u.Path && c.NFSSource != c.Endpoint+":"+u.Path {
			return ErrInstall
		}
		identity, err := quiesce.LonghornExt4SourceIdentity(c.OriginalSourceSHA256, c.ProviderNamespaceUID, c.Binding.NodeUID)
		if err != nil || c.Identity != "" && c.Identity != identity {
			return ErrInstall
		}
	}
	return nil
}

func (i *Installer) validateOriginalLonghornObserverClaim(ctx context.Context, b quiesce.ObservationBinding, name, uid, pvUID, handle string) error {
	if b.Namespace != i.plan.Target.Namespace || b.NamespaceUID != i.plan.Target.NamespaceUID {
		return ErrInstall
	}
	return i.validateOriginalLonghornObserverClaimObjects(ctx, b, name, uid, pvUID, handle)
}

func (i *Installer) validateOriginalLonghornObserverClaimObjects(ctx context.Context, b quiesce.ObservationBinding, name, uid, pvUID, handle string) error {
	if b.InstallationID != i.plan.Target.InstallationID || b.Namespace == "" || b.NamespaceUID == "" || b.Node == "" || b.NodeUID == "" ||
		name == "" || uid == "" || pvUID == "" || handle == "" {
		return ErrInstall
	}
	ns, err := i.kube.CoreV1().Namespaces().Get(ctx, b.Namespace, metav1.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil || string(ns.UID) != b.NamespaceUID {
		return ErrInstall
	}
	node, err := i.kube.CoreV1().Nodes().Get(ctx, b.Node, metav1.GetOptions{})
	if err != nil || node.DeletionTimestamp != nil || string(node.UID) != b.NodeUID || node.Status.NodeInfo.OperatingSystem != "linux" {
		return ErrInstall
	}
	claim, err := i.kube.CoreV1().PersistentVolumeClaims(b.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || claim.DeletionTimestamp != nil || string(claim.UID) != uid || claim.Spec.VolumeName == "" {
		return ErrInstall
	}
	pv, err := i.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
	if err != nil || pv.DeletionTimestamp != nil || string(pv.UID) != pvUID || pv.Spec.CSI == nil ||
		pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle != handle || pv.Spec.ClaimRef == nil ||
		string(pv.Spec.ClaimRef.UID) != uid || pv.Spec.ClaimRef.Name != name || pv.Spec.ClaimRef.Namespace != b.Namespace {
		return ErrInstall
	}
	return nil
}

func (i *Installer) originalLonghornObserverVolume(ctx context.Context, namespace, namespaceUID, handle string) (*unstructured.Unstructured, error) {
	ns, err := i.kube.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil || ns.DeletionTimestamp != nil || string(ns.UID) != namespaceUID {
		return nil, ErrInstall
	}
	rest := i.kube.CoreV1().RESTClient()
	if rest == nil {
		return nil, ErrInstall
	}
	raw, err := rest.Get().AbsPath("/apis/longhorn.io/v1beta2/namespaces/" + url.PathEscape(namespace) + "/volumes/" + url.PathEscape(handle)).DoRaw(ctx)
	var volume unstructured.Unstructured
	if err != nil || json.Unmarshal(raw, &volume) != nil || volume.GetName() != handle || volume.GetNamespace() != namespace ||
		volume.GetUID() == "" || volume.GetDeletionTimestamp() != nil {
		return nil, ErrInstall
	}
	return &volume, nil
}
