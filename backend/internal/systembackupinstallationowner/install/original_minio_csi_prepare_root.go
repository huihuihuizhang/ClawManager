package install

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// originalMinIOCSIPrepareRoot adds only the selected original MinIO whole
// Longhorn root to B's native PREPARE. It does not create a holder or authorize
// archive reading. A second actual CRI/device observation must match the
// immutable warm native plan before the node is asked to protect this path.
func (s *PreparedOriginalWriterSet) originalMinIOCSIPrepareRoot(ctx context.Context, pod *core.Pod) (string, error) {
	fail := func() (string, error) { return "", ErrInstall }
	if s == nil || s.minioHistory == nil || s.minioHistory.writer == nil || pod == nil || ctx == nil || ctx.Err() != nil || s.minioHistory.check(ctx) != nil || s.minioHistory.native.PlanFile == "" || s.minioHistory.native.PlanSHA256 == "" || len(pod.Status.ContainerStatuses) != 1 || len(pod.Spec.Containers) != 1 || len(pod.Spec.EphemeralContainers) != 0 {
		return fail()
	}
	writer := s.minioHistory.writer
	status := pod.Status.ContainerStatuses[0]
	if writer.selection.Name != "minio" || writer.namespace != s.initial.Namespace || writer.namespaceUID != s.initial.NamespaceUID || len(writer.pods) != 1 || writer.pods[0].UID != string(pod.UID) || len(writer.pods[0].Containers) != 1 || writer.pods[0].Containers[0] != status.ContainerID || status.Name != "minio" || status.State.Running == nil || !status.Ready || !strings.HasPrefix(status.ContainerID, "containerd://") || pod.Spec.Containers[0].Name != "minio" {
		return fail()
	}
	var keeper *originalLonghornKeeper
	for _, item := range s.longhornKeepers {
		if item == nil || item.set != s || item.writer == nil {
			return fail()
		}
		if item.writer != writer {
			continue
		}
		if keeper != nil || item.plan.Identity.Namespace != pod.Namespace || item.plan.NamespaceUID != s.initial.NamespaceUID || item.plan.Node != pod.Spec.NodeName || item.plan.Source.Name == "" || item.plan.Source.UID == "" || item.plan.Source.PVUID == "" {
			return fail()
		}
		keeper = item
	}
	if keeper == nil {
		return fail()
	}
	source, ok := s.longhornSources[pod.Namespace+"/"+keeper.plan.Source.Name]
	if !ok || source.Binding.Namespace != pod.Namespace || source.Binding.NamespaceUID != s.initial.NamespaceUID || source.Binding.Node != pod.Spec.NodeName || source.Binding.NodeUID != keeper.plan.NodeUID || source.PVCUID != keeper.plan.Source.UID || source.PVUID != keeper.plan.Source.PVUID || source.ProviderPodUID != string(pod.UID) || source.ProviderContainerID != status.ContainerID || source.MountPoint != "/data" || source.VolumeHandle == "" {
		return fail()
	}
	node, err := s.owner.operator.installer.kube.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || string(node.UID) != keeper.plan.NodeUID || node.DeletionTimestamp != nil || node.Status.NodeInfo.BootID == "" || node.Status.NodeInfo.MachineID == "" {
		return fail()
	}
	native := s.minioHistory.native
	if originalReaderExecutable(native.PythonFile, native.PythonSHA256) != nil || originalReaderExecutable(native.ScriptFile, native.ScriptSHA256) != nil {
		return fail()
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: native.PlanFile, SHA256: native.PlanSHA256}, 262144)
	var plan struct {
		Profile       string `json:"profile"`
		Root          string `json:"root"`
		Endpoint      string `json:"cri_endpoint"`
		CRIFile       string `json:"crictl_file"`
		CRISHA        string `json:"crictl_sha256"`
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		PodUID        string `json:"pod_uid"`
		Node          struct {
			BootID    string `json:"boot_id"`
			MachineID string `json:"machine_id"`
		} `json:"node"`
		CSI struct {
			Driver      string `json:"driver"`
			Handle      string `json:"handle"`
			Destination string `json:"destination"`
			DevicePath  string `json:"device_path"`
			MajorMinor  string `json:"major_minor"`
			CRISource   string `json:"cri_source"`
		} `json:"csi"`
	}
	if err != nil || json.Unmarshal(raw, &plan) != nil || plan.Profile != "original-minio-longhorn-csi-native-raw-cut.v1" || plan.Root == "/" || !filepath.IsAbs(plan.Root) || filepath.Clean(plan.Root) != plan.Root || plan.PodUID != string(pod.UID) || plan.ContainerName != status.Name || plan.ContainerID != strings.TrimPrefix(status.ContainerID, "containerd://") || plan.CSI.Driver != "driver.longhorn.io" || plan.CSI.Handle != source.VolumeHandle || plan.CSI.Destination != "/data" || plan.CSI.DevicePath != "/dev/longhorn/"+source.VolumeHandle || plan.CSI.MajorMinor == "" || plan.CSI.CRISource == "" || plan.Node.BootID != node.Status.NodeInfo.BootID || plan.Node.MachineID != node.Status.NodeInfo.MachineID || !strings.HasPrefix(plan.Endpoint, "unix:///") || plan.CRISHA != "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3" || originalReaderExecutable(plan.CRIFile, plan.CRISHA) != nil {
		return fail()
	}
	var out originalHistoryLimitedOutput
	cmd := exec.CommandContext(ctx, native.PythonFile, "-I", "-B", native.ScriptFile, "observe-csi", "--cri-endpoint", plan.Endpoint, "--crictl-file", plan.CRIFile, "--crictl-sha256", plan.CRISHA, "--container-id", plan.ContainerID, "--pod-uid", plan.PodUID, "--container-name", plan.ContainerName, "--destination", "/data", "--csi-handle", plan.CSI.Handle)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &out, io.Discard
	cmd.WaitDelay = 5 * time.Second
	if cmd.Run() != nil || len(out.Bytes()) > 262144 {
		return fail()
	}
	var observed struct {
		Root          string `json:"root"`
		PodUID        string `json:"pod_uid"`
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		Node          struct {
			BootID    string `json:"boot_id"`
			MachineID string `json:"machine_id"`
		} `json:"node"`
		CSI struct {
			Driver      string `json:"driver"`
			Handle      string `json:"handle"`
			Destination string `json:"destination"`
			DevicePath  string `json:"device_path"`
			MajorMinor  string `json:"major_minor"`
			CRISource   string `json:"cri_source"`
		} `json:"csi"`
	}
	if json.Unmarshal(out.Bytes(), &observed) != nil || observed.Root != plan.Root || observed.PodUID != plan.PodUID || observed.ContainerID != plan.ContainerID || observed.ContainerName != plan.ContainerName || observed.Node.BootID != plan.Node.BootID || observed.Node.MachineID != plan.Node.MachineID || observed.CSI.Driver != plan.CSI.Driver || observed.CSI.Handle != plan.CSI.Handle || observed.CSI.Destination != plan.CSI.Destination || observed.CSI.DevicePath != plan.CSI.DevicePath || observed.CSI.MajorMinor != plan.CSI.MajorMinor || observed.CSI.CRISource != plan.CSI.CRISource || s.minioHistory.check(ctx) != nil {
		return fail()
	}
	return plan.Root, nil
}
