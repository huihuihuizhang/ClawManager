package install

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	archive "clawreef/internal/systembackuphostpatharchive"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OriginalMinIOHistoryNativePlanInputs struct {
	Version                      string
	ArchiveTemplate, CRI         BootstrapSourceFilePin
	CRIEndpoint, OutputDirectory string
}

// Native source DATA producer, not an archive grant, holder or coverage. The
// actual owner derives the native root/container arguments from current API
// sources and verifies the pinned Python observation before saving its bytes.
type OriginalNativePlanError struct{ Stage string }

func (e *OriginalNativePlanError) Error() string {
	return "original MinIO native plan refused at " + e.Stage
}
func (e *OriginalNativePlanError) Unwrap() error { return ErrInstall }

func (i *Installer) PrepareOriginalMinIOHistoryNativePlan(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalMinIOHistoryNativePlanInputs) (_ archive.NativeStream, resultErr error) {
	var zero archive.NativeStream
	stage := "owner_and_cri"
	defer func() {
		if resultErr != nil {
			resultErr = &OriginalNativePlanError{Stage: stage}
		}
	}()
	if i == nil || ctx == nil {
		return zero, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil || in.Version != "original-minio-history-native-plan-inputs.v1" || privateDirectory(in.OutputDirectory) != nil || in.CRI.SHA256 != "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3" || originalReaderExecutable(in.CRI.File, in.CRI.SHA256) != nil || !strings.HasPrefix(in.CRIEndpoint, "unix:///") || strings.ContainsAny(in.CRIEndpoint, "\x00\r\n") {
		return zero, ErrInstall
	}
	stage = "archive_template"
	raw, e := readBootstrapSourcePin(in.ArchiveTemplate, 262144)
	var d OriginalArchiveProviderDefinition
	if e != nil || decodeExact(raw, &d) != nil || d.Version != "original-adoption-evidence-archive-template.v1" || d.PlanSHA256 != "" || d.OperationIdentitySHA256 != "" || d.MaximumFiles <= 0 || d.MaximumBytes <= 0 || d.MaximumSeconds < 1 || d.MaximumSeconds > 600 || originalReaderExecutable(d.NativePythonFile, d.NativePythonSHA256) != nil || originalReaderExecutable(d.NativeScriptFile, d.NativeScriptSHA256) != nil {
		return zero, ErrInstall
	}
	stage = "minio_permission_definition"
	raw, e = readBootstrapSourcePin(BootstrapSourceFilePin{File: d.MinIODefinitionFile, SHA256: d.MinIODefinitionSHA256}, 262144)
	var minio MinIOPermissionDefinition
	if e != nil || decodeExact(raw, &minio) != nil || minio.Grant.Installation != i.plan.Target.InstallationID || minio.Grant.Namespace != i.plan.Target.Namespace || minio.Grant.NamespaceUID != i.plan.Target.NamespaceUID {
		return zero, ErrInstall
	}
	stage = "minio_deployment_and_pod"
	p := minio.Grant.Provider
	actor, e := i.originalDeploymentActor(ctx, p.Deployment.Name, p.Pod.Name, &p)
	if e != nil || actor.PodUID != p.Pod.UID {
		return zero, ErrInstall
	}
	deployment, e := i.kube.AppsV1().Deployments(minio.Grant.Namespace).Get(ctx, p.Deployment.Name, metav1.GetOptions{})
	if e != nil || string(deployment.UID) != p.Deployment.UID || deployment.DeletionTimestamp != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Status.ReadyReplicas != 1 || deployment.Status.ObservedGeneration < deployment.Generation {
		return zero, ErrInstall
	}
	volume := ""
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == p.Container {
			for _, mount := range container.VolumeMounts {
				if mount.MountPath == "/data" {
					if volume != "" || mount.SubPath != "" || mount.SubPathExpr != "" || mount.ReadOnly {
						return zero, ErrInstall
					}
					volume = mount.Name
				}
			}
		}
	}
	if volume == "" {
		return zero, ErrInstall
	}
	found := false
	for _, v := range deployment.Spec.Template.Spec.Volumes {
		if v.Name == volume {
			if found || v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != d.PVCName || v.PersistentVolumeClaim.ReadOnly {
				return zero, ErrInstall
			}
			found = true
		} else if v.PersistentVolumeClaim != nil || v.HostPath != nil || v.CSI != nil || v.NFS != nil {
			return zero, ErrInstall
		}
	}
	if !found {
		return zero, ErrInstall
	}
	stage = "minio_claim_and_volume"
	claim, e := i.kube.CoreV1().PersistentVolumeClaims(minio.Grant.Namespace).Get(ctx, d.PVCName, metav1.GetOptions{})
	if e != nil || string(claim.UID) != d.PVCUID || claim.DeletionTimestamp != nil || claim.Status.Phase != "Bound" || claim.Spec.VolumeName != d.PVName {
		return zero, ErrInstall
	}
	pv, e := i.kube.CoreV1().PersistentVolumes().Get(ctx, d.PVName, metav1.GetOptions{})
	if e != nil || string(pv.UID) != d.PVUID || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != d.PVCUID || pv.Spec.ClaimRef.Namespace != minio.Grant.Namespace || pv.Spec.ClaimRef.Name != d.PVCName {
		return zero, ErrInstall
	}
	root, csiHandle := "", ""
	if pv.Spec.HostPath != nil {
		if pv.Spec.CSI != nil {
			return zero, ErrInstall
		}
		root = pv.Spec.HostPath.Path
	} else {
		csiHandle, e = originalMinIOCSIHandle(pv, claim)
		if e != nil {
			return zero, ErrInstall
		}
	}
	if csiHandle == "" && (!filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || custodyWithin(root, in.OutputDirectory)) {
		return zero, ErrInstall
	}
	stage = "minio_node_and_container"
	node, e := i.kube.CoreV1().Nodes().Get(ctx, p.Node, metav1.GetOptions{})
	if e != nil || string(node.UID) != p.NodeUID || node.DeletionTimestamp != nil || node.Status.NodeInfo.BootID == "" || node.Status.NodeInfo.MachineID == "" {
		return zero, ErrInstall
	}
	pod, e := i.kube.CoreV1().Pods(minio.Grant.Namespace).Get(ctx, p.Pod.Name, metav1.GetOptions{})
	if e != nil || string(pod.UID) != p.Pod.UID || pod.Spec.NodeName != p.Node || pod.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	containerID := ""
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == p.Container && status.ImageID == p.ImageID && status.Ready && status.State.Running != nil {
			if containerID != "" || !strings.HasPrefix(status.ContainerID, "containerd://") {
				return zero, ErrInstall
			}
			containerID = strings.TrimPrefix(status.ContainerID, "containerd://")
		}
	}
	if containerID == "" {
		return zero, ErrInstall
	}
	stage = "native_python_observation"
	var output originalHistoryLimitedOutput
	args := []string{"-I", "-B", d.NativeScriptFile, "prepare", "--cri-endpoint", in.CRIEndpoint, "--crictl-file", in.CRI.File, "--crictl-sha256", in.CRI.SHA256, "--container-id", containerID, "--pod-uid", p.Pod.UID, "--container-name", p.Container}
	if csiHandle == "" {
		args = append(args, "--root", root)
	} else {
		args = append(args, "--csi-handle", csiHandle)
	}
	cmd := exec.CommandContext(ctx, d.NativePythonFile, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &output, io.Discard
	cmd.WaitDelay = 5 * time.Second
	if cmd.Run() != nil || len(output.Bytes()) > 262144 {
		return zero, ErrInstall
	}
	stage = "native_physical_coordinates"
	var plan struct {
		Profile     string                                       `json:"profile"`
		CSI         struct{ Driver, Handle, Destination string } `json:"csi"`
		Root        string                                       `json:"root"`
		PodUID      string                                       `json:"pod_uid"`
		Container   string                                       `json:"container_name"`
		ContainerID string                                       `json:"container_id"`
		Node        struct {
			BootID    string `json:"boot_id"`
			MachineID string `json:"machine_id"`
		} `json:"node"`
		Format struct {
			DeploymentID string `json:"deployment_id"`
		} `json:"format"`
	}
	if json.Unmarshal(output.Bytes(), &plan) != nil || plan.PodUID != p.Pod.UID || plan.Container != p.Container || plan.ContainerID != containerID || plan.Node.BootID != node.Status.NodeInfo.BootID || plan.Node.MachineID != node.Status.NodeInfo.MachineID || plan.Format.DeploymentID != p.DeploymentID {
		return zero, ErrInstall
	}
	if csiHandle == "" {
		if plan.Profile != "original-minio-hostpath-native-raw-cut.v1" || plan.Root != root {
			return zero, ErrInstall
		}
	} else if plan.Profile != "original-minio-longhorn-csi-native-raw-cut.v1" || plan.CSI.Driver != "driver.longhorn.io" || plan.CSI.Handle != csiHandle || plan.CSI.Destination != "/data" || !filepath.IsAbs(plan.Root) || filepath.Clean(plan.Root) != plan.Root || plan.Root == "/" || custodyWithin(plan.Root, in.OutputDirectory) {
		return zero, ErrInstall
	}
	stage = "native_tail_authority"
	again, e := i.originalDeploymentActor(ctx, p.Deployment.Name, p.Pod.Name, &p)
	if e != nil || again != actor || s.authority(ctx, enrollment) != nil || originalReaderExecutable(d.NativePythonFile, d.NativePythonSHA256) != nil || originalReaderExecutable(d.NativeScriptFile, d.NativeScriptSHA256) != nil || originalReaderExecutable(in.CRI.File, in.CRI.SHA256) != nil {
		return zero, ErrInstall
	}
	stage = "native_plan_write"
	const name = "original-minio-warm.native-plan.json"
	if writeNewFiles(in.OutputDirectory, map[string][]byte{name: output.Bytes()}) != nil {
		return zero, ErrInstall
	}
	return archive.NativeStream{PythonFile: d.NativePythonFile, PythonSHA256: d.NativePythonSHA256, ScriptFile: d.NativeScriptFile, ScriptSHA256: d.NativeScriptSHA256, PlanFile: filepath.Join(in.OutputDirectory, name), PlanSHA256: hash(output.Bytes()), MaxFiles: d.MaximumFiles, MaxBytes: d.MaximumBytes, MaxSeconds: d.MaximumSeconds}, nil
}
