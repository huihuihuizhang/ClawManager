package install

import (
	"encoding/json"
	"io"
	corev1 "k8s.io/api/core/v1"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// This only validates original API DATA. Held authority is a distinct opaque
// OriginalMinIOCSIPhysicalSource constructed by the same original writer hold.
func originalMinIOCSIHandle(pv *corev1.PersistentVolume, claim *corev1.PersistentVolumeClaim) (string, error) {
	if pv == nil || claim == nil || pv.Spec.HostPath != nil || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.FSType != "ext4" || pv.Spec.CSI.ReadOnly || !regexp.MustCompile(`^pvc-[a-f0-9-]{36}$`).MatchString(pv.Spec.CSI.VolumeHandle) || pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode != corev1.PersistentVolumeFilesystem || claim.Spec.VolumeMode != nil && *claim.Spec.VolumeMode != corev1.PersistentVolumeFilesystem || len(pv.Spec.AccessModes) != 1 || pv.Spec.AccessModes[0] != corev1.ReadWriteOnce || len(claim.Spec.AccessModes) != 1 || claim.Spec.AccessModes[0] != corev1.ReadWriteOnce {
		return "", ErrInstall
	}
	return pv.Spec.CSI.VolumeHandle, nil
}

// The byte plan is only native DATA. Opaque held-source checks precede and
// follow every observation; neither these fields nor a path confer authority.
func (p *OriginalAdoptionArchiveProvider) originalMinIOCSIPath(handle, boot, machine string) (string, string, string, error) {
	fail := func() (string, string, string, error) { return "", "", "", ErrInstall }
	if p.physical == nil || p.physical.Check(p.ctx) != nil {
		return fail()
	}
	c, err := p.physical.Coordinates(p.ctx)
	if err != nil || c.OperationID != p.reservation.OperationID || c.InstallationID != p.reservation.InstallationID || c.Namespace != p.minio.Grant.Namespace || c.NamespaceUID != p.minio.Grant.NamespaceUID || c.Node != p.minio.Grant.Provider.Node || c.NodeUID != p.minio.Grant.Provider.NodeUID || c.BootID != boot || c.MachineID != machine || c.PVCName != p.definition.PVCName || c.PVCUID != p.definition.PVCUID || c.PVName != p.definition.PVName || c.PVUID != p.definition.PVUID || c.VolumeHandle != handle || c.OriginalPodUID != p.minio.Grant.Provider.Pod.UID || c.KeeperContainerName != "attachment" || c.KeeperMountPath != "/source" {
		return fail()
	}
	pin, err := p.physical.NativePlan(p.ctx)
	if err != nil {
		return fail()
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var plan struct {
		Profile     string                                       `json:"profile"`
		Root        string                                       `json:"root"`
		Endpoint    string                                       `json:"cri_endpoint"`
		CRIFile     string                                       `json:"crictl_file"`
		CRISHA      string                                       `json:"crictl_sha256"`
		ContainerID string                                       `json:"container_id"`
		PodUID      string                                       `json:"pod_uid"`
		CSI         struct{ Driver, Handle, Destination string } `json:"csi"`
	}
	if err != nil || json.Unmarshal(raw, &plan) != nil || plan.Profile != "original-minio-longhorn-csi-native-raw-cut.v1" || plan.CSI.Handle != handle || plan.CSI.Driver != "driver.longhorn.io" || plan.CSI.Destination != "/data" || plan.PodUID != c.OriginalPodUID || plan.ContainerID != c.OriginalContainerID || !strings.HasPrefix(plan.Endpoint, "unix:///") || strings.ContainsAny(plan.Endpoint, "\x00\r\n") || plan.CRISHA != "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3" || originalReaderExecutable(plan.CRIFile, plan.CRISHA) != nil || originalReaderExecutable(p.definition.NativePythonFile, p.definition.NativePythonSHA256) != nil || originalReaderExecutable(p.definition.NativeScriptFile, p.definition.NativeScriptSHA256) != nil {
		return fail()
	}
	var out originalHistoryLimitedOutput
	cmd := exec.CommandContext(p.ctx, p.definition.NativePythonFile, "-I", "-B", p.definition.NativeScriptFile, "observe-csi", "--cri-endpoint", plan.Endpoint, "--crictl-file", plan.CRIFile, "--crictl-sha256", plan.CRISHA, "--container-id", c.KeeperContainerID, "--pod-uid", c.KeeperPodUID, "--container-name", c.KeeperContainerName, "--destination", c.KeeperMountPath, "--csi-handle", handle)
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
			Driver, Handle, Destination string
			DevicePath                  string `json:"device_path"`
			MajorMinor                  string `json:"major_minor"`
		} `json:"csi"`
	}
	if json.Unmarshal(out.Bytes(), &observed) != nil || observed.Root != plan.Root || !filepath.IsAbs(observed.Root) || filepath.Clean(observed.Root) != observed.Root || observed.Root == "/" || observed.PodUID != c.KeeperPodUID || observed.ContainerID != c.KeeperContainerID || observed.ContainerName != c.KeeperContainerName || observed.Node.BootID != boot || observed.Node.MachineID != machine || observed.CSI.Driver != "driver.longhorn.io" || observed.CSI.Handle != handle || observed.CSI.Destination != "/source" || observed.CSI.DevicePath != "/dev/longhorn/"+handle || !regexp.MustCompile(`^[0-9]+:[0-9]+$`).MatchString(observed.CSI.MajorMinor) {
		return fail()
	}
	// Pin native device, mount, keeper runtime and node bytes for this provider.
	identity := hash(out.Bytes())
	if p.physicalObservationSHA != "" && p.physicalObservationSHA != identity {
		return fail()
	}
	if p.physical.Check(p.ctx) != nil || originalReaderExecutable(plan.CRIFile, plan.CRISHA) != nil || originalReaderExecutable(p.definition.NativeScriptFile, p.definition.NativeScriptSHA256) != nil {
		return fail()
	}
	if p.physicalObservationSHA == "" {
		p.physicalObservationSHA = identity
	}
	return observed.Root, boot, machine, nil
}
