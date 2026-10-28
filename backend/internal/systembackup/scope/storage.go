package scope

import (
	"net"
	"path"
	"strings"
)

// Storage identifies a discovered, allowlisted persistent mount. Paths are
// Linux data-plane paths even when the planner runs on Windows. Runtime paths,
// mount ownership and writer completeness still need live verification.
type Storage struct {
	Kind                  string `json:"kind"`
	Namespace             string `json:"namespace,omitempty"`
	ClaimName             string `json:"claim_name,omitempty"`
	ClaimUID              string `json:"claim_uid,omitempty"`
	NodeName              string `json:"node_name,omitempty"`
	HostPath              string `json:"host_path,omitempty"`
	NFSServer             string `json:"nfs_server,omitempty"`
	NFSExport             string `json:"nfs_export,omitempty"`
	SubPath               string `json:"sub_path"`
	Shared                bool   `json:"shared"`
	CSIDriver             string `json:"csi_driver,omitempty"`
	SnapshotClass         string `json:"snapshot_class,omitempty"`
	SnapshotProbePassed   bool   `json:"snapshot_probe_passed"`
	AdditionalMountsKnown bool   `json:"additional_mounts_known"`
}

type CapturePlan struct {
	Method         string   `json:"method"`
	SubPath        string   `json:"sub_path"`
	PinToNode      string   `json:"pin_to_node,omitempty"`
	ReleaseGateAt  string   `json:"release_gate_at"`
	RequiredProofs []string `json:"required_proofs"`
}

func PlanStorage(storage Storage, mode string) (CapturePlan, error) {
	if (mode != "lite" && mode != "pro") || !storage.AdditionalMountsKnown {
		// A PVC alone is not proof that all persistent agent data is on it.
		return CapturePlan{}, ErrStorageUnresolved
	}
	subPath := storage.SubPath
	if subPath == "" {
		subPath = "."
	}
	if !safeRelativePath(subPath) || ((storage.Shared || mode == "lite") && subPath == ".") {
		return CapturePlan{}, ErrStorageUnresolved
	}
	plan := CapturePlan{
		Method: "quiesced_encrypted_copy", SubPath: subPath, ReleaseGateAt: "encrypted_staging_sealed",
		RequiredProofs: []string{"writer_inventory_complete", "all_writers_quiesced", "fencing_generation", "source_mount_identity", "encrypted_staging_sealed", "within_absolute_hold_deadline"},
	}
	switch storage.Kind {
	case "pvc":
		if storage.Namespace == "" || storage.ClaimName == "" || storage.ClaimUID == "" || storage.HostPath != "" || storage.NFSServer != "" || storage.NFSExport != "" {
			return CapturePlan{}, ErrStorageUnresolved
		}
		if storage.SnapshotProbePassed {
			if storage.CSIDriver == "" || storage.SnapshotClass == "" {
				return CapturePlan{}, ErrStorageUnresolved
			}
			plan.Method = "csi_snapshot_then_encrypted_export"
			plan.ReleaseGateAt = "all_required_checkpoints_verified"
			plan.RequiredProofs = []string{"writer_inventory_complete", "all_writers_quiesced", "fencing_generation", "source_mount_identity", "snapshot_ready_and_bound", "readonly_snapshot_mount", "all_required_checkpoints_verified"}
		} else {
			// RWO and local PVCs can require same-node mounting. Carry discovery
			// placement through instead of treating every PVC as portable CSI.
			plan.PinToNode = storage.NodeName
		}
	case "hostpath":
		if storage.NodeName == "" || !safeAbsoluteRoot(storage.HostPath) || storage.Namespace != "" || storage.ClaimName != "" || storage.ClaimUID != "" || storage.NFSServer != "" || storage.NFSExport != "" || hasSnapshotConfiguration(storage) {
			return CapturePlan{}, ErrStorageUnresolved
		}
		plan.PinToNode = storage.NodeName
	case "nfs":
		if !safeNFSServer(storage.NFSServer) || !safeAbsoluteRoot(storage.NFSExport) || storage.HostPath != "" || hasSnapshotConfiguration(storage) {
			return CapturePlan{}, ErrStorageUnresolved
		}
		// NFS can be mounted through an existing PVC or a discovered NFS mount.
		if (storage.ClaimName != "" || storage.ClaimUID != "" || storage.Namespace != "") && (storage.ClaimName == "" || storage.ClaimUID == "" || storage.Namespace == "") {
			return CapturePlan{}, ErrStorageUnresolved
		}
		plan.RequiredProofs = append(plan.RequiredProofs, "all_external_nfs_writers_quiesced")
	default:
		return CapturePlan{}, ErrStorageUnresolved
	}
	return plan, nil
}

func hasSnapshotConfiguration(storage Storage) bool {
	return storage.CSIDriver != "" || storage.SnapshotClass != "" || storage.SnapshotProbePassed
}

func safeRelativePath(value string) bool {
	if value == "" || path.IsAbs(value) || strings.ContainsAny(value, "\\\x00\r\n:") || path.Clean(value) != value {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return false
		}
	}
	return true
}

func safeAbsoluteRoot(value string) bool {
	return value != "/" && path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\\\x00\r\n:")
}

func safeNFSServer(value string) bool {
	// This is a locator, not a URL or credential-bearing connection string.
	// Endpoint authorization, DNS rebinding and CIDR checks belong to discovery.
	if net.ParseIP(value) != nil {
		return true
	}
	if value == "" || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
