package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strconv"
	"strings"
)

const OriginalStoppedSourceBaselineVersion = "original-stopped-pro-current-baseline.v1"

// Correlation DATA shared by the original Installer and the native node
// observer. A caller can construct this struct; it is never an authority,
// positive absence observation, held capability or historical Pod template.
// D derives it from current original authenticated SQL/Kubernetes I/O. B binds
// actual machine/boot/path dev+inode+mount and absence facts in its opaque result.
type OriginalStoppedSourceBaseline struct {
	SourceKey                                   string
	ControllerGeneration                        int64
	Version                                     string
	InstallationID, Namespace, NamespaceUID     string
	Source                                      SourceInstance
	SQLProjectionSHA256, KubernetesCensusSHA256 string
	// ControllerKind is exactly "absent" or "Deployment". An extant Deployment
	// must also have its actual UID/spec SHA and original replicas zero checked.
	ControllerKind, ControllerName, ControllerUID, ControllerSpecSHA256 string
	Volumes                                                             []OriginalStoppedSourceVolume
}

type OriginalStoppedSourceVolume struct {
	MachineID, BootID string
	ID, SourcePath    string
	// local_pv: bind actual claim UID, PV claimRef UID, both specs and affinity.
	// host_path: the original installation owner's independent mapping pin must
	// select the unique actual data node. A directory found on another node is
	// never a replacement for that mapping.
	Kind                                                         string
	PVCName, PVCUID, PVCSpecSHA256                               string
	PVName, PVUID, PVSpecSHA256, ClaimRefUID, NodeAffinitySHA256 string
	OwnerNodeMappingSHA256                                       string
	Node, NodeUID                                                string
}

func OriginalStoppedSourceBaselineSHA256(b OriginalStoppedSourceBaseline) (string, error) {
	hashOK := func(v string) bool {
		raw, err := hex.DecodeString(v)
		return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == v
	}
	if b.Version != OriginalStoppedSourceBaselineVersion || b.SourceKey != "stopped/"+strconv.Itoa(b.Source.ID) || b.InstallationID == "" || b.Namespace == "" || b.NamespaceUID == "" || b.Source.ID <= 0 || b.Source.UserID <= 0 || b.Source.Generation <= 0 || b.Source.Status != "stopped" || b.Source.Namespace != "" && b.Source.Namespace != b.Namespace || !hashOK(b.SQLProjectionSHA256) || !hashOK(b.KubernetesCensusSHA256) || len(b.Volumes) == 0 || len(b.Volumes) > 128 {
		return "", ErrSchema
	}
	switch b.ControllerKind {
	case "absent":
		if b.ControllerName != "" || b.ControllerUID != "" || b.ControllerSpecSHA256 != "" || b.ControllerGeneration != 0 {
			return "", ErrSchema
		}
	case "Deployment":
		if b.ControllerName == "" || b.ControllerUID == "" || b.ControllerGeneration <= 0 || !hashOK(b.ControllerSpecSHA256) {
			return "", ErrSchema
		}
	default:
		return "", ErrSchema
	}
	seen := map[string]bool{}
	for _, v := range b.Volumes {
		if v.ID == "" || seen[v.ID] || v.SourcePath == "/" || !path.IsAbs(v.SourcePath) || path.Clean(v.SourcePath) != v.SourcePath || strings.ContainsAny(v.SourcePath, "\\\x00\r\n") || v.Node == "" || v.NodeUID == "" || v.MachineID == "" || v.BootID == "" || v.Node != b.Volumes[0].Node || v.NodeUID != b.Volumes[0].NodeUID || v.MachineID != b.Volumes[0].MachineID || v.BootID != b.Volumes[0].BootID {
			return "", ErrSchema
		}
		seen[v.ID] = true
		switch v.Kind {
		case "local_pv":
			if v.PVCName == "" || v.PVCUID == "" || v.PVName == "" || v.PVUID == "" || v.ClaimRefUID != v.PVCUID || !hashOK(v.PVCSpecSHA256) || !hashOK(v.PVSpecSHA256) || !hashOK(v.NodeAffinitySHA256) || v.OwnerNodeMappingSHA256 != "" {
				return "", ErrSchema
			}
		case "host_path":
			if !hashOK(v.OwnerNodeMappingSHA256) || v.PVCName != "" || v.PVCUID != "" || v.PVName != "" || v.PVUID != "" || v.ClaimRefUID != "" || v.PVCSpecSHA256 != "" || v.PVSpecSHA256 != "" || v.NodeAffinitySHA256 != "" {
				return "", ErrSchema
			}
		default:
			return "", ErrSchema
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", ErrSchema
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
