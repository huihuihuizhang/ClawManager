package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

const InventoryVersion = "users-instances-inventory.v1alpha1"

var ErrInvalidInventory = errors.New("user/instance inventory is incomplete or inconsistent")

type User struct {
	ID              int    `json:"id"`
	Role            string `json:"role"`
	AuthProvider    string `json:"auth_provider"`
	HasPasswordHash bool   `json:"has_password_hash"`
}

type Mount struct {
	ContainerPath string  `json:"container_path"`
	Storage       Storage `json:"storage"`
}

type Instance struct {
	ID      int     `json:"id"`
	UserID  int     `json:"user_id"`
	Runtime Runtime `json:"runtime"`
	Mounts  []Mount `json:"mounts"`
}

type Input struct {
	Orchestrator   string     `json:"orchestrator"`
	Profile        string     `json:"profile"`
	TotalUsers     int        `json:"total_users"`
	TotalInstances int        `json:"total_instances"`
	Users          []User     `json:"users"`
	Instances      []Instance `json:"instances"`
}

type MountPlan struct {
	ContainerPath string      `json:"container_path"`
	Storage       Storage     `json:"storage"`
	Capture       CapturePlan `json:"capture"`
}

type InstancePlan struct {
	ID      int         `json:"id"`
	UserID  int         `json:"user_id"`
	Runtime RuntimePlan `json:"runtime"`
	Mounts  []MountPlan `json:"mounts"`
}

// Inventory contains no account/configuration payload and does not assert
// backup success, strong consistency, restore capability or acceptance.
type Inventory struct {
	Version                    string         `json:"version"`
	Orchestrator               string         `json:"orchestrator"`
	Profile                    string         `json:"profile"`
	UserIDs                    []int          `json:"user_ids"`
	SourceAdminIDs             []int          `json:"source_admin_ids"`
	Instances                  []InstancePlan `json:"instances"`
	Tables                     []TableRule    `json:"tables"`
	Dependencies               []Dependency   `json:"dependencies"`
	CredentialRequirements     []string       `json:"credential_requirements"`
	SourceResumePolicy         string         `json:"source_resume_policy"`
	TargetPowerState           string         `json:"target_power_state"`
	LegacyNFSContractExtension bool           `json:"legacy_nfs_contract_extension"`
}

// BuildInventory is all-or-nothing. One unsupported instance or unresolved
// mount prevents a partial set from being presented as a full migration plan.
func BuildInventory(input Input) (*Inventory, error) {
	if input.Orchestrator != "kubernetes" || (input.Profile != "cluster" && input.Profile != "single-node" && input.Profile != "legacy-nfs") {
		return nil, fmt.Errorf("%w: unsupported deployment", ErrInvalidInventory)
	}
	if input.TotalUsers != len(input.Users) || input.TotalInstances != len(input.Instances) || len(input.Users) == 0 {
		return nil, fmt.Errorf("%w: source counts do not match the complete inventory", ErrInvalidInventory)
	}
	inventory := &Inventory{
		Version: InventoryVersion, Orchestrator: input.Orchestrator, Profile: input.Profile,
		UserIDs: []int{}, SourceAdminIDs: []int{}, Instances: []InstancePlan{},
		Tables: TableRegistry(), Dependencies: CrossDomainDependencies(),
		CredentialRequirements: []string{"encrypted_password_hash_payload", "enterprise_auth_decryption_and_rewrap", "model_and_channel_secret_bundle", "external_secret_reference_inventory", "source_independent_backup_decryption"},
		SourceResumePolicy:     "restore_pre_capture_state", TargetPowerState: "stopped",
		LegacyNFSContractExtension: input.Profile == "legacy-nfs",
	}
	if err := ValidateRegistry(inventory.Tables, inventory.Dependencies); err != nil {
		return nil, err
	}
	users := make(map[int]bool, len(input.Users))
	for _, user := range input.Users {
		if user.ID <= 0 || users[user.ID] || (user.Role != "admin" && user.Role != "user") {
			return nil, fmt.Errorf("%w: duplicate or invalid user identity", ErrInvalidInventory)
		}
		provider := strings.ToLower(strings.TrimSpace(user.AuthProvider))
		if provider == "" {
			provider = "local"
		}
		if provider != "local" && provider != "ldap" {
			return nil, fmt.Errorf("%w: unsupported user authentication provider", ErrInvalidInventory)
		}
		if provider == "local" && !user.HasPasswordHash {
			return nil, fmt.Errorf("%w: local user %d has no password hash to preserve", ErrInvalidInventory, user.ID)
		}
		users[user.ID] = true
		inventory.UserIDs = append(inventory.UserIDs, user.ID)
		if user.Role == "admin" {
			inventory.SourceAdminIDs = append(inventory.SourceAdminIDs, user.ID)
		}
	}
	if len(inventory.SourceAdminIDs) == 0 {
		return nil, fmt.Errorf("%w: no source administrator", ErrInvalidInventory)
	}
	instances := make(map[int]bool, len(input.Instances))
	claimedMounts := make(map[string][]mountClaim)
	for _, instance := range input.Instances {
		if instance.ID <= 0 || instances[instance.ID] || !users[instance.UserID] {
			return nil, fmt.Errorf("%w: duplicate instance or missing user relationship", ErrInvalidInventory)
		}
		instances[instance.ID] = true
		runtime, err := PlanRuntime(instance.Runtime)
		if err != nil {
			return nil, fmt.Errorf("instance %d: %w", instance.ID, err)
		}
		if len(instance.Mounts) == 0 {
			return nil, fmt.Errorf("instance %d: %w", instance.ID, ErrStorageUnresolved)
		}
		planned := InstancePlan{ID: instance.ID, UserID: instance.UserID, Runtime: runtime, Mounts: []MountPlan{}}
		mountPaths := make(map[string]bool, len(instance.Mounts))
		for _, mount := range instance.Mounts {
			if !safeAbsoluteRoot(mount.ContainerPath) || mountPaths[mount.ContainerPath] {
				return nil, fmt.Errorf("instance %d: %w", instance.ID, ErrStorageUnresolved)
			}
			mountPaths[mount.ContainerPath] = true
			capture, err := PlanStorage(mount.Storage, runtime.Mode)
			if err != nil {
				return nil, fmt.Errorf("instance %d: %w", instance.ID, err)
			}
			storage := mount.Storage
			storage.SubPath = capture.SubPath
			identity, root := storageLocation(storage)
			claimedMounts[identity] = append(claimedMounts[identity], mountClaim{instance.ID, root})
			if input.Profile == "single-node" {
				// Single-node's shared contract requires sealing while the gate
				// is held, even when a CSI snapshot happens to be available.
				capture.ReleaseGateAt = "encrypted_staging_sealed"
				if !containsString(capture.RequiredProofs, "encrypted_staging_sealed") {
					capture.RequiredProofs = append(capture.RequiredProofs, "encrypted_staging_sealed", "within_absolute_hold_deadline")
				}
			}
			planned.Mounts = append(planned.Mounts, MountPlan{ContainerPath: mount.ContainerPath, Storage: storage, Capture: capture})
		}
		sort.Slice(planned.Mounts, func(i, j int) bool { return planned.Mounts[i].ContainerPath < planned.Mounts[j].ContainerPath })
		inventory.Instances = append(inventory.Instances, planned)
	}
	if err := validateStorageClaims(claimedMounts); err != nil {
		return nil, err
	}
	sort.Ints(inventory.UserIDs)
	sort.Ints(inventory.SourceAdminIDs)
	sort.Slice(inventory.Instances, func(i, j int) bool { return inventory.Instances[i].ID < inventory.Instances[j].ID })
	return inventory, nil
}

type mountClaim struct {
	instanceID int
	root       string
}

func storageLocation(storage Storage) (string, string) {
	switch storage.Kind {
	case "pvc":
		return "pvc:" + storage.ClaimUID, storage.SubPath
	case "hostpath":
		return "hostpath:" + storage.NodeName, path.Join(storage.HostPath, storage.SubPath)
	default:
		return "nfs:" + strings.ToLower(storage.NFSServer), path.Join(storage.NFSExport, storage.SubPath)
	}
}

func validateStorageClaims(groups map[string][]mountClaim) error {
	for _, claims := range groups {
		// Appending a separator keeps a directory and all its descendants
		// together, including names with '-' or '.' before the separator.
		sort.Slice(claims, func(i, j int) bool { return claims[i].root+"/" < claims[j].root+"/" })
		var ancestor *mountClaim
		for index := range claims {
			claim := &claims[index]
			if ancestor != nil && overlappingPaths(ancestor.root, claim.root) {
				if ancestor.instanceID != claim.instanceID {
					return fmt.Errorf("instances %d and %d: %w: overlapping persistent data", ancestor.instanceID, claim.instanceID, ErrStorageUnresolved)
				}
				continue
			}
			ancestor = claim
		}
	}
	return nil
}

func overlappingPaths(left, right string) bool {
	return left == "." || right == "." || left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}

func containsString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

// Fingerprint detects changes in this internal inventory. It deliberately does
// not claim to be the system-backup JCS config/manifest checksum or a signature.
func (inventory Inventory) Fingerprint() (string, error) {
	data, err := json.Marshal(inventory)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}
