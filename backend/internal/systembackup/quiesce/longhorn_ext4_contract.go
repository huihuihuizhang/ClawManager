package quiesce

import (
	"encoding/hex"
	"time"
)

const LonghornExt4Route = "/shared-runtime-lifecycle/longhorn-ext4/v3"
const LonghornExt4Protocol = "longhorn-ext4-native-hold.v3"

// Both installer and controller call this with the signed source's JSON
// digest and actual provider-namespace/Node UIDs. No task or guessed path.
func LonghornExt4SourceIdentity(originalSourceSHA256, providerNamespaceUID, nodeUID string) (string, error) {
	if !validObservationHash(originalSourceSHA256) || providerNamespaceUID == "" || nodeUID == "" {
		return "", ErrNodeObservation
	}
	return observationDigest([]string{"longhorn-ext4-install-grant.v3", originalSourceSHA256, providerNamespaceUID, nodeUID}), nil
}

// Frozen at the native Hold entry from the real controller claim/SQL lease.
// EntryRowVersion stays fixed across ordinary controller heartbeats. A new
// claim acquisition, including by the same owner string, gets a new entry.
type LonghornExt4Claim struct {
	TaskPublicID, Owner, MaintenanceOwner string
	EntryRowVersion                       uint64
	LeaseObservedAt, LeaseExpiresAt       time.Time
	// Original installation maintenance has no backup task. These fields are
	// correlation data from its actual acquiring SQL gate, not permission.
	// Omitting them preserves existing task journal digests byte for byte.
	OriginalOperationID   string `json:",omitempty"`
	OriginalReservationID string `json:",omitempty"`
}

func (c LonghornExt4Claim) valid() bool {
	identity := c.TaskPublicID != "" && c.OriginalOperationID == "" && c.OriginalReservationID == ""
	if c.TaskPublicID == "" {
		identity = longhornOriginalToken(c.OriginalOperationID) && longhornOriginalToken(c.OriginalReservationID) &&
			c.Owner == "adoption:"+c.OriginalOperationID && c.MaintenanceOwner == c.Owner
	}
	return identity && c.Owner != "" && c.MaintenanceOwner != "" &&
		c.EntryRowVersion > 0 && !c.LeaseObservedAt.IsZero() &&
		c.LeaseExpiresAt.After(c.LeaseObservedAt) &&
		c.LeaseExpiresAt.Sub(c.LeaseObservedAt) <= 300*time.Second
}

func longhornOriginalToken(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == s
}

// The original-operation branch cannot borrow a task's binding or another
// installation reservation. Authentication and a live SQL gate check remain
// the caller's responsibility; the Node checks its installed source and mTLS.
func (c LonghornExt4Claim) matchesBinding(b ObservationBinding) bool {
	if !c.valid() {
		return false
	}
	if c.OriginalOperationID == "" {
		return true // Existing task correlation is unchanged.
	}
	return b.Kind == LonghornExt4Protocol && b.OperationID == c.OriginalOperationID &&
		b.ReservationID == c.OriginalReservationID && b.InstallationID != "" &&
		b.Namespace != "" && b.NamespaceUID != "" && b.Node != "" && b.NodeUID != "" &&
		b.Generation > 0 && validObservationHash(b.InventorySHA256) &&
		b.ExpiresAt.After(c.LeaseObservedAt)
}

func (c LonghornExt4Claim) keeperBinding(b ObservationBinding) bool {
	if !c.matchesBinding(b) {
		return false
	}
	if c.OriginalOperationID != "" {
		return true // Original acquisition epochs may be zero.
	}
	return c.TaskPublicID == b.OperationID && validObservationHash(b.ReservationID) && b.FenceEpoch != 0
}

func longhornExt4ForwardUntil(binding ObservationBinding, claim LonghornExt4Claim) time.Time {
	if claim.LeaseExpiresAt.Before(binding.ExpiresAt) {
		return claim.LeaseExpiresAt
	}
	return binding.ExpiresAt
}

type LonghornExt4Request struct {
	Version, Action, Nonce, SourceIdentity string
	Binding                                ObservationBinding
	Attempt                                uint64
	Claim                                  LonghornExt4Claim
	Deadline                               time.Time
	// Correlation with the controller's original gate/drain records.
	// The concrete controller verifies this boundary before acquire.
	DrainBoundarySHA256                            string
	RecoveryBoundarySHA256                         string
	RegistrationBoundarySHA256                     string
	ClientPodUID, ClientPodName, ClientContainerID string
	Keeper                                         *LonghornExt4Keeper `json:",omitempty"`
	// Original cold clients must really exit, even if CRI still reports their
	// process as live after Kubernetes removed the Pod. Fixed at registration.
	ClientMustExit bool `json:",omitempty"`
}

// The controller obtains the keeper identity from its original resource
// journal. The Node independently resolves the CRI process and mount.
type LonghornExt4Keeper struct {
	OriginalPodUID string
	PodName        string
	PodUID         string
	ContainerID    string
}

type LonghornExt4Response struct {
	Version, Action, Nonce, RequestSHA256, SourceIdentity    string
	Binding                                                  ObservationBinding
	Attempt, Sequence                                        uint64
	Claim                                                    LonghornExt4Claim
	Phase, NativeState                                       string
	ProviderObservedAt, HeldObservedAt, StartedAt, ExpiresAt time.Time
	JournalSHA256                                            string
	ClientPodUID, ClientContainerID                          string
}

// Long-lived, SHA-pinned installation coordinates. Task/claim fields stay
// zero until authenticated runtime registration. No descriptor numbers.
type LonghornExt4SourceCoordinates struct {
	// Volume CR namespace, distinct from mounted provider/keeper Pod namespace.
	LonghornNamespace string
	// ProviderNamespaceUID retains its wire meaning: Longhorn namespace UID.
	Binding                                                                 ObservationBinding
	Attempt                                                                 uint64
	Claim                                                                   LonghornExt4Claim
	Identity, VolumeHandle, PVCName, PVCUID, PVUID                          string
	OriginalSourceSHA256, ProviderNamespaceUID                              string
	ProviderNamespace, ProviderPodName, ProviderPodUID, ProviderContainerID string
	MountPoint                                                              string
}

type LonghornRWXClientCoordinates struct {
	Binding                                        ObservationBinding
	Attempt                                        uint64
	Claim                                          LonghornExt4Claim
	Identity, VolumeHandle, PVCName, PVCUID, PVUID string
	OriginalSourceSHA256, ProviderNamespaceUID     string
	PodNamespace, PodName, PodUID, ContainerID     string
	MountPoint, NFSSource, Endpoint                string
}

type LonghornExt4Materials struct {
	Version, RecoveryURI string
	Sources              []LonghornExt4SourceCoordinates
	Clients              []LonghornRWXClientCoordinates
}
