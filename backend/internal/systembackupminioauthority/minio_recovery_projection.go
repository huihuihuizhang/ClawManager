package systembackupminioauthority

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const MinIORecoveryProjectionVersion = "original-minio-whole-cold-resource-succession.v1"
const MinIORecoveryProjectionDomain = MinIORecoveryProjectionVersion + "\x00"
const MinIORecoveryDescriptorVersion = "original-minio-whole-cold-resource-locator.v1"

// Independently installed BEFORE cold capture. ProjectionFile may not exist
// yet. This descriptor is outside the signed SQL grant/definition hash graph.
// Its own deployment File/SHA must never be learned from a request/projection.
type MinIORecoveryDescriptor struct {
	Version                string
	ProjectionFile         string
	Pin                    SQLTrustPin
	Actor                  Actor
	DefinitionSHA256       Digest
	PermissionSourceFile   string
	PermissionSourceSHA256 Digest
	PermissionProfile      string
}

type MinIORecoveryMaterial struct {
	Kind, Name, UID, ResourceVersion string
	ContentSHA256                    Digest
}
type MinIORecoveryStorage struct {
	Kind, Name, UID string
	SpecSHA256      Digest
}

// Stable original/current native resource comparison data. Pod UID/name and
// runtime CID are deliberately separate. No credential body is serialized.
type MinIORecoveryResources struct {
	Version                                                                                                            string
	NamespaceUID                                                                                                       string
	Deployment, ReplicaSet, Service, ServiceAccount                                                                    ObjectIdentity
	Node, NodeUID                                                                                                      string
	DeploymentSpecSHA256, ReplicaSetSpecSHA256, ServiceSpecSHA256, ServiceAccountSHA256, PodSpecSHA256, NodeSpecSHA256 Digest
	Materials                                                                                                          []MinIORecoveryMaterial
	Storage                                                                                                            []MinIORecoveryStorage
}

// Only D's sealed actual whole-cold recovery source can deliver this to the
// Installer signing bridge. These exported fields alone confer NO authority.
type MinIORecoveryTransition struct {
	OperationID, ReservationID                                                       string
	InventorySHA256, NativeRequestSHA256, NativeResponseSHA256, OriginalNativeSHA256 Digest
	ColdTreeSHA256, ArchiveReadbackSHA256, FormatSHA256                              Digest
	OriginalContainerID                                                              string
	NewPod                                                                           ObjectIdentity
	NewContainerID                                                                   string
	OriginalResources                                                                MinIORecoveryResources
	RecoveredAt, OriginalProofUntil                                                  time.Time
}

type MinIORecoveryProjection struct {
	Version                                                         string
	Target                                                          Target
	Enrollment                                                      Enrollment
	AuthorityID, GrantID                                            string
	DefinitionSHA256, PermissionSourceSHA256, PermissionGrantSHA256 Digest
	OriginalSQL                                                     SQLExpected
	OriginalProvider                                                Provider
	Transition                                                      MinIORecoveryTransition
	NotBefore, Until, SignedAt                                      time.Time
}
type SignedMinIORecoveryProjection struct{ Record, Signature []byte }

type VerifiedMinIORecoveryProjection struct {
	origin *VerifiedMinIORecoveryProjection
	record MinIORecoveryProjection
	sha    Digest
}

func (*VerifiedMinIORecoveryProjection) MarshalJSON() ([]byte, error) { return nil, ErrRecord }

// Encoding comparison/deployment data never grants SQL or native authority.
func EncodeMinIORecoveryDescriptor(d MinIORecoveryDescriptor) ([]byte, error) {
	if !validRecoveryDescriptor(d) {
		return nil, ErrRecord
	}
	raw, e := canonical(d)
	if e != nil || len(raw) > 65536 {
		return nil, ErrRecord
	}
	return raw, nil
}

func DecodeMinIORecoveryDescriptor(raw []byte) (MinIORecoveryDescriptor, error) {
	var d MinIORecoveryDescriptor
	if decodeRecoveryCanonical(raw, &d, 65536) != nil || !validRecoveryDescriptor(d) {
		return MinIORecoveryDescriptor{}, ErrRecord
	}
	return d, nil
}

func validRecoveryDescriptor(d MinIORecoveryDescriptor) bool {
	if d.Version != MinIORecoveryDescriptorVersion || !validPin(d.Pin) || d.Actor.LocalAdminUserID < 1 || !text(d.Actor.LocalAdminUsername) || !text(d.Actor.InstallerDatabaseAccount) || d.Actor.InstallerDatabaseAccount == d.Pin.Target.ConsumerDatabaseAccount || !validDigest(d.DefinitionSHA256) || !validDigest(d.PermissionSourceSHA256) || !recoveryAbsolute(d.ProjectionFile) || !recoveryAbsolute(d.PermissionSourceFile) || d.ProjectionFile == d.PermissionSourceFile {
		return false
	}
	_, ok := NativeProfile(d.PermissionProfile)
	return ok
}

func recoveryAbsolute(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && s != string(filepath.Separator) && !strings.ContainsAny(s, "\x00\r\n")
}
func recoveryCID(s string) bool {
	return strings.HasPrefix(s, "containerd://") && len(s) > len("containerd://") && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n ")
}

func ValidateMinIORecoveryTransition(t MinIORecoveryTransition) error {
	if !text(t.OperationID) || !text(t.ReservationID) || !text(t.NewPod.Name) || !text(t.NewPod.UID) || !recoveryCID(t.OriginalContainerID) || !recoveryCID(t.NewContainerID) || t.OriginalContainerID == t.NewContainerID || !validTime(t.RecoveredAt) || !validTime(t.OriginalProofUntil) || !t.RecoveredAt.Before(t.OriginalProofUntil) {
		return ErrRecord
	}
	for _, h := range []Digest{t.InventorySHA256, t.NativeRequestSHA256, t.NativeResponseSHA256, t.OriginalNativeSHA256, t.ColdTreeSHA256, t.ArchiveReadbackSHA256, t.FormatSHA256} {
		if !validDigest(h) {
			return ErrRecord
		}
	}
	return validateRecoveryResources(t.OriginalResources)
}

func validateRecoveryResources(r MinIORecoveryResources) error {
	if r.Version != "original-minio-resource-comparison.v1" || !text(r.NamespaceUID) || !text(r.Node) || !text(r.NodeUID) || r.Materials == nil || r.Storage == nil {
		return ErrRecord
	}
	for _, o := range []ObjectIdentity{r.Deployment, r.ReplicaSet, r.Service, r.ServiceAccount} {
		if !text(o.Name) || !text(o.UID) {
			return ErrRecord
		}
	}
	for _, h := range []Digest{r.DeploymentSpecSHA256, r.ReplicaSetSpecSHA256, r.ServiceSpecSHA256, r.ServiceAccountSHA256, r.PodSpecSHA256, r.NodeSpecSHA256} {
		if !validDigest(h) {
			return ErrRecord
		}
	}
	last := ""
	for _, m := range r.Materials {
		key := m.Kind + "/" + m.Name
		if (m.Kind != "Secret" && m.Kind != "ConfigMap") || !text(m.Name) || !text(m.UID) || !text(m.ResourceVersion) || !validDigest(m.ContentSHA256) || key <= last {
			return ErrRecord
		}
		last = key
	}
	last = ""
	for _, v := range r.Storage {
		key := v.Kind + "/" + v.Name
		if (v.Kind != "PersistentVolumeClaim" && v.Kind != "PersistentVolume") || !text(v.Name) || !text(v.UID) || !validDigest(v.SpecSHA256) || key <= last {
			return ErrRecord
		}
		last = key
	}
	return nil
}

// Verify uses a REAL current SQL snapshot, not caller CAS/Passed data. History
// proof may now be old; it was required live at SignedAt. Until remains the
// original grant/head bound. This never grants native health or key use.
func VerifyMinIORecoveryProjection(raw []byte, d MinIORecoveryDescriptor, current *SQLCurrentSnapshot, now time.Time) (*VerifiedMinIORecoveryProjection, error) {
	var envelope SignedMinIORecoveryProjection
	if !validRecoveryDescriptor(d) || decodeRecoveryCanonical(raw, &envelope, 65536) != nil || len(envelope.Record) == 0 || len(envelope.Record) > 32768 || !ed25519.Verify(d.Pin.IssuerPublic, append([]byte(MinIORecoveryProjectionDomain), envelope.Record...), envelope.Signature) {
		return nil, ErrRecord
	}
	var r MinIORecoveryProjection
	if decodeRecoveryCanonical(envelope.Record, &r, 32768) != nil || ValidateMinIORecoveryTransition(r.Transition) != nil || current == nil || current.RequireCurrent(now) != nil {
		return nil, ErrRecord
	}
	g, h, _, e := current.Declarations()
	expected, _, ce := current.Comparison()
	if g.Actor != d.Actor || r.PermissionGrantSHA256 != g.PermissionSource.GrantSHA256 || d.PermissionProfile != g.PermissionSource.Profile {
		return nil, ErrRecord
	}
	end := g.Until
	if h.Until.Before(end) {
		end = h.Until
	}
	if e != nil || ce != nil || r.Version != MinIORecoveryProjectionVersion || r.Target != d.Pin.Target || r.Target != g.Target || r.Enrollment != d.Pin.Enrollment || r.Enrollment != g.Enrollment || r.AuthorityID != g.AuthorityID || r.GrantID != g.GrantID || r.DefinitionSHA256 != d.DefinitionSHA256 || r.DefinitionSHA256 != g.Observation.DefinitionSHA256 || r.PermissionSourceSHA256 != d.PermissionSourceSHA256 || !reflect.DeepEqual(r.OriginalSQL, expected) || !reflect.DeepEqual(r.OriginalProvider, g.Provider) || !r.NotBefore.Equal(g.NotBefore) || !r.Until.Equal(end) || !validTime(r.SignedAt) || r.SignedAt.Before(r.NotBefore) || !r.SignedAt.Before(r.Until) || r.Transition.RecoveredAt.After(r.SignedAt) || !r.SignedAt.Before(r.Transition.OriginalProofUntil) || r.SignedAt.After(now) || !now.Before(r.Until) || r.Transition.NewPod.UID == g.Provider.Pod.UID {
		return nil, ErrRecord
	}
	resources := r.Transition.OriginalResources
	if resources.NamespaceUID != g.Target.NamespaceUID || resources.Deployment != g.Provider.Deployment || resources.ReplicaSet != g.Provider.ReplicaSet || resources.Service != g.Provider.Service || resources.ServiceAccount != g.Provider.ServiceAccount || resources.Node != g.Provider.Node || resources.NodeUID != g.Provider.NodeUID {
		return nil, ErrRecord
	}
	v := &VerifiedMinIORecoveryProjection{record: r, sha: digest(raw)}
	v.origin = v
	return v, nil
}

func (v *VerifiedMinIORecoveryProjection) Record() (MinIORecoveryProjection, error) {
	var out MinIORecoveryProjection
	if v == nil || v.origin != v {
		return out, ErrRecord
	}
	raw, e := json.Marshal(v.record)
	if e != nil || json.Unmarshal(raw, &out) != nil {
		return MinIORecoveryProjection{}, ErrRecord
	}
	return out, nil
}
func (v *VerifiedMinIORecoveryProjection) SHA256() (Digest, error) {
	if v == nil || v.origin != v {
		return "", ErrRecord
	}
	return v.sha, nil
}

// Same record bytes only; independent SQL/current-window checks belong to
// VerifyMinIORecoveryProjection on each prepare/final original read.
func (v *VerifiedMinIORecoveryProjection) Matches(raw []byte) bool {
	return v != nil && v.origin == v && v.sha == digest(raw)
}
func decodeRecoveryCanonical(raw []byte, out any, maximum int) error {
	return decode(raw, maximum, out)
}
