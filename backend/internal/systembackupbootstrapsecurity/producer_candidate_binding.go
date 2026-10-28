package systembackupbootstrapsecurity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// CandidateConfigDigests describes existing validated ConfigValues bytes. It
// authenticates neither a deployment nor a producer admission. The original
// deployment authority must have explicitly selected this digest profile.
type CandidateConfigDigests struct {
	CandidateHash, RegistrySetHash, RefSetHash string
}

func ConfigCandidateHashes(c sec.BootstrapConfig) (CandidateConfigDigests, error) {
	raw := c.CanonicalJSON()
	verified, err := sec.DecodeBootstrapConfig(raw)
	if err != nil || len(raw) == 0 || !bytes.Equal(verified.CanonicalJSON(), raw) {
		return CandidateConfigDigests{}, sec.ErrRegistrationUnavailable
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields["registries"]) == 0 || len(fields["references"]) == 0 {
		return CandidateConfigDigests{}, sec.ErrRegistrationUnavailable
	}
	// RawMessage retains the exact canonical array spans: preserve the original
	// array order and do not add a newline, sort entries or re-encode strings.
	return CandidateConfigDigests{shaBytes(raw), shaBytes(fields["registries"]), shaBytes(fields["references"])}, nil
}

// CaptureCandidateRelationData is comparison DATA from the original mapping,
// not a signature, grant or authorization. Receipt may be an untrusted lookup
// result; ExpectedDigests/ResultVersion must come from the independent original
// association. A matching constructor result still confers no authority.
type CaptureCandidateRelationData struct {
	Grant            sec.OfflineBootstrapGrant
	Config           sec.BootstrapConfig
	Admission        pd.UnconfiguredAdmission
	Target           pd.Target
	Descriptor       []byte
	DescriptorSHA256 string
	MappingSHA256    string
	ExpectedDigests  pd.ResultDigests
	ResultVersion    pd.Counter
	Receipt          pd.ReceiptRecord
}

func (CaptureCandidateRelationData) String() string   { return "CaptureCandidateRelationData" }
func (CaptureCandidateRelationData) GoString() string { return "CaptureCandidateRelationData" }
func (CaptureCandidateRelationData) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

// CaptureCandidateRelation freezes a purpose/ref-to-candidate relationship.
// It deliberately implements neither BootstrapResourceValidator nor producer
// Policy/authority. The concrete trusted authority must authenticate the full
// original mapping and current state before D can consume any candidate.
type CaptureCandidateRelation struct {
	grant         sec.OfflineBootstrapGrant
	canonical     []byte
	reference     sec.BootstrapSecretRef
	descriptorSHA string
	mappingSHA    string
	receipt       pd.ReceiptRecord
}

func (CaptureCandidateRelation) String() string   { return "CaptureCandidateRelation" }
func (CaptureCandidateRelation) GoString() string { return "CaptureCandidateRelation" }
func (CaptureCandidateRelation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

func NewCaptureCandidateRelation(d CaptureCandidateRelationData) (*CaptureCandidateRelation, error) {
	deny := func() (*CaptureCandidateRelation, error) { return nil, sec.ErrRegistrationUnavailable }
	hashes, err := ConfigCandidateHashes(d.Config)
	if err != nil || d.Grant.ConfigSHA256 != hashes.CandidateHash || !refHash.MatchString(d.MappingSHA256) {
		return deny()
	}
	var pin sec.BootstrapSecretRef
	for _, ref := range d.Config.References() {
		if ref.Purpose == "capture_signing" {
			pin = ref
		}
	}
	ref, err := DecodeSecurityReference(d.Descriptor, d.DescriptorSHA256)
	if err != nil || pin.Purpose != "capture_signing" || ref.Kind() != "signing_key" || ref.Purpose() != "capture_certificate" || !ref.MatchesBootstrapPin(pin) {
		return deny()
	}
	receipt, err := copyCandidateReceipt(d.Receipt)
	if err != nil {
		return deny()
	}
	r := receipt.Request
	digests, err := pd.ResultHashes(r)
	if err != nil || digests != d.ExpectedDigests || receipt.ResultVersion != d.ResultVersion {
		return deny()
	}
	if r.Scope != (pd.Scope{ServerUUID: pd.ServerUUID(d.Grant.ServerUUID), Database: pd.Database(d.Grant.Database), Installation: pd.Installation(d.Grant.InstallationID)}) ||
		r.Admission.Unconfigured == nil || r.Admission.Configured != nil || *r.Admission.Unconfigured != d.Admission ||
		string(d.Admission.CandidateHash) != hashes.CandidateHash || string(d.Admission.RegistrySetHash) != hashes.RegistrySetHash || string(d.Admission.RefSetHash) != hashes.RefSetHash {
		return deny()
	}
	if !reflect.DeepEqual(r.Target, d.Target) || r.Target.Role != "signing" || r.Target.EvaluatorOwner != "A" ||
		len(r.Target.ResultSlots) != 1 || r.Target.ResultSlots[0] != "signing" || r.Purpose != "dependency_check" ||
		r.Results.Dependency == nil || r.Results.Provider != nil || len(r.Results.Dependency.Observations) != 1 {
		return deny()
	}
	o := r.Results.Dependency.Observations[0]
	if o.Slot != "signing" || o.Status != "healthy" || o.Reason != "none" ||
		receipt.CommittedAt < r.ObservedAt || receipt.CommittedAt >= r.ObservationExpiresAt || receipt.RetentionExpiresAt < r.ObservationExpiresAt {
		return deny()
	}
	// Do not equate the bootstrap reference identity with the producer target
	// identity, or infer policy/profile/domain/payload authority from a healthy
	// signing slot. Their complete original association is authenticated elsewhere.
	return &CaptureCandidateRelation{grant: d.Grant, canonical: d.Config.CanonicalJSON(), reference: pin,
		descriptorSHA: d.DescriptorSHA256, mappingSHA: d.MappingSHA256, receipt: receipt}, nil
}

// CheckReceipt compares data only. It performs no SQL, file/network work,
// renewal or current authorization, and cannot substitute for D's final guard.
func (r *CaptureCandidateRelation) CheckReceipt(g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, candidate pd.ReceiptRecord) error {
	if r == nil || len(r.canonical) == 0 || g != r.grant || !bytes.Equal(c.CanonicalJSON(), r.canonical) {
		return sec.ErrRegistrationUnavailable
	}
	copy, err := copyCandidateReceipt(candidate)
	if err != nil || !reflect.DeepEqual(copy, r.receipt) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

// Receipt returns owned lookup/comparison data, never a consumption credential.
func (r *CaptureCandidateRelation) Receipt() (pd.ReceiptRecord, error) {
	if r == nil || len(r.canonical) == 0 {
		return pd.ReceiptRecord{}, sec.ErrRegistrationUnavailable
	}
	return copyCandidateReceipt(r.receipt)
}

// Selection returns owned comparison data for D's constructor-fixed authority
// to authenticate. It is not a prepared consumption or execution capability.
func (r *CaptureCandidateRelation) Selection() (pd.BootstrapCandidateSelection, error) {
	receipt, err := r.Receipt()
	if err != nil {
		return pd.BootstrapCandidateSelection{}, sec.ErrRegistrationUnavailable
	}
	return pd.BootstrapCandidateSelection{Purpose: r.reference.Purpose, ReferenceIdentityHash: pd.Hash(r.reference.IdentityHash),
		ReferenceVersion: pd.RefVersion(r.reference.Version), MappingHash: pd.Hash(r.mappingSHA),
		Request: receipt.Request, ResultVersion: receipt.ResultVersion}, nil
}

func (r *CaptureCandidateRelation) Reference() sec.BootstrapSecretRef {
	if r == nil {
		return sec.BootstrapSecretRef{}
	}
	return r.reference
}
func (r *CaptureCandidateRelation) MappingSHA256() string {
	if r == nil {
		return ""
	}
	return r.mappingSHA
}
func (r *CaptureCandidateRelation) DescriptorSHA256() string {
	if r == nil {
		return ""
	}
	return r.descriptorSHA
}

func copyCandidateReceipt(receipt pd.ReceiptRecord) (pd.ReceiptRecord, error) {
	raw, err := json.Marshal(receipt)
	var out pd.ReceiptRecord
	if err != nil || pd.DecodeRecord(raw, &out) != nil {
		return out, sec.ErrRegistrationUnavailable
	}
	return out, nil
}

func shaBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
