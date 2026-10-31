// Package systembackupcontrolevidence contains the read-only control sidecar
// protocol. It has no provider, credentials, source writes or task authority.
package systembackupcontrolevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const Version = "system-backup-control-evidence.v1"
const Part = "control_evidence"
const ProofPart = "control_evidence_proofs"
const Operation = "capture-control-evidence"
const CipherPath = "control/evidence.json.enc"
const EnvelopePath = "control/evidence.envelope.json"
const ProofCipherPath = "control/evidence-proofs.json.enc"
const LogicalCipherName = "control-evidence.enc"
const LogicalProofCipherName = "control-evidence-proofs.enc"
const MaxBytes = 262144
const MaxProofBytes = 8 << 20
const RecordsPerEvidence = 40
const MaxGroupEvidence = 16
const MaxGroupRecords = RecordsPerEvidence * MaxGroupEvidence

var ErrInvalid = errors.New("control evidence failed independent verification")
var ErrCapacity = errors.New("control evidence capacity_exceeded")
var groups = []string{"task_terminal", "operation_terminal", "event", "audit", "promotion", "dependency_health", "provider_capability", "alert_state", "installation_state"}

func GroupNames() []string { return append([]string(nil), groups...) }

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var evidencePattern = regexp.MustCompile(`^sev_[A-Za-z0-9_.:-]{1,124}$`)

type Scope struct {
	Installation string `json:"origin_installation_id"`
	Backup       string `json:"backup_public_id"`
	Attempt      uint64 `json:"attempt_no"`
}
type RegistryPin struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}
type EvidenceRef struct {
	PublicID string `json:"public_id"`
	SHA256   string `json:"sha256"`
}
type Exclusion struct {
	Version     string      `json:"schema_registry_version"`
	SHA256      string      `json:"schema_registry_hash"`
	Count       uint64      `json:"excluded_control_object_count"`
	NamesSHA256 string      `json:"excluded_control_object_names_hash"`
	Evidence    EvidenceRef `json:"exclusion_check_evidence"`
}
type Redaction struct {
	Version  string      `json:"registry_version"`
	SHA256   string      `json:"registry_hash"`
	Applied  bool        `json:"applied"`
	Rejected uint64      `json:"rejected_records"`
	Evidence EvidenceRef `json:"redaction_check_evidence"`
}
type Group struct {
	Group         string        `json:"group"`
	Count         uint64        `json:"record_count"`
	First         *time.Time    `json:"first_recorded_at"`
	Last          *time.Time    `json:"last_recorded_at"`
	RollingSHA256 string        `json:"rolling_hash"`
	Evidence      []EvidenceRef `json:"evidence_refs"`
}
type Owner struct {
	Owner    string        `json:"owner"`
	Status   string        `json:"status"`
	Reason   string        `json:"reason"`
	Summary  *string       `json:"verifier_summary_hash"`
	Evidence []EvidenceRef `json:"evidence_refs"`
}
type Warning struct {
	Code          string `json:"code"`
	Category      string `json:"category"`
	Disqualifying bool   `json:"disqualifying"`
}
type Sidecar struct {
	Version  string `json:"schema_version"`
	Contract string `json:"contract_version"`
	Scope
	Generated time.Time        `json:"generated_at"`
	Start     time.Time        `json:"coverage_started_at"`
	End       time.Time        `json:"coverage_ended_at"`
	Exclusion Exclusion        `json:"control_exclusion"`
	Redaction Redaction        `json:"redaction_proof"`
	Groups    map[string]Group `json:"record_groups"`
	Owners    map[string]Owner `json:"owner_sections"`
	Warnings  []Warning        `json:"warnings"`
}

// Evidence bodies are copied from actual registered, immutable original
// evidence into a SECOND original planned C stream. Readback cannot repair a
// missing body from SQL. Neither this DTO nor its checksum grants capture use.
type RegisteredEvidence struct {
	PublicID  string          `json:"public_id"`
	SHA256    string          `json:"sha256"`
	OwnerType string          `json:"owner_target_type"`
	OwnerID   string          `json:"owner_target_public_id"`
	Type      string          `json:"evidence_type"`
	Payload   json.RawMessage `json:"payload"`
}
type ProofBundle struct {
	Version string `json:"schema_version"`
	Scope
	Entries []RegisteredEvidence `json:"entries"`
}
type PreparedSource struct {
	Scope
	SidecarJSON   []byte         `json:"-"`
	SidecarSHA256 string         `json:"sidecar_sha256"`
	ProofsJSON    []byte         `json:"-"`
	ProofsSHA256  string         `json:"proofs_sha256"`
	Locator       CaptureLocator `json:"locator"`
}
type Expected struct {
	Scope
	ConfigSHA256         string      `json:"config_sha256"`
	SourceIdentitySHA256 string      `json:"source_identity_sha256"`
	SchemaRegistry       RegistryPin `json:"schema_registry"`
	RedactionRegistry    RegistryPin `json:"redaction_registry"`
}

type TimedDigest struct {
	At     time.Time `json:"recorded_at"`
	SHA256 string    `json:"canonical_redacted_record_sha256"`
}
type GroupProof struct {
	Version string `json:"schema_version"`
	Scope
	Group      string        `json:"group"`
	ChunkIndex uint32        `json:"chunk_index"`
	ChunkCount uint32        `json:"chunk_count"`
	Start      time.Time     `json:"coverage_started_at"`
	End        time.Time     `json:"coverage_ended_at"`
	Records    []TimedDigest `json:"records"`
}
type ExclusionProof struct {
	Version string `json:"schema_version"`
	Scope
	Registry       RegistryPin `json:"registry"`
	Excluded       []string    `json:"excluded_control_objects"`
	Included       []string    `json:"included_control_objects"`
	SourceEvidence EvidenceRef `json:"source_exclusion_evidence"`
}
type SourceExclusionProof struct {
	Version string `json:"schema_version"`
	Scope
	ConfigSHA256         string      `json:"config_sha256"`
	SourceIdentitySHA256 string      `json:"source_identity_sha256"`
	Registry             RegistryPin `json:"registry"`
	ExcludedNamesSHA256  string      `json:"excluded_control_object_names_hash"`
	IncludedControlCount uint64      `json:"included_control_object_count"`
}
type RedactionProof struct {
	Version string `json:"schema_version"`
	Scope
	Registry         RegistryPin `json:"registry"`
	Applied          bool        `json:"applied"`
	Rejected         uint64      `json:"rejected_records"`
	ProjectionSHA256 string      `json:"projection_sha256"`
}
type OwnerProof struct {
	Version string `json:"schema_version"`
	Scope
	Owner         string `json:"owner"`
	SummarySHA256 string `json:"verifier_summary_hash"`
}

func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func Canonical(value any) ([]byte, error) {
	return canonicalLimit(value, MaxBytes)
}
func CanonicalProofs(value any) ([]byte, error) { return canonicalLimit(value, MaxProofBytes) }
func canonicalLimit(value any, limit int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalid
	}
	out, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(out) > limit {
		return nil, ErrInvalid
	}
	return out, nil
}
func closed(raw []byte, out any) error {
	return closedLimit(raw, out, MaxBytes)
}
func closedLimit(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrInvalid
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func ValidScope(s Scope) bool {
	return regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(s.Installation) && regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`).MatchString(s.Backup) && s.Attempt > 0 && s.Attempt < 1<<32
}
func validPin(p RegistryPin) bool {
	return p.Version != "" && p.Version != "latest" && p.Version != "current" && len(p.Version) <= 128 && digestPattern.MatchString(p.SHA256)
}
func validRef(r EvidenceRef) bool {
	return evidencePattern.MatchString(r.PublicID) && digestPattern.MatchString(r.SHA256)
}
func namesHash(names []string) (string, error) {
	if len(names) == 0 || len(names) > 10000 || !sort.StringsAreSorted(names) {
		return "", ErrInvalid
	}
	for i, name := range names {
		if !regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`).MatchString(name) || i > 0 && name == names[i-1] {
			return "", ErrInvalid
		}
	}
	raw, err := Canonical(names)
	if err != nil {
		return "", err
	}
	return SHA256(raw), nil
}

// RollingHash implements the specified length-prefixed ordered sequence of
// lowercase canonical SHA-256 TEXT bytes; the empty sequence hashes empty.
func RollingHash(records []TimedDigest) (string, error) {
	h := sha256.New()
	for i, record := range records {
		if !digestPattern.MatchString(record.SHA256) || record.At.IsZero() || i > 0 && record.At.Before(records[i-1].At) {
			return "", ErrInvalid
		}
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(record.SHA256)))
		h.Write(length[:])
		h.Write([]byte(record.SHA256))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify consumes BOTH complete independently decrypted original artifact
// streams. No network/SQL lookup, missing-reference repair or success flag is
// accepted. Current encryption authority remains the caller's C-frame duty.
func Verify(ctx context.Context, sidecarRaw, proofRaw []byte, expected Expected) (Sidecar, error) {
	var sidecar Sidecar
	var bundle ProofBundle
	if ctx == nil || ctx.Err() != nil || !ValidScope(expected.Scope) || !digestPattern.MatchString(expected.ConfigSHA256) || !validPin(expected.SchemaRegistry) || !validPin(expected.RedactionRegistry) || closed(sidecarRaw, &sidecar) != nil || closedLimit(proofRaw, &bundle, MaxProofBytes) != nil || len(bundle.Entries) > 256 || sidecar.Version != Version || sidecar.Contract != "system-backup-plan.v12" || sidecar.Scope != expected.Scope || bundle.Version != "system-backup-control-evidence-proofs.v1" || bundle.Scope != expected.Scope || sidecar.Start.IsZero() || sidecar.End.Before(sidecar.Start) || sidecar.Generated.Before(sidecar.End) || len(sidecar.Groups) != len(groups) || len(sidecar.Owners) != 4 || sidecar.Warnings == nil || len(sidecar.Warnings) > 16 {
		return Sidecar{}, ErrInvalid
	}
	refs := map[string]RegisteredEvidence{}
	last := ""
	for _, entry := range bundle.Entries {
		canonical, err := jsoncanonicalizer.Transform(entry.Payload)
		if err != nil || !bytes.Equal(canonical, entry.Payload) || !validRef(EvidenceRef{entry.PublicID, entry.SHA256}) || SHA256(entry.Payload) != entry.SHA256 || entry.PublicID <= last || entry.Type != "verifier_report" || entry.OwnerType != "backup" && entry.OwnerType != "system" || entry.OwnerType == "backup" && entry.OwnerID != expected.Backup || entry.OwnerType == "system" && entry.OwnerID != expected.Installation {
			return Sidecar{}, ErrInvalid
		}
		last = entry.PublicID
		refs[entry.PublicID] = entry
	}
	used := map[string]bool{}
	resolve := func(ref EvidenceRef) ([]byte, error) {
		entry, ok := refs[ref.PublicID]
		if !ok || !validRef(ref) || entry.SHA256 != ref.SHA256 {
			return nil, ErrInvalid
		}
		used[ref.PublicID] = true
		return entry.Payload, nil
	}
	raw, err := resolve(sidecar.Exclusion.Evidence)
	var exclusion ExclusionProof
	if err != nil || closed(raw, &exclusion) != nil || exclusion.Version != "system-backup-control-exclusion-proof.v1" || exclusion.Scope != expected.Scope || exclusion.Registry != expected.SchemaRegistry || sidecar.Exclusion.Version != expected.SchemaRegistry.Version || sidecar.Exclusion.SHA256 != expected.SchemaRegistry.SHA256 || len(exclusion.Included) != 0 || exclusion.Included == nil {
		return Sidecar{}, ErrInvalid
	}
	namesSHA, err := namesHash(exclusion.Excluded)
	if err != nil || uint64(len(exclusion.Excluded)) != sidecar.Exclusion.Count || namesSHA != sidecar.Exclusion.NamesSHA256 {
		return Sidecar{}, ErrInvalid
	}
	// The source's independently registered exclusion result is mandatory too.
	sourceRaw, err := resolve(exclusion.SourceEvidence)
	var source SourceExclusionProof
	if err != nil || closed(sourceRaw, &source) != nil || source.Version != "system-backup-source-control-exclusion.v1" || source.Scope != expected.Scope || source.ConfigSHA256 != expected.ConfigSHA256 || !digestPattern.MatchString(source.SourceIdentitySHA256) || source.SourceIdentitySHA256 != expected.SourceIdentitySHA256 || source.Registry != expected.SchemaRegistry || source.ExcludedNamesSHA256 != namesSHA || source.IncludedControlCount != 0 {
		return Sidecar{}, ErrInvalid
	}
	raw, err = resolve(sidecar.Redaction.Evidence)
	var redaction RedactionProof
	if err != nil || closed(raw, &redaction) != nil || redaction.Version != "system-backup-control-redaction-proof.v1" || redaction.Scope != expected.Scope || redaction.Registry != expected.RedactionRegistry || !redaction.Applied || redaction.Rejected != 0 || !digestPattern.MatchString(redaction.ProjectionSHA256) || sidecar.Redaction.Version != expected.RedactionRegistry.Version || sidecar.Redaction.SHA256 != expected.RedactionRegistry.SHA256 || !sidecar.Redaction.Applied || sidecar.Redaction.Rejected != 0 {
		return Sidecar{}, ErrInvalid
	}
	projectionRaw, err := Canonical(ProjectionColumns())
	if err != nil || redaction.ProjectionSHA256 != SHA256(projectionRaw) {
		return Sidecar{}, ErrInvalid
	}
	for _, name := range groups {
		group, ok := sidecar.Groups[name]
		if !ok || group.Group != name || len(group.Evidence) < 1 || len(group.Evidence) > MaxGroupEvidence {
			return Sidecar{}, ErrInvalid
		}
		records := []TimedDigest{}
		for index, ref := range group.Evidence {
			raw, err = resolve(ref)
			var proof GroupProof
			if err != nil || closed(raw, &proof) != nil || proof.Version != "system-backup-control-group-proof.v1" || proof.Scope != expected.Scope || proof.Group != name || proof.ChunkIndex != uint32(index) || proof.ChunkCount != uint32(len(group.Evidence)) || !proof.Start.Equal(sidecar.Start) || !proof.End.Equal(sidecar.End) || proof.Records == nil || len(proof.Records) > RecordsPerEvidence || len(proof.Records) == 0 && len(group.Evidence) != 1 {
				return Sidecar{}, ErrInvalid
			}
			records = append(records, proof.Records...)
		}
		if uint64(len(records)) != group.Count {
			return Sidecar{}, ErrInvalid
		}
		rolling, err := RollingHash(records)
		if err != nil || rolling != group.RollingSHA256 {
			return Sidecar{}, ErrInvalid
		}
		if group.Count == 0 {
			if group.First != nil || group.Last != nil {
				return Sidecar{}, ErrInvalid
			}
		} else {
			if group.First == nil || group.Last == nil || !group.First.Equal(records[0].At) || !group.Last.Equal(records[len(records)-1].At) || group.First.Before(sidecar.Start) || group.Last.After(sidecar.End) {
				return Sidecar{}, ErrInvalid
			}
		}
	}
	ownerBasisSHA := ""
	for _, name := range []string{"A", "B", "C", "D"} {
		owner, ok := sidecar.Owners[name]
		if !ok || owner.Owner != name || owner.Evidence == nil || len(owner.Evidence) > 32 {
			return Sidecar{}, ErrInvalid
		}
		switch owner.Status {
		case "complete":
			if owner.Reason != "none" || owner.Summary == nil || !digestPattern.MatchString(*owner.Summary) || len(owner.Evidence) < 1 {
				return Sidecar{}, ErrInvalid
			}
			if name != "A" {
				raw, err = resolve(owner.Evidence[0])
				var proof OwnedReportProof
				if err != nil || closed(raw, &proof) != nil || proof.Version != "system-backup-control-owned-reports.v1" || proof.Scope != expected.Scope || proof.Owner != name || proof.ConfigSHA256 != expected.ConfigSHA256 || !proof.CoverageEndedAt.Equal(sidecar.End) || proof.ObservedAt.Before(sidecar.End) || proof.ObservedAt.After(sidecar.Generated) || proof.SummarySHA256 != *owner.Summary || len(owner.Evidence) != len(proof.Reports)+len(proof.BasisRefs)+1 {
					return Sidecar{}, ErrInvalid
				}
				basis, basisErr := ownedBasis(proof, refs)
				if basisErr != nil {
					return Sidecar{}, basisErr
				}
				basisRaw, basisErr := CanonicalProofs(basis)
				if basisErr != nil || ownerBasisSHA != "" && ownerBasisSHA != SHA256(basisRaw) {
					return Sidecar{}, ErrInvalid
				}
				ownerBasisSHA = SHA256(basisRaw)
				for index, ref := range append(append([]EvidenceRef{}, proof.BasisRefs...), proof.Reports...) {
					if ref != owner.Evidence[index+1] {
						return Sidecar{}, ErrInvalid
					}
					if _, err = resolve(ref); err != nil {
						return Sidecar{}, err
					}
				}
				summary, err := ownedSummary(proof, refs)
				if err != nil || summary != *owner.Summary {
					return Sidecar{}, ErrInvalid
				}
				continue
			}
			if len(owner.Evidence) != 1 {
				return Sidecar{}, ErrInvalid
			}
			raw, err = resolve(owner.Evidence[0])
			var proof OwnerProof
			if err != nil || closed(raw, &proof) != nil || proof.Version != "system-backup-control-owner-proof.v1" || proof.Scope != expected.Scope || proof.Owner != name || proof.SummarySHA256 != *owner.Summary {
				return Sidecar{}, ErrInvalid
			}
			summary, err := OwnerASummary(sidecar)
			if err != nil || summary != *owner.Summary {
				return Sidecar{}, ErrInvalid
			}
		case "incomplete":
			if owner.Reason != "evidence_missing" && owner.Reason != "owner_check_failed" && owner.Reason != "redaction_failed" && owner.Reason != "capacity_exceeded" || owner.Summary != nil || len(owner.Evidence) != 0 {
				return Sidecar{}, ErrInvalid
			}
		case "not_applicable":
			if owner.Reason != "none" || owner.Summary != nil || len(owner.Evidence) != 0 {
				return Sidecar{}, ErrInvalid
			}
		default:
			return Sidecar{}, ErrInvalid
		}
	}
	for _, entry := range bundle.Entries {
		var kind struct {
			Version string `json:"schema_version"`
		}
		if json.Unmarshal(entry.Payload, &kind) != nil {
			return Sidecar{}, ErrInvalid
		}
		if kind.Version != "system-backup-control-original-source-seed.v1" {
			continue
		}
		seed, root, chunks, err := finalizedSeed(refs)
		if err != nil || seed.Expected != expected || verifySeedBasis(ctx, seed, sidecar, refs) != nil {
			return Sidecar{}, ErrInvalid
		}
		if _, err = resolve(reference(root)); err != nil {
			return Sidecar{}, err
		}
		for _, ref := range chunks {
			if _, err = resolve(ref); err != nil {
				return Sidecar{}, err
			}
		}
	}
	if len(used) != len(refs) || ctx.Err() != nil {
		return Sidecar{}, ErrInvalid
	}
	return sidecar, nil
}

func SourceIdentity(serverUUID, database string) (string, error) {
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(serverUUID) || !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(database) {
		return "", ErrInvalid
	}
	raw, err := Canonical(struct {
		Server   string `json:"server_uuid"`
		Database string `json:"database"`
	}{serverUUID, database})
	if err != nil {
		return "", err
	}
	return SHA256(raw), nil
}

// Intrinsic validation is deliberately independent of today's clock or worker
// credential lifetime. Live control/Generate checks stay in the real worker;
// authenticated historical candidates remain readable by a new publisher.
func ValidatePrepared(ctx context.Context, source PreparedSource, expected Expected) error {
	if source.Scope != expected.Scope || SHA256(source.SidecarJSON) != source.SidecarSHA256 || SHA256(source.ProofsJSON) != source.ProofsSHA256 {
		return ErrInvalid
	}
	_, err := Verify(ctx, source.SidecarJSON, source.ProofsJSON, expected)
	return err
}
