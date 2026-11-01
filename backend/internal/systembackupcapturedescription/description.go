// Package systembackupcapturedescription defines encrypted historical DATA.
// Parsing these records grants no execution, key use, or source permission.
package systembackupcapturedescription

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	Version           = "system-backup-capture-description.v1"
	SeedVersion       = "system-backup-capture-description-seed.v1"
	Part              = "capture_description"
	Operation         = "capture-description"
	ControlPart       = "control_evidence"
	ProofPart         = "control_evidence_proofs"
	ControlOperation  = "capture-control-evidence"
	LogicalCipherName = "capture-description.json.enc"
	// The ORIGINAL runner plan is bounded to 4 MiB. Source and all invocation
	// bytes are a subset of that plan, not an independently refillable budget.
	MaxOriginalPlanBytes = 4 << 20
	MaxInvocationBytes   = 1 << 20
	MaxCandidateBytes    = 16384
	MaxMembers           = 9997 // the original 10,000-member plan also contains D/E/P
)

var ErrDescription = errors.New("invalid original capture description")
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var unit = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

// Selection is declared before capture. It deliberately has no future
// invocation/candidate/carrier digest and cannot create a context-hash cycle.
type Selection struct {
	Part      string `json:"part"`
	Operation string `json:"operation"`
	PartIndex uint32 `json:"part_index"`
}

type Seed struct {
	Version           string      `json:"schema_version"`
	Members           []Selection `json:"business_members"`
	MaxPlaintextBytes int64       `json:"max_plaintext_bytes"`
}

// Budget includes base64 expansion of the original source/invocation bytes and
// every full 16-KiB candidate wrapper, plus bounded typed-record overhead. It is
// arithmetic only; no allocation or large-file I/O is needed to derive it.
func Budget(members int) (int64, error) {
	if members < 1 || members > MaxMembers {
		return 0, ErrDescription
	}
	raw := int64(MaxOriginalPlanBytes) + int64(members)*MaxCandidateBytes
	return 4*((raw+2)/3) + int64(members)*1024 + 65536, nil
}

func BusinessOperation(operation string) bool {
	switch operation {
	case "capture-database", "capture-workspace", "capture-source-redis", "capture-team-redis", "capture-team-objects", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle":
		return true
	}
	return false
}

func (s Seed) Validate() error {
	limit, err := Budget(len(s.Members))
	if err != nil || s.Version != SeedVersion || s.MaxPlaintextBytes != limit {
		return ErrDescription
	}
	indices := map[uint32]bool{}
	for i, m := range s.Members {
		if !unit.MatchString(m.Part) || m.Part == Part || m.Part == ControlPart || m.Part == ProofPart || !BusinessOperation(m.Operation) || m.PartIndex >= 10000 || indices[m.PartIndex] || i > 0 && s.Members[i-1].Part >= m.Part {
			return ErrDescription
		}
		indices[m.PartIndex] = true
	}
	return nil
}

type Scope struct {
	InstallationID       string `json:"installation_id"`
	TaskPublicID         string `json:"task_public_id"`
	ConfigVersion        uint64 `json:"config_version"`
	ConfigSHA256         string `json:"config_sha256"`
	AttemptNo            uint64 `json:"attempt_no"`
	CaptureContextSHA256 string `json:"capture_context_sha256"`
}

type Invocation struct {
	Selection
	// []byte is intentional: JSON RawMessage would reserialize/compact bytes
	// whose existing InvocationSHA256 is defined over their ORIGINAL spelling.
	JSON   []byte `json:"original_invocation_bytes"`
	SHA256 string `json:"original_invocation_sha256"`
}

type Member struct {
	Invocation
	// This is the COMPLETE publisherStoredCandidate/FormalCandidateRecord
	// wrapper. Its candidate field is extracted by the semantic reader; it is
	// never re-marshaled and substituted for the wrapper's existing digest.
	CandidateJSON   []byte `json:"original_candidate_wrapper_bytes"`
	CandidateSHA256 string `json:"original_candidate_wrapper_sha256"`
	ResultSHA256    string `json:"original_result_sha256"`
}

type Description struct {
	Version               string   `json:"schema_version"`
	Scope                 Scope    `json:"scope"`
	Seed                  Seed     `json:"original_seed"`
	SourceInventoryJSON   []byte   `json:"original_source_inventory_bytes"`
	SourceInventorySHA256 string   `json:"original_source_inventory_sha256"`
	Members               []Member `json:"business_members"`
	// Frozen original D/E/P invocations are historical policy, not content
	// members or final results. In particular D's own candidate is NOT here.
	AdministrativeInvocations []Invocation `json:"administrative_invocations"`
}

func SHA256(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func originalJSON(raw []byte, limit int) bool {
	if len(raw) == 0 || len(raw) > limit || raw[0] != '{' || !json.Valid(raw) {
		return false
	}
	// JCS is used solely to detect malformed/duplicate properties. The
	// original bytes and their non-JCS hash remain untouched.
	_, err := jsoncanonicalizer.Transform(raw)
	return err == nil
}

func (d Description) Validate() error {
	s := d.Scope
	if d.Version != Version || d.Seed.Validate() != nil || s.InstallationID == "" || len(s.InstallationID) > 128 || s.TaskPublicID == "" || len(s.TaskPublicID) > 128 || s.ConfigVersion == 0 || s.ConfigVersion > 9007199254740991 || s.AttemptNo == 0 || s.AttemptNo > 9007199254740991 || !digest.MatchString(s.ConfigSHA256) || !digest.MatchString(s.CaptureContextSHA256) || !originalJSON(d.SourceInventoryJSON, MaxOriginalPlanBytes) || SHA256(d.SourceInventoryJSON) != d.SourceInventorySHA256 || len(d.Members) != len(d.Seed.Members) || len(d.AdministrativeInvocations) != 3 {
		return ErrDescription
	}
	bytesUsed := len(d.SourceInventoryJSON)
	indices := map[uint32]bool{}
	checkInvocation := func(v Invocation) bool {
		if indices[v.PartIndex] || v.PartIndex >= 10000 || !originalJSON(v.JSON, MaxInvocationBytes) || SHA256(v.JSON) != v.SHA256 {
			return false
		}
		indices[v.PartIndex] = true
		bytesUsed += len(v.JSON)
		return bytesUsed <= MaxOriginalPlanBytes
	}
	for i, m := range d.Members {
		if m.Selection != d.Seed.Members[i] || !checkInvocation(m.Invocation) || !originalJSON(m.CandidateJSON, MaxCandidateBytes) || SHA256(m.CandidateJSON) != m.CandidateSHA256 || !digest.MatchString(m.ResultSHA256) {
			return ErrDescription
		}
	}
	admin := []Selection{{Part: Part, Operation: Operation}, {Part: ControlPart, Operation: ControlOperation}, {Part: ProofPart, Operation: ControlOperation}}
	for i, v := range d.AdministrativeInvocations {
		if v.Part != admin[i].Part || v.Operation != admin[i].Operation || !checkInvocation(v) {
			return ErrDescription
		}
	}
	for i := 0; i < len(d.Members)+3; i++ {
		if !indices[uint32(i)] {
			return ErrDescription
		}
	}
	return nil
}

// Encode and Decode check only the closed typed transport and exact original
// byte digests. Callers MUST independently bind the whole original plan set,
// typed Invocation/candidate semantics and certificate/AEAD/checkpoint chain.
func Encode(d Description) ([]byte, error) {
	if d.Validate() != nil {
		return nil, ErrDescription
	}
	input, err := json.Marshal(d)
	defer clear(input)
	if err != nil {
		return nil, ErrDescription
	}
	raw, err := jsoncanonicalizer.Transform(input)
	if err != nil || int64(len(raw)) > d.Seed.MaxPlaintextBytes {
		clear(raw)
		return nil, ErrDescription
	}
	return raw, nil
}

func Decode(raw []byte, expected Seed) (Description, error) {
	var d Description
	keep := false
	defer func() {
		if !keep {
			d.Clear()
		}
	}()
	if expected.Validate() != nil || len(raw) == 0 || int64(len(raw)) > expected.MaxPlaintextBytes {
		return d, ErrDescription
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF {
		return Description{}, ErrDescription
	}
	actualSeed, _ := json.Marshal(d.Seed)
	expectedSeed, _ := json.Marshal(expected)
	if !bytes.Equal(actualSeed, expectedSeed) {
		return Description{}, ErrDescription
	}
	canonical, err := Encode(d)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Description{}, ErrDescription
	}
	keep = true
	return d, nil
}

func (d *Description) Clear() {
	if d == nil {
		return
	}
	clear(d.SourceInventoryJSON)
	for _, m := range d.Members {
		clear(m.JSON)
		clear(m.CandidateJSON)
	}
	for _, v := range d.AdministrativeInvocations {
		clear(v.JSON)
	}
}
