package systembackupcapturedescription

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	w "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const BootstrapVersion = "system-backup-capture-bootstrap.v1"
const BootstrapPath = "control/capture-bootstrap.json"
const CipherPath = "control/capture-description.json.enc"
const EnvelopePath = "control/capture-description.envelope.json"
const MaxBootstrapBytes = 3*(64<<10) + 4096

// Public DATA: only immutable ciphertext coordinates/specs and original
// checkpoint bytes. No raw Invocation/source inventory/authority or candidate
// wrapper is exposed here. The signed certificate pins every checkpoint.
type Bootstrap struct {
	Version               string                 `json:"schema_version"`
	Scope                 Scope                  `json:"scope"`
	SourceInventorySHA256 string                 `json:"source_inventory_sha256"`
	Members               []AdministrativeMember `json:"administrative_members"`
}

type AdministrativeMember struct {
	Selection
	CipherPath     string       `json:"cipher_path"`
	EnvelopePath   string       `json:"envelope_path"`
	CipherBytes    int64        `json:"cipher_bytes"`
	CipherSHA256   string       `json:"cipher_sha256"`
	EnvelopeBytes  int64        `json:"envelope_bytes"`
	EnvelopeSHA256 string       `json:"envelope_sha256"`
	Stream         w.StreamSpec `json:"original_stream_spec"`
	CheckpointJSON []byte       `json:"original_checkpoint_bytes"`
}

// Same closed historical checkpoint shape as the original B protocol. Kept
// local so this package can be used by worker without an import cycle.
type checkpoint struct {
	InstallationID   string `json:"installation_id"`
	ConfigVersion    uint64 `json:"config_version"`
	SchemaVersion    string `json:"schema_version"`
	TaskPublicID     string `json:"task_public_id"`
	AttemptNo        uint64 `json:"attempt_no"`
	Phase            string `json:"phase"`
	ConfigSHA256     string `json:"config_sha256"`
	InventorySHA256  string `json:"inventory_sha256"`
	Part             string `json:"part"`
	JobUID           string `json:"job_uid"`
	JobGeneration    uint64 `json:"job_generation"`
	InvocationSHA256 string `json:"invocation_sha256"`
	SealedRef        string `json:"sealed_ref"`
	ContentSHA256    string `json:"content_sha256"`
}

func (b Bootstrap) Validate(checkpoints map[string]string) error {
	s := b.Scope
	if b.Version != BootstrapVersion || len(b.Members) != 3 || !digest.MatchString(b.SourceInventorySHA256) || len(checkpoints) < 4 || len(checkpoints) > 10000 || s.InstallationID == "" || len(s.InstallationID) > 128 || s.TaskPublicID == "" || len(s.TaskPublicID) > 128 || s.AttemptNo == 0 || s.AttemptNo > 9007199254740991 || s.ConfigVersion == 0 || s.ConfigVersion > 9007199254740991 || !digest.MatchString(s.ConfigSHA256) || !digest.MatchString(s.CaptureContextSHA256) {
		return ErrDescription
	}
	expected := []struct{ part, op, cipher, envelope, path string }{{Part, Operation, CipherPath, EnvelopePath, LogicalCipherName}, {ControlPart, ControlOperation, "control/evidence.json.enc", "control/evidence.envelope.json", "control-evidence.enc"}, {ProofPart, ControlOperation, "control/evidence-proofs.json.enc", "control/evidence-proofs.envelope.json", "control-evidence-proofs.enc"}}
	indices := map[uint32]bool{}
	uids := map[string]bool{}
	envelopes := map[string]bool{}
	descriptionLimit, err := Budget(len(checkpoints) - 3)
	if err != nil {
		return ErrDescription
	}
	limits := []int64{descriptionLimit, 262144, 8 << 20}
	for i, m := range b.Members {
		if w.ValidateStreamSpec(m.Stream) != nil || envelopes[m.Stream.Request.Context.EnvelopeID] {
			return ErrDescription
		}
		envelopes[m.Stream.Request.Context.EnvelopeID] = true
		if m.Stream.MaxPlaintextBytes != limits[i] || m.CipherBytes > m.Stream.MaxPlaintextBytes+int64(m.Stream.MaxFrames)*4096+8192 {
			return ErrDescription
		}
		e := expected[i]
		k := m.Stream.Request.Context
		if m.Part != e.part || m.Operation != e.op || m.CipherPath != e.cipher || m.EnvelopePath != e.envelope || m.PartIndex >= 10000 || indices[m.PartIndex] || m.CipherBytes < 1 || m.EnvelopeBytes < 1 || m.EnvelopeBytes > 32<<20 || !digest.MatchString(m.CipherSHA256) || !digest.MatchString(m.EnvelopeSHA256) || m.Stream.Path != e.path || m.Stream.MaxFrames < 2 || m.Stream.MaxFrames > w.MaxStreamFrames || m.Stream.MaxPlaintextBytes < 1 || m.Stream.MaxPlaintextBytes > int64(m.Stream.MaxFrames-1)*w.ChunkSize || k.InstallationID != s.InstallationID || k.BackupPublicID != s.TaskPublicID || k.AttemptNo != strconv.FormatUint(s.AttemptNo, 10) || k.Phase != "capture" || k.Part != m.Part || k.PartIndex != strconv.FormatUint(uint64(m.PartIndex), 10) || k.CaptureContextHash != s.CaptureContextSHA256 || k.EnvelopeID == "" {
			return ErrDescription
		}
		indices[m.PartIndex] = true
		if len(m.CheckpointJSON) == 0 || len(m.CheckpointJSON) > 8192 {
			return ErrDescription
		}
		var cp checkpoint
		decoder := json.NewDecoder(bytes.NewReader(m.CheckpointJSON))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&cp) != nil || decoder.Decode(new(any)) != io.EOF {
			return ErrDescription
		}
		original, err := json.Marshal(cp)
		if err != nil || !bytes.Equal(original, m.CheckpointJSON) || cp.InstallationID != s.InstallationID || cp.ConfigVersion != s.ConfigVersion || cp.SchemaVersion != "system-backup-b-checkpoint.v1" || cp.TaskPublicID != s.TaskPublicID || cp.AttemptNo != s.AttemptNo || cp.Phase != "capture" || cp.ConfigSHA256 != s.ConfigSHA256 || cp.InventorySHA256 != b.SourceInventorySHA256 || cp.Part != m.Part || cp.ContentSHA256 != m.CipherSHA256 || !digest.MatchString(cp.InvocationSHA256) || cp.JobUID == "" || len(cp.JobUID) > 256 || uids[cp.JobUID] || cp.JobGeneration < 1 || cp.JobGeneration > 9007199254740991 || cp.SealedRef == "" || len(cp.SealedRef) > 1024 {
			return ErrDescription
		}
		uids[cp.JobUID] = true
		canonical, err := jsoncanonicalizer.Transform(m.CheckpointJSON)
		if err != nil || !digest.MatchString(checkpoints[m.Part]) || SHA256(canonical) != checkpoints[m.Part] {
			return ErrDescription
		}
	}
	return nil
}

func EncodeBootstrap(b Bootstrap, checkpoints map[string]string) ([]byte, error) {
	if b.Validate(checkpoints) != nil {
		return nil, ErrDescription
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxBootstrapBytes {
		return nil, ErrDescription
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(canonical) > MaxBootstrapBytes {
		return nil, ErrDescription
	}
	return canonical, nil
}

// checkpoints and scope MUST come from the independently authenticated
// original certificate/manifest, not this bootstrap's own declarations.
func DecodeBootstrap(raw []byte, scope Scope, sourceSHA string, checkpoints map[string]string) (Bootstrap, error) {
	var b Bootstrap
	if len(raw) == 0 || len(raw) > MaxBootstrapBytes {
		return b, ErrDescription
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&b) != nil || decoder.Decode(new(any)) != io.EOF || b.Scope != scope || b.SourceInventorySHA256 != sourceSHA {
		return Bootstrap{}, ErrDescription
	}
	canonical, err := EncodeBootstrap(b, checkpoints)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Bootstrap{}, ErrDescription
	}
	return b, nil
}
