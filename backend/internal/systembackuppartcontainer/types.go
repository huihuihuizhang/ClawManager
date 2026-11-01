// Package systembackuppartcontainer frames existing ORIGINAL C streams without
// decrypting, re-encrypting, obtaining a source grant or calling a provider.
// All outputs are inert byte facts, never capture/publication/DR authority.
package systembackuppartcontainer

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	b "clawreef/internal/systembackup/publicadapter"
	w "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const Version = "system-backup-part-container.v1"

// Original v12 CapacityConfig maxima; callers pass their actual lower limits.
const MaxBytes int64 = 900 << 30
const MaxIndexBytes int64 = 8 << 30
const MaxMembers = 10000
const maxMemberMetadataBytes = 64 << 10
const maxScopeMetadataBytes = 4096

// Derived shape bound: original capture admits at most 10,000 C streams;
// each bounded AAD/spec/path and original 8 KiB checkpoint fits in 64 KiB.
// Source rows/files stay INSIDE C, never in this member metadata index.
const MaxHeaderBytes = MaxMembers*(maxMemberMetadataBytes+1) + maxScopeMetadataBytes + 256
const maxEnvelopeBytes = 32 << 20
const prefixBytes = 12

var magic = [8]byte{'S', 'B', 'P', 'C', 0, 0, 0, 1}
var ErrContainer = errors.New("original C part container unavailable or conflicting")
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var backupID = regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`)

type Scope struct {
	Installation         string `json:"origin_installation_id"`
	Backup               string `json:"backup_public_id"`
	Attempt              uint64 `json:"attempt_no"`
	ConfigVersion        uint64 `json:"config_version"`
	ConfigSHA256         string `json:"config_sha256"`
	CaptureContextSHA256 string `json:"capture_context_hash"`
	Part                 string `json:"requested_part"`
}

type Header struct {
	Version               string   `json:"schema_version"`
	Scope                 Scope    `json:"scope"`
	SourceInventorySHA256 string   `json:"source_inventory_sha256"`
	Members               []Member `json:"members"`
}

// Offsets are relative to the payload AFTER the 12-byte prefix and complete
// canonical header. Each original C is immediately followed by its original
// complete envelope. No member byte, framing, AAD, path or key is rewritten.
type Member struct {
	Part            string       `json:"part"`
	Operation       string       `json:"operation"`
	Index           uint32       `json:"original_part_index"`
	CipherPath      string       `json:"original_cipher_object_path"`
	EnvelopePath    string       `json:"original_envelope_object_path"`
	CipherOffset    int64        `json:"cipher_offset"`
	CipherBytes     int64        `json:"cipher_bytes"`
	CipherSHA256    string       `json:"cipher_sha256"`
	CipherFraming   string       `json:"cipher_framing_version"`
	EnvelopeOffset  int64        `json:"envelope_offset"`
	EnvelopeBytes   int64        `json:"envelope_bytes"`
	EnvelopeSHA256  string       `json:"envelope_sha256"`
	EnvelopeFraming string       `json:"envelope_framing_version"`
	Stream          w.StreamSpec `json:"original_stream_spec"`
	Checkpoint      []byte       `json:"original_checkpoint_bytes"`
}

// A remote version belongs to the complete immutable container object and all
// its member ranges. It is recorded at readback, not invented before upload,
// and is deliberately absent from the unchanged v12 public artifact index.
type MemberLocation struct {
	Part, ObjectVersion                                      string
	Index                                                    uint32
	CipherOffset, CipherBytes, EnvelopeOffset, EnvelopeBytes int64
	CipherSHA256, EnvelopeSHA256, CheckpointSHA256           string
}

type Facts struct {
	Header                           Header
	Size, CipherBytes, EnvelopeBytes int64
	SHA256                           string
	HeaderBytes                      int
	Locations                        []MemberLocation
}

func requestedPart(operation string) string {
	switch operation {
	case "capture-database":
		return "mysql"
	case "capture-source-redis", "capture-team-redis":
		return "redis"
	case "capture-skill-objects", "capture-team-objects":
		return "object_storage"
	case "capture-workspace":
		return "workspace"
	case "capture-deployment-resources":
		return "deployment_resources"
	case "capture-secret-bundle":
		return "secret_bundle"
	}
	return ""
}

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrContainer
	}
	out, err := jsoncanonicalizer.Transform(raw)
	if err != nil || len(out) == 0 || len(out) > MaxHeaderBytes {
		return nil, ErrContainer
	}
	return out, nil
}

func safePath(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.ContainsAny(value, ":\\\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func fixedVersion(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for _, alias := range []string{"null", "latest", "current", "default"} {
		if strings.EqualFold(value, alias) {
			return false
		}
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// Validate every retained checkpoint against its independent certificate hash.
// Parsing the original spec/envelope still grants no DEK or source authority.
func validateHeader(header Header, expected Scope, checkpoints map[string]string, limit int64) (Facts, error) {
	var zero Facts
	s := header.Scope
	if header.Version != Version || s != expected || s.Installation == "" || len(s.Installation) > 128 || len(s.Backup) > 128 || !backupID.MatchString(s.Backup) || s.Attempt < 1 || s.Attempt > 9007199254740991 || s.ConfigVersion < 1 || s.ConfigVersion > 9007199254740991 || !digest.MatchString(s.ConfigSHA256) || !digest.MatchString(s.CaptureContextSHA256) || !digest.MatchString(header.SourceInventorySHA256) || requestedPartForName(s.Part) == "" || len(header.Members) == 0 || len(header.Members) > MaxMembers || len(checkpoints) != len(header.Members) || limit < 1 || limit > MaxBytes {
		return zero, ErrContainer
	}
	seen := map[string]bool{}
	paths := map[string]bool{}
	var offset int64
	result := Facts{Header: header, Locations: make([]MemberLocation, 0, len(header.Members))}
	for index, member := range header.Members {
		context := member.Stream.Request.Context
		if member.Part == "" || len(member.Part) > 256 || seen[member.Part] || member.Index >= MaxMembers || index != 0 && member.Index <= header.Members[index-1].Index || requestedPart(member.Operation) != s.Part || !safePath(member.CipherPath) || !safePath(member.EnvelopePath) || member.CipherPath == member.EnvelopePath || paths[member.CipherPath] || paths[member.EnvelopePath] || member.CipherFraming != w.FramingVersion || member.EnvelopeFraming != w.EnvelopeVersion || !digest.MatchString(member.CipherSHA256) || !digest.MatchString(member.EnvelopeSHA256) || member.CipherOffset != offset || member.CipherBytes < 1 || member.CipherBytes > limit-offset || context.InstallationID != s.Installation || context.BackupPublicID != s.Backup || context.AttemptNo != strconv.FormatUint(s.Attempt, 10) || context.Phase != "capture" || context.Part != member.Part || context.PartIndex != strconv.FormatUint(uint64(member.Index), 10) || context.CaptureContextHash != s.CaptureContextSHA256 || !safePath(member.Stream.Path) || member.Stream.MaxFrames < 1 || member.Stream.MaxFrames > w.MaxStreamFrames || member.Stream.MaxPlaintextBytes < 0 || member.Stream.MaxPlaintextBytes > int64(member.Stream.MaxFrames-1)*w.ChunkSize {
			return zero, ErrContainer
		}
		offset += member.CipherBytes
		if member.EnvelopeOffset != offset || member.EnvelopeBytes < 1 || member.EnvelopeBytes > maxEnvelopeBytes || member.EnvelopeBytes > limit-offset {
			return zero, ErrContainer
		}
		offset += member.EnvelopeBytes
		seen[member.Part], paths[member.CipherPath], paths[member.EnvelopePath] = true, true, true
		var checkpoint b.Checkpoint
		if len(member.Checkpoint) == 0 || len(member.Checkpoint) > 8192 || json.Unmarshal(member.Checkpoint, &checkpoint) != nil || checkpoint.SchemaVersion != "system-backup-b-checkpoint.v1" || checkpoint.InstallationID != s.Installation || checkpoint.TaskPublicID != s.Backup || checkpoint.ConfigVersion != s.ConfigVersion || checkpoint.ConfigSHA256 != s.ConfigSHA256 || checkpoint.AttemptNo != s.Attempt || checkpoint.Phase != "capture" || checkpoint.Part != member.Part || checkpoint.InventorySHA256 != header.SourceInventorySHA256 || checkpoint.ContentSHA256 != member.CipherSHA256 || !digest.MatchString(checkpoint.InvocationSHA256) || checkpoint.JobUID == "" || len(checkpoint.JobUID) > 256 || checkpoint.JobGeneration < 1 || checkpoint.JobGeneration > 9007199254740991 || checkpoint.SealedRef == "" || len(checkpoint.SealedRef) > 1024 {
			return zero, ErrContainer
		}
		raw, err := json.Marshal(checkpoint)
		if err != nil || !bytes.Equal(raw, member.Checkpoint) {
			return zero, ErrContainer
		}
		canonicalCheckpoint, err := canonical(json.RawMessage(member.Checkpoint))
		checkpointSHA := checksum(canonicalCheckpoint)
		if err != nil || checkpoints[member.Part] != checkpointSHA || !digest.MatchString(checkpointSHA) {
			return zero, ErrContainer
		}
		result.CipherBytes += member.CipherBytes
		result.EnvelopeBytes += member.EnvelopeBytes
		result.Locations = append(result.Locations, MemberLocation{Part: member.Part, Index: member.Index, CipherOffset: member.CipherOffset, CipherBytes: member.CipherBytes, EnvelopeOffset: member.EnvelopeOffset, EnvelopeBytes: member.EnvelopeBytes, CipherSHA256: member.CipherSHA256, EnvelopeSHA256: member.EnvelopeSHA256, CheckpointSHA256: checkpointSHA})
	}
	result.Size = offset
	return result, nil
}

func requestedPartForName(part string) string {
	for _, name := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		if part == name {
			return name
		}
	}
	return ""
}
