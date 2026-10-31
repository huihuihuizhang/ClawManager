package systembackupcontrolevidence

import (
	"bytes"
	"encoding/json"
)

const registeredJSONChunkBytes = 5600

// Original inline evidence still caps EVERY body at 8192 bytes. Locator/seed
// metadata is transported by a complete content-addressed bounded chunk set;
// neither a truncated basis nor a larger inline column is permitted.
type RegisteredJSON struct {
	Kind   string        `json:"kind"`
	SHA256 string        `json:"sha256"`
	Bytes  uint64        `json:"bytes"`
	Chunks []EvidenceRef `json:"chunks"`
}

type registeredJSONChunk struct {
	Version string `json:"schema_version"`
	Scope
	Kind   string `json:"kind"`
	SHA256 string `json:"complete_sha256"`
	Index  uint32 `json:"chunk_index"`
	Count  uint32 `json:"chunk_count"`
	Data   []byte `json:"data"`
}

func proposeRegisteredJSON(scope Scope, kind string, raw []byte) (RegisteredJSON, []RegisteredEvidence, error) {
	if !ValidScope(scope) || kind != "original-source-seed" && kind != "final-source-locator" || len(raw) < 2 || len(raw) > MaxBytes {
		return RegisteredJSON{}, nil, ErrCapacity
	}
	canonical, err := Canonical(json.RawMessage(raw))
	if err != nil || !bytes.Equal(canonical, raw) {
		return RegisteredJSON{}, nil, ErrInvalid
	}
	descriptor := RegisteredJSON{Kind: kind, SHA256: SHA256(raw), Bytes: uint64(len(raw)), Chunks: []EvidenceRef{}}
	count := (len(raw) + registeredJSONChunkBytes - 1) / registeredJSONChunkBytes
	entries := []RegisteredEvidence{}
	for index := 0; index < count; index++ {
		end := (index + 1) * registeredJSONChunkBytes
		if end > len(raw) {
			end = len(raw)
		}
		chunk := registeredJSONChunk{Version: "system-backup-control-registered-json-chunk.v1", Scope: scope, Kind: kind, SHA256: descriptor.SHA256, Index: uint32(index), Count: uint32(count), Data: raw[index*registeredJSONChunkBytes : end]}
		entry, err := registered(scope, chunk)
		if err != nil {
			return RegisteredJSON{}, nil, ErrCapacity
		}
		entries = append(entries, entry)
		descriptor.Chunks = append(descriptor.Chunks, reference(entry))
	}
	return descriptor, entries, nil
}

func readRegisteredJSON(scope Scope, descriptor RegisteredJSON, entries map[string]RegisteredEvidence) ([]byte, error) {
	if descriptor.Kind != "original-source-seed" && descriptor.Kind != "final-source-locator" || !digestPattern.MatchString(descriptor.SHA256) || descriptor.Bytes < 2 || descriptor.Bytes > MaxBytes || len(descriptor.Chunks) != (int(descriptor.Bytes)+registeredJSONChunkBytes-1)/registeredJSONChunkBytes {
		return nil, ErrInvalid
	}
	raw := make([]byte, 0, int(descriptor.Bytes))
	for index, ref := range descriptor.Chunks {
		entry, ok := entries[ref.PublicID]
		var chunk registeredJSONChunk
		if !ok || reference(entry) != ref || entry.OwnerType != "backup" || entry.OwnerID != scope.Backup || entry.Type != "verifier_report" || SHA256(entry.Payload) != ref.SHA256 || closed(entry.Payload, &chunk) != nil || chunk.Version != "system-backup-control-registered-json-chunk.v1" || chunk.Scope != scope || chunk.Kind != descriptor.Kind || chunk.SHA256 != descriptor.SHA256 || chunk.Index != uint32(index) || chunk.Count != uint32(len(descriptor.Chunks)) || len(chunk.Data) < 1 || len(chunk.Data) > registeredJSONChunkBytes || index < len(descriptor.Chunks)-1 && len(chunk.Data) != registeredJSONChunkBytes {
			return nil, ErrInvalid
		}
		raw = append(raw, chunk.Data...)
	}
	if uint64(len(raw)) != descriptor.Bytes || SHA256(raw) != descriptor.SHA256 {
		return nil, ErrInvalid
	}
	canonical, err := Canonical(json.RawMessage(raw))
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrInvalid
	}
	return raw, nil
}
