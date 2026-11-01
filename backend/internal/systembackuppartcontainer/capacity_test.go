package systembackuppartcontainer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	w "clawreef/internal/systembackupwire"
)

// Declared-layout arithmetic DATA only, never a claim to have generated or
// verified huge C bytes. No multi-GiB allocation, read or source authority.
func layoutData(t *testing.T, cipherBytes int64) (Scope, Header, map[string]string) {
	t.Helper()
	scope, source, inputs, _, _ := containerData(t)
	header := Header{Version: Version, Scope: scope, SourceInventorySHA256: source}
	checkpoints := map[string]string{}
	var offset int64
	for index := 0; cipherBytes > 0; index++ {
		member := inputs[0].Member
		member.Part = fmt.Sprintf("layout_workspace_DATA_%d", index)
		member.Index = uint32(index)
		member.Stream.Request.Context.Part = member.Part
		member.Stream.Request.Context.PartIndex = fmt.Sprint(index)
		member.Stream.MaxFrames = w.MaxStreamFrames
		member.Stream.MaxPlaintextBytes = int64(w.MaxStreamFrames-1) * w.ChunkSize
		member.CipherPath = fmt.Sprintf("parts/%d/layout.enc", index)
		member.EnvelopePath = fmt.Sprintf("parts/%d/layout.envelope.json", index)
		member.CipherBytes = 60 << 30
		if cipherBytes < member.CipherBytes {
			member.CipherBytes = cipherBytes
		}
		cipherBytes -= member.CipherBytes
		member.CipherOffset = offset
		offset += member.CipherBytes
		member.EnvelopeOffset = offset
		offset += member.EnvelopeBytes
		var checkpoint b.Checkpoint
		json.Unmarshal(member.Checkpoint, &checkpoint)
		checkpoint.Part = member.Part
		member.Checkpoint, _ = json.Marshal(checkpoint)
		canonicalCheckpoint, _ := canonical(json.RawMessage(member.Checkpoint))
		checkpoints[member.Part] = checksum(canonicalCheckpoint)
		header.Members = append(header.Members, member)
	}
	return scope, header, checkpoints
}

func TestContainerLayoutPreservesOriginalV12CapacityRangeData(t *testing.T) {
	for _, limit := range []int64{16 << 30, 900 << 30} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			scope, header, checkpoints := layoutData(t, limit-(2<<20))
			facts, err := validateHeader(header, scope, checkpoints, limit)
			if err != nil || facts.Size <= 8<<30 {
				t.Fatal("valid original configured layout restricted to 8 GiB", err)
			}
			plan, err := planHeader(header, 512<<20)
			if err != nil || facts.Size+plan.Size+prefixBytes > limit {
				t.Fatal("physical overhead exceeds declared artifact budget", err)
			}
			if _, err = validateHeader(header, scope, checkpoints, facts.Size-1); err == nil {
				t.Fatal("actual configured artifact budget ignored")
			}
			if _, err = validateHeader(header, scope, checkpoints, MaxBytes+1); err == nil {
				t.Fatal("original 900 GiB contract maximum ignored")
			}
		})
	}
	if MaxBytes != 966367641600 || MaxIndexBytes != 8589934592 {
		t.Fatal("v12 CapacityConfig maxima drifted")
	}
}

type rejectWriteData struct{ called bool }

func (w *rejectWriteData) Write([]byte) (int, error) {
	w.called = true
	return 0, errors.New("named early sink error DATA")
}

// Proves the real writer admits >8 GiB declared layouts through its config
// gate, then stops at the tiny prefix sink. It never reads/allocates huge C.
func TestContainerWriterUsesConfiguredBudgetBeforeLargeIOData(t *testing.T) {
	scope, source, inputs, checkpoints, _ := containerData(t)
	inputs = inputs[:1]
	delete(checkpoints, "named_workspace_DATA_9")
	inputs[0].Member.CipherBytes = 12 << 30
	for _, mode := range []string{"original-16GiB", "configured-too-small", "contract-overflow"} {
		t.Run(mode, func(t *testing.T) {
			limit := int64(16 << 30)
			if mode == "configured-too-small" {
				limit = 8 << 30
			}
			if mode == "contract-overflow" {
				limit = MaxBytes + 1
			}
			dst := &rejectWriteData{}
			facts, err := Write(context.Background(), dst, scope, source, inputs, checkpoints, limit, 512<<20)
			if err == nil || facts.Size != 0 || facts.SHA256 != "" {
				t.Fatal("early failure returned complete facts")
			}
			if dst.called != (mode == "original-16GiB") {
				t.Fatal("declared config gate used wrong capacity range", dst.called)
			}
		})
	}
}

func TestContainerHeaderStreamsPastEightMiBWithinConfiguredIndexData(t *testing.T) {
	scope, header, checkpoints := layoutData(t, 1)
	template := header.Members[0]
	header.Members = nil
	checkpoints = map[string]string{}
	for index := 0; index < MaxMembers; index++ {
		member := template
		member.Part = fmt.Sprintf("named_header_only_DATA_%d", index)
		member.Index = uint32(index)
		member.Stream.Request.Context.Part = member.Part
		member.Stream.Request.Context.PartIndex = fmt.Sprint(index)
		member.CipherPath = fmt.Sprintf("parts/%d/header.enc", index)
		member.EnvelopePath = fmt.Sprintf("parts/%d/header.envelope.json", index)
		member.CipherOffset = int64(index) * (member.CipherBytes + member.EnvelopeBytes)
		member.EnvelopeOffset = member.CipherOffset + member.CipherBytes
		var checkpoint b.Checkpoint
		json.Unmarshal(member.Checkpoint, &checkpoint)
		checkpoint.Part = member.Part
		member.Checkpoint, _ = json.Marshal(checkpoint)
		canonicalCheckpoint, _ := canonical(json.RawMessage(member.Checkpoint))
		checkpoints[member.Part] = checksum(canonicalCheckpoint)
		header.Members = append(header.Members, member)
	}
	if _, err := validateHeader(header, scope, checkpoints, MaxBytes); err != nil {
		t.Fatal("original maximum part count", err)
	}
	plan, err := planHeader(header, 512<<20)
	if err != nil || plan.Size <= 8<<20 {
		t.Fatal("configured default index budget was silently reduced to 8 MiB", err, plan.Size)
	}
	if _, err = planHeader(header, 1<<20); err == nil {
		t.Fatal("configured 1 MiB index budget ignored")
	}
	var serialized bytes.Buffer
	if err = writeHeader(&serialized, header, plan); err != nil {
		t.Fatal(err)
	}
	parsed, err := readHeader(bytes.NewReader(serialized.Bytes()), plan.Size, 512<<20)
	if err != nil || len(parsed.Members) != MaxMembers {
		t.Fatal("streamed maximum member header", err)
	}
	if _, err = readHeader(bytes.NewReader(serialized.Bytes()), plan.Size, plan.Size-1); err == nil {
		t.Fatal("reader ignored actual index budget")
	}
	if _, err = readHeader(io.LimitReader(bytes.NewReader(serialized.Bytes()), plan.Size-1), plan.Size, 512<<20); err == nil {
		t.Fatal("truncated streamed header admitted")
	}
}
