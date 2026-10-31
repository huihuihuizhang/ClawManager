package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
)

func TestProductionFinalizationSeedUsesCompleteUnchangedSourceAndActualBusinessInvocations(t *testing.T) {
	in, source, hold, writers, operations := productionModuleFixture(t)
	writers = append(writers, b.FrozenWriter{ID: "another-original-writer", Original: flow.State{UID: "another-original-writer-uid", Generation: 2, Running: false, Checkpoint: "another-original-checkpoint"}})
	before, _ := json.Marshal(source)
	modules, err := productionCaptureModules(in, source, hold, writers, operations, "owned-source-r1")
	if err != nil {
		t.Fatal(err)
	}
	parts, err := modules.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(source)
	if !bytes.Equal(before, after) {
		t.Fatal("finalization was written into source/context input")
	}
	var metadata productionCaptureMetadata
	if decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.ControlEvidence.Finalization != nil || metadata.ControlEvidence.Version != "system-backup-control-evidence-source.v1" {
		t.Fatal("source ceased to pin the exact original base locator")
	}
	point, err := productionModuleContext(in, source, hold, writers, "")
	if err != nil || point.InventorySHA256 != hash(before) {
		t.Fatal("context resolver did not authenticate complete original Source bytes", err)
	}
	discovery := b.Discovery{Source: before, SourceSHA256: hash(before), Parts: parts, Writers: writers, HoldUntil: hold}
	if err := validateProductionControlSeeds(in, source, metadata, discovery); err != nil {
		t.Fatal("exact actual source/seed binding", err)
	}
	policy, err := productionFinalizationPolicy(point.CaptureContextSHA256, parts)
	if err != nil || len(policy.Parts) != len(parts)-2 {
		t.Fatal("complete actual business set", err)
	}
	var prior *ce.CaptureLocator
	for _, part := range parts {
		var invocation worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &invocation) != nil {
			t.Fatal("invocation")
		}
		if invocation.Request.ControlEvidence != nil {
			seed := invocation.Request.ControlEvidence
			base, err := seed.BaseSnapshot()
			if err != nil || !reflect.DeepEqual(base, metadata.ControlEvidence) || seed.Finalization == nil || !reflect.DeepEqual(*seed.Finalization, policy) {
				t.Fatal("CE seed lost base/context/exact business set", err)
			}
			if prior != nil && !reflect.DeepEqual(prior, seed) {
				t.Fatal("paired CE seeds differ")
			}
			prior = seed
			continue
		}
		if part.Part == b.UsersInstancesDatabasePart && (invocation.Request.Database.TeamsInventory == nil || invocation.Request.Database.SkillsInventory == nil || invocation.Request.Database.TeamsInventory.SHA256() != source.Teams.SHA256() || invocation.Request.Database.SkillsInventory.SHA256() != source.Skills.SHA256()) {
			t.Fatal("seed was made before original SQL constructor added Teams/Skills")
		}
	}
	if prior == nil {
		t.Fatal("missing paired CE seed")
	}
	var seededMetadata productionCaptureMetadata
	json.Unmarshal(source.CaptureMetadata, &seededMetadata)
	seededMetadata.ControlEvidence = *prior
	seededSource := source
	seededSource.CaptureMetadata, _ = json.Marshal(seededMetadata)
	if _, err := productionCaptureModules(in, seededSource, hold, writers, operations, "owned-source-r1"); err == nil {
		t.Fatal("factory accepted a V2 locator in full Source and created a context cycle")
	}
	for _, fault := range []string{"base-hash", "context", "checks-version", "part-hash", "part-operation", "missing-policy-part", "extra-policy-part", "missing-business-part", "business-invocation-drift", "source-drift", "writer-drift", "hold-drift", "v1-invocation"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := json.Marshal(discovery)
			var changed b.Discovery
			json.Unmarshal(raw, &changed)
			actualSource := source
			if fault == "source-drift" {
				var changedMetadata productionCaptureMetadata
				json.Unmarshal(source.CaptureMetadata, &changedMetadata)
				changedMetadata.Secrets.MaxItems++
				actualSource.CaptureMetadata, _ = json.Marshal(changedMetadata)
			}
			if fault == "writer-drift" {
				changed.Writers[0].Original.Checkpoint = "another original checkpoint"
			}
			if fault == "hold-drift" {
				changed.HoldUntil = changed.HoldUntil.Add(-1)
			}
			if fault == "missing-business-part" {
				changed.Parts = changed.Parts[:len(changed.Parts)-1]
			}
			for index := range changed.Parts {
				part := &changed.Parts[index]
				var invocation worker.Invocation
				json.Unmarshal(part.InvocationJSON, &invocation)
				if invocation.Request.ControlEvidence == nil {
					if fault == "business-invocation-drift" && part.Part == b.UsersInstancesDatabasePart {
						invocation.Request.Database.MaxRows--
						part.InvocationJSON, _ = json.Marshal(invocation)
						part.InvocationSHA256 = hash(part.InvocationJSON)
					}
					continue
				}
				seed := invocation.Request.ControlEvidence
				switch fault {
				case "base-hash":
					seed.SidecarSHA256 = strings.Repeat("0", 64)
				case "context":
					seed.Finalization.CaptureContextSHA256 = strings.Repeat("0", 64)
				case "checks-version":
					seed.Finalization.ChecksVersion = "foreign-owned-check-policy"
				case "part-hash":
					seed.Finalization.Parts[0].InvocationSHA256 = strings.Repeat("0", 64)
				case "part-operation":
					seed.Finalization.Parts[0].Operation = "capture-workspace"
				case "missing-policy-part":
					seed.Finalization.Parts = seed.Finalization.Parts[1:]
				case "extra-policy-part":
					seed.Finalization.Parts = append(seed.Finalization.Parts, ce.FinalizationPart{Part: "zz_foreign", Operation: "capture-workspace", InvocationSHA256: strings.Repeat("0", 64)})
				case "v1-invocation":
					base, err := seed.BaseSnapshot()
					if err != nil {
						t.Fatal(err)
					}
					invocation.Request.ControlEvidence = &base
				}
				part.InvocationJSON, _ = json.Marshal(invocation)
				part.InvocationSHA256 = hash(part.InvocationJSON)
			}
			if err := validateProductionControlSeeds(in, actualSource, metadata, changed); err == nil {
				t.Fatal("changed original source/policy/business set accepted", fault)
			}
		})
	}
	// Context canonicalizes the SAME complete writer set, while inventory SHA
	// always remains the digest of the full original Source, without exclusions.
	reordered := append([]b.FrozenWriter{}, writers...)
	sort.Slice(reordered, func(i, j int) bool { return reordered[i].ID > reordered[j].ID })
	other, err := productionModuleContext(in, source, hold, reordered, "")
	if err != nil || other.CaptureContextSHA256 != point.CaptureContextSHA256 || other.InventorySHA256 != hash(before) {
		t.Fatal("original context ordering/source binding changed", err)
	}
}
