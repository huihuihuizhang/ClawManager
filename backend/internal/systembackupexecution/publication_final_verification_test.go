package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Frozen descriptor DATA only; no C/cleanup/current authorization receipt is
// manufactured by these structural regressions.
func TestPublicationFinalVerificationFrozenSourceAndMemberJoins(t *testing.T) {
	_, source, _, _, _ := productionModuleFixture(t)
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := finalVerificationFrozenSource(raw, hash(raw))
	if err != nil {
		t.Fatal("original frozen source", err)
	}
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("metadata fixture")
	}
	sql := c.PublisherCaptureRecord{Invocation: worker.Invocation{Request: worker.Request{Database: &worker.DatabaseSpec{Name: source.Database, ServerUUID: source.ServerUUID, TeamsInventory: source.Teams, SkillsInventory: source.Skills}}}}
	objects := c.PublisherCaptureRecord{Invocation: worker.Invocation{Request: worker.Request{SkillObjects: &metadata.Skills}}}
	if finalVerificationMemberSource(frozen, publicationVerifiedPart{Part: b.UsersInstancesDatabasePart, Operation: "capture-database"}, sql) != nil || finalVerificationMemberSource(frozen, publicationVerifiedPart{Part: b.SkillObjectsPart, Operation: "capture-skill-objects"}, objects) != nil {
		t.Fatal("original SQL/object joins rejected")
	}
	for _, mode := range []string{"source-hash", "source-nil-teams", "source-nil-skills", "sql-nil-teams", "sql-nil-skills", "object-inventory", "object-blob-omitted"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "source-hash" {
				if _, err := finalVerificationFrozenSource(raw, hash([]byte("other source DATA"))); err == nil {
					t.Fatal("wrong source digest")
				}
				return
			}
			if mode == "source-nil-teams" || mode == "source-nil-skills" {
				changed := source
				if mode == "source-nil-teams" {
					changed.Teams = nil
				} else {
					changed.Skills = nil
				}
				body, _ := json.Marshal(changed)
				if _, err := finalVerificationFrozenSource(body, hash(body)); err == nil {
					t.Fatal("missing inventory")
				}
				return
			}
			if mode == "sql-nil-teams" || mode == "sql-nil-skills" {
				changed := sql
				spec := *sql.Invocation.Request.Database
				changed.Invocation.Request.Database = &spec
				if mode == "sql-nil-teams" {
					spec.TeamsInventory = nil
				} else {
					spec.SkillsInventory = nil
				}
				if finalVerificationMemberSource(frozen, publicationVerifiedPart{Part: b.UsersInstancesDatabasePart, Operation: "capture-database"}, changed) == nil {
					t.Fatal("missing SQL inventory accepted")
				}
				return
			}
			changed := objects
			spec := *objects.Invocation.Request.SkillObjects
			changed.Invocation.Request.SkillObjects = &spec
			if mode == "object-inventory" {
				spec.InventorySHA256 = hash([]byte("wrong inventory DATA"))
			} else {
				spec.Blobs = nil
			}
			if finalVerificationMemberSource(frozen, publicationVerifiedPart{Part: b.SkillObjectsPart, Operation: "capture-skill-objects"}, changed) == nil {
				t.Fatal("mismatched object inventory accepted")
			}
		})
	}
}

func TestPublicationFinalVerificationRequiresActualCompleteProducer(t *testing.T) {
	ctx := context.Background()
	for _, cleanup := range []*publicationCompleteCleanup{nil, {}, {native: &publicationNativeCleanup{done: true}}} {
		if _, err := finalVerificationOriginalSHA(cleanup); err == nil {
			t.Fatal("incomplete cleanup manufactured history")
		}
		var s *DeploymentService
		if result, err := s.verifyOriginalPublicationFinalization(ctx, nil, c.LeasePolicy{}, cleanup); err == nil || result != nil {
			t.Fatal("missing actual cleanup/current claim accepted")
		}
	}
	for _, proof := range []*publicationFinalVerification{nil, {}, {originalSHA256: hash([]byte("named incomplete DATA"))}} {
		if err := proof.recheckVerifiedTx(ctx, nil); err == nil {
			t.Fatal("history-only handle manufactured full-read proof")
		}
	}
}

func TestPublicationFinalVerificationComparisonDigestIsNotFinalStamp(t *testing.T) {
	// Named comparison DATA only: content checksums and an allocated authority
	// cannot replace actual cleanup and the authenticated relation producer.
	p := &publicationFinalVerification{access: &security.SQLPublisherCaptureAuthority{}, originalSHA256: hash([]byte("original comparison DATA")), manifest: []byte("{}"), marker: []byte("{}"), index: []byte("{}")}
	p.manifestObject.SHA256 = hash(p.manifest)
	p.markerObject.SHA256 = hash(p.marker)
	if _, err := p.contentSHA(); err == nil {
		t.Fatal("comparison checksums manufactured a producer-bound digest")
	}
	if p.verifiedSHA256 != "" {
		t.Fatal("comparison minted final stamp")
	}
	if err := p.recheckVerifiedTx(context.Background(), nil); err == nil {
		t.Fatal("incomplete member relations admitted to final consumer")
	}
}
