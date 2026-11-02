package systembackupexecution

import (
	"testing"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	pc "clawreef/internal/systembackuppartcontainer"
)

// Comparison DATA only. These tests do not create an authenticated remote
// receipt, final verification, source-recovery proof or terminal Ready.
func publicationContentSampleData() (*publicationContentSamples, worker.Invocation, ArtifactReadObject, pc.Member, pc.MemberLocation, ownedPayloadCounts) {
	i := worker.Invocation{Request: worker.Request{Operation: "capture-database", Binding: staging.Binding{BackupID: "task-data", Path: "users_instances_database"}}}
	invocation, _ := i.Hash()
	counts := ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Kind: "sql_raw_cell_bytes", Complete: true, Items: 1, ContentBytes: 17, SQLTables: []ownedSQLTableCount{{Table: "teams", Rows: 1, CellBytes: 17}}}
	member := pc.Member{Part: i.Request.Binding.Path, Operation: i.Request.Operation, Index: 2, CipherBytes: 128, EnvelopeOffset: 128, EnvelopeBytes: 10, CipherSHA256: hash([]byte("original C DATA")), EnvelopeSHA256: hash([]byte("original E DATA")), Checkpoint: []byte(`{}`)}
	checkpoint, _ := pcCheckpointSHA(member.Checkpoint)
	object := ArtifactReadObject{Key: "installation/task-data/1/parts/mysql/container.enc", Version: "original-version", SHA256: hash([]byte("complete container DATA")), Size: 2048}
	location := pc.MemberLocation{Part: member.Part, Index: member.Index, ObjectVersion: object.Version, CipherOffset: 1024, CipherBytes: 128, EnvelopeOffset: 1152, EnvelopeBytes: 10, CipherSHA256: member.CipherSHA256, EnvelopeSHA256: member.EnvelopeSHA256, CheckpointSHA256: checkpoint}
	part := publicationVerifiedPart{Part: member.Part, RequestedPart: "mysql", Operation: member.Operation, Index: member.Index, InvocationSHA256: invocation, CipherSHA256: member.CipherSHA256, EnvelopeSHA256: member.EnvelopeSHA256, Counts: counts}
	p := &publicationContentSamples{report: publicationContentSampleReport{Version: "system-backup-final-content-observations.v1", Backup: "task-data", Manifest: ArtifactReadObject{Key: "original/manifest.json", Version: "manifest-version", SHA256: hash([]byte("manifest DATA")), Size: 64}}, expected: map[string]publicationVerifiedPart{part.Part: part}, observed: map[string]publicationContentMemberSample{}}
	return p, i, object, member, location, counts
}

func TestPublicationContentSampleBindsActualCountsAndAbsoluteOriginalRange(t *testing.T) {
	p, i, object, member, location, counts := publicationContentSampleData()
	if _, _, err := p.snapshot(); err == nil {
		t.Fatal("unconfirmed member reported")
	}
	if err := p.confirm(i, object, member, location, counts); err != nil {
		t.Fatal("original absolute remote range", err)
	}
	report, digest, err := p.snapshot()
	if err != nil || !formalCandidateDigest(digest) || len(report.Members) != 1 || report.Members[0].Container != object || report.Members[0].Member != location || report.Members[0].Counts.SQLTables[0].Rows != 1 {
		t.Fatal("fixed-version final observation lost", err)
	}
	report.Members[0].Counts.SQLTables[0].Rows++
	counts.SQLTables[0].CellBytes++
	_, unchanged, err := p.snapshot()
	if err != nil || unchanged != digest {
		t.Fatal("report retained caller aliases", err)
	}
	p.clear()
	if _, _, err := p.snapshot(); err == nil {
		t.Fatal("failed round retained observations")
	}
}

func TestPublicationContentSampleRejectsDriftAndClearsPartialRound(t *testing.T) {
	for _, mode := range []string{"counts", "version", "range", "invocation", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p, i, object, member, location, counts := publicationContentSampleData()
			switch mode {
			case "counts":
				counts.ContentBytes++
			case "version":
				object.Version = "different-original-version"
			case "range":
				location.EnvelopeOffset++
			case "invocation":
				i.Request.Binding.BackupID = "other-task"
			case "duplicate":
				if err := p.confirm(i, object, member, location, counts); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.confirm(i, object, member, location, counts); err == nil {
				t.Fatal("drift accepted", mode)
			}
			if report, _, err := p.snapshot(); err == nil || len(report.Members) != 0 {
				t.Fatal("partial failed round escaped", mode)
			}
		})
	}
}
