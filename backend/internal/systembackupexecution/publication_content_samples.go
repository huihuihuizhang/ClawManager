package systembackupexecution

import (
	"sort"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
)

// Redacted observations of the ACTUAL final remote read, not source row-count
// estimates. Exact container versions/member ranges locate the bytes whose
// complete business parser, AEAD/EOF and current authority checks succeeded.
// No SQL cells, Redis keys/dumps, object bodies or workspace names are retained.
type publicationContentMemberSample struct {
	Part, RequestedPart, Operation, InvocationSHA256 string
	Container                                        ArtifactReadObject
	Member                                           pc.MemberLocation
	Counts                                           ownedPayloadCounts
}

type publicationContentSampleReport struct {
	ArtifactReadIdentitySHA256                  string
	Version, Installation, Backup, SourceSHA256 string
	TeamsInventorySHA256, SkillsInventorySHA256 string
	Attempt                                     uint64
	Manifest                                    ArtifactReadObject
	Members                                     []publicationContentMemberSample
}

// Private to one final verification round. The existing inert parser remains
// the single semantic parser; these observations are confirmed only AFTER its
// surrounding full authenticated remote stream and current recheck complete.
type publicationContentSamples struct {
	report   publicationContentSampleReport
	expected map[string]publicationVerifiedPart
	observed map[string]publicationContentMemberSample
	failed   bool
}

func newPublicationContentSamples(capture publicationVerifiedCapture, source b.SourceInventory, target PublicationTargetMaterials, manifest ArtifactReadObject) (*publicationContentSamples, error) {
	if !capture.checked() || source.Teams == nil || source.Skills == nil || target.InstallationID != capture.Input.InstallationID || !formalCandidateDigest(target.ReadIdentityHash) || !formalCandidateDigest(manifest.SHA256) || !fixedPublicationReadVersion(manifest.Version) {
		return nil, c.ErrExecutionRecord
	}
	p := &publicationContentSamples{report: publicationContentSampleReport{Version: "system-backup-final-content-observations.v1", Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, SourceSHA256: capture.Input.SourceSHA256, TeamsInventorySHA256: source.Teams.SHA256(), SkillsInventorySHA256: source.Skills.SHA256(), Manifest: manifest}, expected: map[string]publicationVerifiedPart{}, observed: map[string]publicationContentMemberSample{}}
	p.report.ArtifactReadIdentitySHA256 = target.ReadIdentityHash
	for _, part := range capture.Parts {
		if part.RequestedPart == "" {
			continue // Independently authenticated administrative members.
		}
		if part.Part == "" || p.expected[part.Part].Part != "" || !part.Counts.Complete {
			return nil, c.ErrExecutionRecord
		}
		p.expected[part.Part] = part
	}
	if len(p.expected) < len(publicationRequestedParts) {
		return nil, c.ErrExecutionRecord
	}
	return p, nil
}

func (p *publicationContentSamples) clear() {
	if p != nil {
		p.report = publicationContentSampleReport{}
		p.expected, p.observed, p.failed = nil, nil, true
	}
}

func (p *publicationContentSamples) confirm(i worker.Invocation, object ArtifactReadObject, member pc.Member, location pc.MemberLocation, counts ownedPayloadCounts) error {
	if p == nil || p.failed {
		return c.ErrExecutionRecord
	}
	part, ok := p.expected[member.Part]
	invocation, err := i.Hash()
	checkpoint, checkpointErr := pcCheckpointSHA(member.Checkpoint)
	want, wantErr := ce.Canonical(part.Counts)
	actual, actualErr := ce.Canonical(counts)
	// Header members use body-relative offsets; Inspect's fixed-version ranges
	// include the outer prefix/header. Both ranges must have the SAME shift.
	offset := location.CipherOffset - member.CipherOffset
	if !ok || err != nil || checkpointErr != nil || wantErr != nil || actualErr != nil || hash(want) != hash(actual) || !counts.Complete || p.observed[member.Part].Part != "" || part.InvocationSHA256 != invocation || i.Request.Binding.BackupID != p.report.Backup || i.Request.Binding.Path != member.Part || part.Operation != member.Operation || part.Index != member.Index || part.CipherSHA256 != member.CipherSHA256 || part.EnvelopeSHA256 != member.EnvelopeSHA256 || location.Part != member.Part || location.Index != member.Index || location.ObjectVersion != object.Version || location.CipherSHA256 != member.CipherSHA256 || location.EnvelopeSHA256 != member.EnvelopeSHA256 || location.CheckpointSHA256 != checkpoint || offset < 12 || offset >= object.Size || location.CipherOffset < offset || location.CipherOffset >= object.Size || location.CipherBytes < 1 || location.CipherBytes > object.Size-location.CipherOffset || location.CipherBytes != member.CipherBytes || location.EnvelopeOffset < member.EnvelopeOffset || location.EnvelopeOffset-member.EnvelopeOffset != offset || location.EnvelopeOffset >= object.Size || location.EnvelopeBytes < 1 || location.EnvelopeBytes > object.Size-location.EnvelopeOffset || location.EnvelopeBytes != member.EnvelopeBytes || !formalCandidateDigest(object.SHA256) || !fixedPublicationReadVersion(object.Version) {
		p.clear()
		return c.ErrExecutionRecord
	}
	counts.SQLTables = append([]ownedSQLTableCount(nil), counts.SQLTables...)
	if counts.SecretPolicy != nil {
		copy := *counts.SecretPolicy
		counts.SecretPolicy = &copy
	}
	p.observed[member.Part] = publicationContentMemberSample{Part: member.Part, RequestedPart: part.RequestedPart, Operation: member.Operation, InvocationSHA256: invocation, Container: object, Member: location, Counts: counts}
	return nil
}

func (p *publicationContentSamples) snapshot() (publicationContentSampleReport, string, error) {
	if p == nil || p.failed || len(p.expected) == 0 || len(p.expected) != len(p.observed) {
		return publicationContentSampleReport{}, "", c.ErrExecutionRecord
	}
	report := p.report
	for name := range p.expected {
		observed, ok := p.observed[name]
		if !ok {
			return publicationContentSampleReport{}, "", c.ErrExecutionRecord
		}
		observed.Counts.SQLTables = append([]ownedSQLTableCount(nil), observed.Counts.SQLTables...)
		if observed.Counts.SecretPolicy != nil {
			copy := *observed.Counts.SecretPolicy
			observed.Counts.SecretPolicy = &copy
		}
		report.Members = append(report.Members, observed)
	}
	sort.Slice(report.Members, func(i, j int) bool { return report.Members[i].Part < report.Members[j].Part })
	raw, err := ce.Canonical(report)
	if err != nil {
		return publicationContentSampleReport{}, "", err
	}
	return report, hash(raw), nil
}
