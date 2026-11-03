package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	sh "clawreef/internal/systembackupskillhub"
)

// Private business metadata, never a restore/acceptance assertion. All object
// bodies are discarded before the authenticated outer callback returns.
type SkillContentReport struct {
	Version, Scope, InventorySHA256, ObjectIndexSHA256 string
	SampleAvailable                                    bool
	Sample                                             *sh.RestoreSample
}
type publicationFinalSkillReport struct {
	input                      sh.RestoreSampleInput
	pending, confirmed, failed bool
	index                      string
	report                     SkillContentReport
}

func newPublicationFinalSkillReport(source b.SourceInventory) *publicationFinalSkillReport {
	s := &publicationFinalSkillReport{input: sh.RestoreSampleInput{Users: map[int]bool{}, InstanceOwners: map[int]int{}}}
	inventory := sh.CloneCaptureInventory(source.Skills)
	if inventory == nil {
		s.failed = true
		return s
	}
	s.input.Inventory = *inventory
	for _, id := range source.Users {
		s.input.Users[id] = true
	}
	for _, v := range source.Instances {
		s.input.InstanceOwners[v.ID] = v.UserID
	}
	return s
}
func (s *publicationFinalSkillReport) read(ctx context.Context, i worker.Invocation, src io.Reader, counts *ownedPayloadCounts) error {
	if s == nil || s.failed || s.pending || s.confirmed || i.Request.SkillObjects == nil || counts == nil {
		return c.ErrExecutionRecord
	}
	spec := i.Request.SkillObjects
	if spec.InventorySHA256 != s.input.Inventory.SHA256() {
		return c.ErrExecutionRecord
	}
	invocation, err := i.Hash()
	if err != nil {
		return err
	}
	header, err := json.Marshal(struct {
		Version, InvocationSHA256 string
		Spec                      worker.SkillObjectCaptureSpec
	}{worker.SkillObjectCaptureVersion, invocation, *spec})
	if err != nil {
		return err
	}
	limits := sh.ObjectCaptureLimits{MaxObjects: spec.MaxObjects, MaxObjectBytes: spec.MaxObjectBytes, MaxTotalBytes: spec.MaxTotalBytes, MaxIndexBytes: spec.MaxIndexBytes}
	payload, err := sh.ReadSkillObjectArchive(ctx, src, sh.SkillArchiveReadSpec{ExpectedHeaderJSON: header, Inventory: s.input.Inventory, Users: s.input.Users, InstanceOwners: s.input.InstanceOwners, Objects: spec.Objects, Limits: limits, MaxArchiveBytes: i.Request.MaxArchiveBytes})
	if err != nil {
		return err
	}
	defer payload.Clear()
	// Tentative only. The outer AEAD/EOF/current check MUST call confirm later.
	raw, err := json.Marshal(struct {
		Objects  []sh.FrozenObject
		Captured []sh.CapturedObject
	}{payload.Plan.Objects, payload.Captured})
	if err != nil {
		return err
	}
	var copy struct {
		Objects  []sh.FrozenObject
		Captured []sh.CapturedObject
	}
	if json.Unmarshal(raw, &copy) != nil {
		return c.ErrExecutionRecord
	}
	s.input.Objects, s.input.Captured, s.input.ObjectLimits = copy.Objects, copy.Captured, limits
	s.index = payload.IndexSHA256
	s.pending = true
	counts.Items = int64(len(payload.Captured))
	for _, item := range payload.Captured {
		counts.ContentBytes += item.Digest.Size
	}
	return nil
}
func (s *publicationFinalSkillReport) confirm(ctx context.Context) error {
	if s == nil || s.failed || !s.pending || s.confirmed {
		return c.ErrExecutionRecord
	}
	sample, err := sh.SelectRestoreSample(ctx, s.input)
	report := SkillContentReport{Version: "system-backup-skill-content-report.v1", Scope: "same_authenticated_final_read_only_not_restore", InventorySHA256: s.input.Inventory.SHA256(), ObjectIndexSHA256: s.index}
	if err != nil && !errors.Is(err, sh.ErrRestoreSampleUnavailable) {
		return err
	}
	if err == nil {
		if sample.ObjectIndexSHA256 != s.index || sample.InventorySHA256 != report.InventorySHA256 {
			return c.ErrExecutionRecord
		}
		report.SampleAvailable = true
		report.Sample = &sample
	}
	s.report = report
	s.confirmed = true
	s.pending = false
	return nil
}
func (s *publicationFinalSkillReport) snapshot() (SkillContentReport, string, error) {
	if s == nil || s.failed || s.pending || !s.confirmed {
		return SkillContentReport{}, "", c.ErrExecutionRecord
	}
	raw, err := ce.Canonical(s.report)
	if err != nil {
		return SkillContentReport{}, "", err
	}
	var detached SkillContentReport
	if json.Unmarshal(raw, &detached) != nil {
		return SkillContentReport{}, "", c.ErrExecutionRecord
	}
	return detached, hash(raw), nil
}

// Both domains are generated on the SAME real Ready. This is a private report
// outlet, not a new HTTP route, database kind, public manifest or success flag.
type BusinessContentReport struct {
	Version, Scope    string
	AuthenticatedRead publicationContentSampleReport
	Teams             TeamContentReport
	Skills            SkillContentReport
}

func (p *publicationTerminalReady) businessContentReport() (BusinessContentReport, error) {
	var zero BusinessContentReport
	read, err := p.ContentSamples()
	if err != nil {
		return zero, err
	}
	team, err := p.TeamContentSamples()
	if err != nil {
		return zero, err
	}
	proof := decisionRegisteredProof(p.decision.registered)
	skill, digest, err := proof.contentSamples.skills.snapshot()
	if err != nil || digest != read.SkillsSelectionSHA256 || skill.InventorySHA256 != read.SkillsInventorySHA256 {
		return zero, c.ErrExecutionRecord
	}
	return BusinessContentReport{"system-backup-business-content-report.v1", "private_same_ready_not_acceptance_or_restore", read, team, skill}, nil
}

// The opaque Ready producer has already rechecked original authority. Export
// rechecks that SAME current publisher scope and SQL Ready immediately before
// emitting to the coordinator's explicitly selected private writer. No stdout,
// path, caller JSON, background callback or task reenactment is installed.
func (p *publicationTerminalReady) WriteBusinessContentReport(ctx context.Context, dst io.Writer) error {
	if p == nil || p.decision == nil || dst == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	proof := decisionRegisteredProof(p.decision.registered)
	if proof == nil || proof.access == nil || proof.access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	tx, err := proof.service.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = p.recheckTx(ctx, tx); err != nil {
		return err
	}
	report, err := p.businessContentReport()
	if err != nil {
		return err
	}
	raw, err := ce.Canonical(report)
	if err != nil {
		return err
	}
	if len(p.businessReport) == 0 || hash(raw) != hash(p.businessReport) {
		return c.ErrExecutionRecord
	}
	if err = tx.Rollback(); err != nil {
		return err
	}
	if err = proof.access.Check(ctx); err != nil {
		return err
	}
	n, err := dst.Write(append(raw, '\n'))
	if err == nil && n != len(raw)+1 {
		return io.ErrShortWrite
	}
	return err
}
