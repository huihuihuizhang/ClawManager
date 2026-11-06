package systembackupexecution

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"time"

	d "clawreef/internal/systembackupdispatch"
	ma "clawreef/internal/systembackupminioauthority"
)

// Window arithmetic only: this does not authenticate a source or grant
// readiness. The caller obtains both observations through concrete readers.
func runtimeReadinessWindow(started, now, originalUntil time.Time, source SourceDependencyObservation, publisher PublicationDependencyObservation) (time.Time, error) {
	until := originalUntil
	for _, end := range []time.Time{source.until, publisher.until} {
		if end.Before(until) {
			until = end
		}
	}
	if started.IsZero() || now.Before(started) || source.checkedAt.Before(started) || publisher.checkedAt.Before(started) || now.Before(source.checkedAt) || now.Before(publisher.checkedAt) || now.Before(publisher.notBefore) || !now.Before(until) {
		return time.Time{}, d.ErrNotReady
	}
	return until, nil
}

// This is an independent original C permission SOURCE selection, not a mode,
// cached pass or task grant. Only the concrete effective-v2 reader is accepted.
type RuntimeReadinessInput struct {
	Profile string
	Source  MinIOPublicationPermissionInput
}

func RuntimeReadinessInputsFromEnvironment() []RuntimeReadinessInput {
	file, sha := os.Getenv("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_FILE"), os.Getenv("SYSTEM_BACKUP_READINESS_MINIO_SOURCE_SHA256")
	profile := os.Getenv("SYSTEM_BACKUP_READINESS_MINIO_PROFILE")
	if file == "" && sha == "" && profile == "" {
		return nil
	}
	return []RuntimeReadinessInput{{Profile: profile, Source: MinIOPublicationPermissionInput{File: file, SHA256: sha}}}
}

type sixPartRuntimeReadiness struct {
	service         *DeploymentService
	binding         *productionSourceBinding
	permission      RuntimeReadinessInput
	source          SourceDependencyObservation
	publisher       PublicationDependencyObservation
	publisherSHA256 string
	started, until  time.Time
	publishedUntil  time.Time
	sqlFloor        time.Time
}

func runtimeSixParts() []string {
	return []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}
}

func (s *DeploymentService) attachRuntimeReadiness(inputs []RuntimeReadinessInput) error {
	if len(inputs) == 0 {
		return nil // Absent source closes readiness; recovery remains available.
	}
	if len(inputs) != 1 || s == nil || s.Config.CaptureScope != "six-part" {
		return d.ErrNotReady
	}
	if _, err := newRuntimeReadinessPermissionReader(inputs[0]); err != nil {
		return err
	}
	file, sha := os.Getenv("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_FILE"), os.Getenv("SYSTEM_BACKUP_MINIO_RECOVERY_SOURCE_SHA256")
	if file != "" || sha != "" {
		locator := MinIORecoveryProjectionInput{File: file, SHA256: sha}
		descriptor, e := readMinIORecoveryDescriptor(locator)
		if e != nil || descriptor.PermissionSourceFile != inputs[0].Source.File || string(descriptor.PermissionSourceSHA256) != inputs[0].Source.SHA256 || descriptor.PermissionProfile != inputs[0].Profile {
			return d.ErrNotReady
		}
		s.runtimeReadinessRecovery = &locator
	}
	selected := inputs[0]
	s.runtimeReadinessInput = &selected
	return nil
}

func runtimeReadinessSQLTime(ctx context.Context, db *sql.DB) (time.Time, error) {
	if db == nil || ctx == nil || ctx.Err() != nil {
		return time.Time{}, d.ErrNotReady
	}
	var raw any
	if db.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&raw) != nil {
		return time.Time{}, d.ErrNotReady
	}
	return decodeSourceObservationSQLTime(raw)
}

// Concrete taskless ORIGINAL runtime observations only. No fake task, passed
// callback or bootstrap enabled-v1 source is constructed. Actual stopped writers
// require the existing physical witness path; complete all-running/empty sets
// need no invented stopped witness. ObserveSourceDependencies owns completeness.
func (s *DeploymentService) observeSixPartRuntimeReadiness(ctx context.Context) (*sixPartRuntimeReadiness, error) {
	if ctx == nil || s == nil || s.Config.CaptureScope != "six-part" || !s.ForwardEnabled || s.Runtime == nil || s.Runtime.Owner == nil || s.runtimeReadinessInput == nil {
		return nil, d.ErrNotReady
	}
	if _, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil {
		return nil, d.ErrNotReady
	}
	binding := s.Runtime.Owner.productionSource
	if binding == nil || binding.service != s || binding.owner != s.Runtime.Owner || !binding.matchesCapturePlan() {
		return nil, d.ErrNotReady
	}
	x, err := s.newSourceSQLObservation(ctx)
	if err != nil {
		return nil, err
	}
	started, err := runtimeReadinessSQLTime(ctx, x.control)
	if err != nil || started.Before(x.delegation.grant.NotBefore) || !started.Before(x.delegation.until) {
		return nil, d.ErrNotReady
	}
	bounded, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	first, err := s.ObserveSourceDependencies(bounded)
	if err != nil {
		return nil, err
	}
	// Missing C provider permission observations are errors, even if the base
	// helper returns partial facts. Never interpret a credential as permission.
	publication, firstPublisherSHA, err := s.observeRuntimePublicationSources(bounded, *s.runtimeReadinessInput)
	if err != nil {
		return nil, err
	}
	until := x.delegation.until
	for _, end := range []time.Time{first.until, publication.until} {
		if end.Before(until) {
			until = end
		}
	}
	finalCtx, finish := context.WithDeadline(bounded, until)
	defer finish()
	last, err := s.ObserveSourceDependencies(finalCtx)
	if err != nil || first.metadataSHA256 != last.metadataSHA256 || first.writerSHA256 != last.writerSHA256 || last.checkedAt.Before(first.checkedAt) || x.recheck(finalCtx) != nil {
		return nil, d.ErrNotReady
	}
	if last.until.Before(until) {
		until = last.until
	}
	// Recheck current provider/owner sources after potentially slow source
	// reads. Preserve the FIRST combined upper bound; never renew an attempt.
	lastPublication, lastPublisherSHA, err := s.observeRuntimePublicationSources(finalCtx, *s.runtimeReadinessInput)
	if err != nil || lastPublication.checkedAt.Before(publication.checkedAt) || firstPublisherSHA != lastPublisherSHA {
		return nil, d.ErrNotReady
	}
	if lastPublication.until.Before(until) {
		until = lastPublication.until
	}
	proof := &sixPartRuntimeReadiness{service: s, binding: binding, permission: *s.runtimeReadinessInput, source: last, publisher: lastPublication, publisherSHA256: lastPublisherSHA, started: started, until: until}
	now, err := runtimeReadinessSQLTime(finalCtx, x.control)
	if err != nil {
		return nil, d.ErrNotReady
	}
	proof.until, err = runtimeReadinessWindow(started, now, until, last, lastPublication)
	if err != nil || proof.current(s, now) != nil {
		return nil, d.ErrNotReady
	}
	return proof, nil
}

func (p *sixPartRuntimeReadiness) current(s *DeploymentService, now time.Time) error {
	if p == nil || p.binding == nil || s == nil || p.service != s || !s.ForwardEnabled || s.Config.CaptureScope != "six-part" || s.runtimeReadinessInput == nil || p.permission != *s.runtimeReadinessInput || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.productionSource != p.binding || p.binding.service != s || !p.binding.matchesCapturePlan() || s.checkProductionCaptureMaterials() != nil {
		return d.ErrNotReady
	}
	if p.started.IsZero() || now.Before(p.started) || now.Before(p.sqlFloor) || !now.Before(p.until) || p.source.metadata.inventory == nil || !formalCandidateDigest(p.source.metadataSHA256) || !formalCandidateDigest(p.source.writerSHA256) || !formalCandidateDigest(p.publisherSHA256) || p.source.checkedAt.Before(p.started) || now.Before(p.source.checkedAt) || now.Before(p.publisher.checkedAt) || now.Before(p.publisher.notBefore) || !now.Before(p.publisher.until) || !now.Before(p.source.until) {
		return d.ErrNotReady
	}
	// Local exact source bytes only, including inside the SQL final boundary.
	// This constructor performs no API/provider request or authority mutation.
	if _, err := newRuntimeReadinessPermissionReader(p.permission); err != nil {
		return err
	}
	return nil
}

// Closed explicit source/profile pair. A missing/unknown profile never falls
// back to April, and the two original constructors reject cross-profile files.
func newRuntimeReadinessPermissionReader(input RuntimeReadinessInput) (*MinIOPublicationPermissionReader, error) {
	switch input.Profile {
	case ma.PermissionProfile:
		return NewMinIOEffectivePublicationPermissionV2Reader(input.Source)
	case ma.SeptemberPermissionProfile, ma.DeleteCompatPermissionProfile:
		return newMinIOBuiltinFlatPermissionReader(input.Source, input.Profile)
	default:
		return nil, d.ErrNotReady
	}
}

func (s *DeploymentService) publishedSixPartCapability() bool {
	if s == nil {
		return false
	}
	p := s.runtimeReadiness.Load()
	now := time.Now().UTC()
	return p != nil && !p.publishedUntil.IsZero() && now.Before(p.publishedUntil) && p.current(s, now) == nil
}

// All external/native observations have finished before the transaction.
// Recheck actual current config/SQL time under the existing readiness lock;
// cap the short readiness lease by EVERY original observed absolute deadline.
func (s *DeploymentService) lockSixPartReadinessConfig(ctx context.Context, tx *sql.Tx, version uint64, p *sixPartRuntimeReadiness) (time.Time, error) {
	var now time.Time
	var active uint64
	var effective, enabled bool
	var config string
	if tx.QueryRowContext(ctx, `SELECT s.active_config_version,s.last_effective_enabled,c.enabled,c.config_sha256,UTC_TIMESTAMP(6) FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version WHERE s.origin_installation_id=? FOR SHARE`, s.Config.InstallationID).Scan(&active, &effective, &enabled, &config, &now) != nil || !effective || !enabled || active != version || config != s.Forward.DeploymentBinding().ConfigSHA256 || p.current(s, now) != nil {
		return time.Time{}, d.ErrNotReady
	}
	p.sqlFloor = now
	return now, nil
}

func (s *DeploymentService) writeSixPartReadiness(ctx context.Context, tx *sql.Tx, version, generation uint64, p *sixPartRuntimeReadiness) error {
	now, clockErr := s.lockSixPartReadinessConfig(ctx, tx, version, p)
	if clockErr != nil {
		return clockErr
	}
	until := now.Add(5 * time.Second)
	if p.until.Before(until) {
		until = p.until
	}
	if !now.Before(until) {
		return d.ErrNotReady
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_readiness(origin_installation_id,task_type,config_version,profile_sha256,owner,generation,ready,checked_at,expires_at,execution_protocol,supported_parts,acceptance_ready) VALUES(?,'backup',?,?,?,?,TRUE,?,?,'public-v1',?,FALSE) ON DUPLICATE KEY UPDATE config_version=VALUES(config_version),profile_sha256=VALUES(profile_sha256),owner=VALUES(owner),generation=VALUES(generation),ready=TRUE,checked_at=VALUES(checked_at),expires_at=VALUES(expires_at),execution_protocol='public-v1',supported_parts=VALUES(supported_parts),acceptance_ready=FALSE`, s.Config.InstallationID, version, s.profileHash, s.PublisherOwner, generation, p.started, until, strings.Join(runtimeSixParts(), ","))
	if err == nil {
		p.publishedUntil = until // Exposed only AFTER caller's acknowledged COMMIT.
	}
	return err
}
