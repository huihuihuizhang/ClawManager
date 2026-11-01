package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"clawreef/internal/systembackup/staging"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
	security "clawreef/internal/systembackupsecurity"
)

type publicationContainerFile struct {
	Part, Path, SubPath string
	Receipt             staging.Receipt
}

type publicationContainerFileSet struct {
	Version    string `json:"schema_version"`
	PlanSHA256 string
	Files      []publicationContainerFile
}

var publicationRequestedParts = []string{"deployment_resources", "mysql", "object_storage", "redis", "secret_bundle", "workspace"}

// These physical file facts are created from actual bytes under the current
// publisher. They are still not native object versions or artifact acceptance.
func (s *DeploymentService) preparePublicationContainerFiles(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture) (publicationContainerFileSet, error) {
	var zero publicationContainerFileSet
	dir, err := s.ensurePublicationContainerDirectory(ctx, claim, attempt, policy, capture)
	if err != nil {
		return zero, err
	}
	defer dir.Close()
	guard := &publicationContainerGuard{service: s, claim: claim, attempt: attempt, policy: policy}
	if err = guard.current(ctx, true); err != nil {
		return zero, err
	}
	limits, err := s.publicationContainerLimits(ctx, *claim, attempt)
	if err != nil {
		return zero, err
	}
	planRaw, err := ce.Canonical(dir.plan)
	if err != nil {
		return zero, err
	}
	out := publicationContainerFileSet{Version: "system-backup-original-publication-container-files.v1", PlanSHA256: hash(planRaw), Files: []publicationContainerFile{}}
	var total int64
	for _, requested := range publicationRequestedParts {
		if err = guard.current(ctx, true); err != nil {
			return zero, err
		}
		name := "container-" + requested + ".enc"
		_, existsErr := dir.root.Lstat(name)
		if errors.Is(existsErr, os.ErrNotExist) {
			// The committed exact plan and authenticated parent/child markers
			// precede this private create-only write. A partial is never adopted.
			_, err = staging.WriteUnpublishedFile(ctx, dir.root, name, func(dst io.Writer) error {
				_, err := s.writeOriginalPublicationContainer(ctx, claim, attempt, policy, capture, requested, dst)
				return err
			})
			if err != nil {
				return zero, err
			}
		} else if existsErr != nil {
			return zero, existsErr
		}
		// Also handles an acknowledged plan followed by a complete file write
		// whose receipt SQL commit was interrupted. Ownership alone is not
		// enough: hash and inspect all bytes against the original capture.
		receipt, err := hashOwnedPublicationContainer(ctx, dir.root, name, limits.MaxArtifactBytes, guard.check)
		if err != nil {
			return zero, err
		}
		if receipt.Size > limits.MaxArtifactBytes-total {
			return zero, c.ErrExecutionRecord
		}
		total += receipt.Size
		if err = s.inspectOwnedPublicationContainer(ctx, guard, capture, requested, dir.root, receipt, limits); err != nil {
			return zero, err
		}
		out.Files = append(out.Files, publicationContainerFile{Part: requested, Path: "parts/" + requested + "/container.enc", SubPath: capture.Input.TaskPublicID + "/" + dir.plan.Directory + "/" + name, Receipt: receipt})
	}
	if err = s.freezePublicationContainerFiles(ctx, guard, capture, dir.plan, out); err != nil {
		return zero, err
	}
	return out, nil
}

func hashOwnedPublicationContainer(ctx context.Context, root *os.Root, name string, limit int64, check func(context.Context) error) (staging.Receipt, error) {
	var zero staging.Receipt
	if ctx == nil || ctx.Err() != nil || root == nil || check == nil || check(ctx) != nil || limit < 1 || limit > MaxPublicationArtifactBytes {
		return zero, c.ErrExecutionAuthority
	}
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return zero, c.ErrExecutionRecord
	}
	file, err := root.Open(name)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return zero, c.ErrExecutionRecord
	}
	whole := sha256.New()
	reader := &publicationContainerReader{ctx: ctx, src: file, check: check}
	size, err := io.Copy(whole, io.LimitReader(reader, before.Size()+1))
	if err != nil || ctx.Err() != nil || size != before.Size() || check(ctx) != nil {
		return zero, c.ErrExecutionRecord
	}
	return staging.Receipt{Name: name, Size: size, SHA256: hex.EncodeToString(whole.Sum(nil))}, nil
}

func (s *DeploymentService) inspectOwnedPublicationContainer(ctx context.Context, guard *publicationContainerGuard, capture publicationVerifiedCapture, requested string, root *os.Root, receipt staging.Receipt, limits ArtifactReadLimits) error {
	if guard == nil || !capture.checked() || guard.current(ctx, true) != nil {
		return c.ErrExecutionAuthority
	}
	file, err := staging.OpenFileGuarded(ctx, root, receipt, guard.check)
	if err != nil {
		return err
	}
	defer file.Close()
	checkpoints := map[string]string{}
	parts := map[string]publicationVerifiedPart{}
	for _, part := range capture.Parts {
		if part.RequestedPart == requested {
			sum, err := pcCheckpointSHA(part.Checkpoint)
			if err != nil {
				return err
			}
			checkpoints[part.Part] = sum
			parts[part.Part] = part
		}
	}
	scope := pc.Scope{Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: capture.Input.CaptureAttemptNo, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, CaptureContextSHA256: capture.CaptureContextSHA256, Part: requested}
	// This is a local content-addressed custody label only. Native remote object
	// versions are acquired by the independent post-Job readback, never here.
	facts, err := pc.Inspect(ctx, pc.FixedObject{Reader: &publicationContainerReaderAt{ctx: ctx, src: file, check: guard.check}, Version: "local-custody-" + receipt.SHA256, SHA256: receipt.SHA256, Size: receipt.Size}, scope, checkpoints, limits.MaxArtifactBytes, limits.MaxIndexBytes)
	if err != nil || len(facts.Header.Members) != len(parts) {
		return c.ErrExecutionRecord
	}
	for _, member := range facts.Header.Members {
		if err = guard.current(ctx, true); err != nil {
			return err
		}
		part, ok := parts[member.Part]
		if !ok {
			return c.ErrExecutionRecord
		}
		verifier, err := s.PublisherVerifierForPart(ctx, *guard.claim, guard.attempt, member.Part)
		if err != nil {
			return err
		}
		record, err := verifier.CapturedRecord(ctx)
		verifier.Close()
		if err != nil {
			return err
		}
		expected, _, err := publicationContainerMember(capture, part, record)
		if err != nil {
			return err
		}
		expected.CipherOffset, expected.EnvelopeOffset = member.CipherOffset, member.EnvelopeOffset
		if !reflect.DeepEqual(expected, member) {
			return c.ErrExecutionRecord
		}
		delete(parts, member.Part)
	}
	if len(parts) != 0 {
		return c.ErrExecutionRecord
	}
	return guard.current(ctx, true)
}

func (s *DeploymentService) freezePublicationContainerFiles(ctx context.Context, guard *publicationContainerGuard, capture publicationVerifiedCapture, plan publicationContainerPlan, files publicationContainerFileSet) error {
	if guard == nil || guard.current(ctx, true) != nil || !capture.checked() {
		return c.ErrExecutionAuthority
	}
	planRaw, err := ce.Canonical(plan)
	if err != nil {
		return err
	}
	if files.Version != "system-backup-original-publication-container-files.v1" || files.PlanSHA256 != hash(planRaw) || len(files.Files) != len(publicationRequestedParts) {
		return c.ErrExecutionRecord
	}
	for index, file := range files.Files {
		part := publicationRequestedParts[index]
		name := "container-" + part + ".enc"
		if file.Part != part || file.Path != "parts/"+part+"/container.enc" || file.SubPath != plan.Backup+"/"+plan.Directory+"/"+name || file.Receipt.Name != name || file.Receipt.Size < 1 || !formalCandidateDigest(file.Receipt.SHA256) {
			return c.ErrExecutionRecord
		}
	}
	body, err := ce.Canonical(files)
	if err != nil || len(body) > 8192 {
		return c.ErrExecutionRecord
	}
	original, err := s.publicationStageForContainers(ctx, guard, capture)
	if err != nil {
		return err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	bound, err := guard.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	current, err := s.readPublicationCertificateFactsTx(ctx, tx, bound.Facts(), capture, nil)
	if err != nil || !samePublicationContainerStage(original, current) {
		return c.ErrExecutionRecord
	}
	if _, err = readPublicationLimitsTx(ctx, tx, bound); err != nil {
		return err
	}
	id := publicationContainerPlanID(plan.Installation, plan.Backup, plan.Attempt)
	actualPlan, err := loadPublicationMetadata(ctx, tx, plan.Backup, id)
	if err != nil || !bytes.Equal(actualPlan, planRaw) {
		return c.ErrExecutionRecord
	}
	old, err := loadPublicationMetadata(ctx, tx, plan.Backup, id+"_files")
	if err == nil {
		if !bytes.Equal(old, body) {
			return c.ErrExecutionRecord
		}
		return bound.RecheckTx(ctx, tx)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err = publicationPreparationOpenTx(ctx, tx, plan.Installation, plan.Backup); err != nil {
		return err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, plan.Installation, plan.ConfigVersion, plan.ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(bound.Facts().TaskDeadline) {
		return c.ErrExecutionAuthority
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)); err != nil {
		return err
	}
	if err = registerPublicationMetadata(ctx, tx, plan.Installation, plan.Backup, id+"_files", body, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return err
	}
	if err = bound.RecheckTx(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}
