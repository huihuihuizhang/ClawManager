package systembackupexecution

import (
	"context"
	"errors"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// PublicationDependencyObservation is an inert, bounded deployment observation,
// not a claim, signing permission, six-part source capability or Ready proof.
// Its private fields are populated only after the concrete checks below. D must
// combine this with its own complete current source/writer observations.
type PublicationDependencyObservation struct {
	checkedAt, notBefore, until time.Time
}

// The existing transport mapping/credential files are not an authenticated
// current provider ACL observation. No such source is accepted by this entry
// yet; absence is an explicit refusal, not a caller-controlled approval hook.
var ErrPublicationProviderPermissionObservationMissing = errors.New("current object-provider permission observation source unavailable")

func (o PublicationDependencyObservation) CheckedAt() time.Time  { return o.checkedAt }
func (o PublicationDependencyObservation) NotBefore() time.Time  { return o.notBefore }
func (o PublicationDependencyObservation) ValidUntil() time.Time { return o.until }

func (o PublicationDependencyObservation) VerifiedSources() []string {
	if o.checkedAt.IsZero() || o.until.IsZero() {
		return nil
	}
	return []string{"original-deployment-and-current-sql-identity", "original-current-config-and-purpose-references", "original-kek-owner-and-unwrap-capability", "original-publisher-verification-grant", "original-three-purpose-signing-owner-and-live-workload", "pinned-transport-ca-and-credential-files", "current-controller-node-pvc-pv-staging-binding"}
}

// RemainingChecks identifies observations this taskless entry cannot perform.
// In particular, credentials and signed owner permissions do not prove that a
// provider will permit a future operation. No caller-supplied pass flags exist.
func (PublicationDependencyObservation) RemainingChecks() []string {
	return []string{
		"complete-current-source-and-writer-observation",
		"original-task-purpose-claim-attempt-cancel-and-deadline",
		"original-six-part-capture-and-physical-source-recovery",
		"exact-signing-input-and-provider-signing-use",
		"provider-artifact-read-write-delete-and-catalog-append-use",
		"complete-fixed-version-content-readback-cleanup-and-terminal-cas",
	}
}

// PublicationDependencyError exposes a fixed dependency name, never mounted
// credentials, SQL diagnostics, JWT content or provider response bodies.
type PublicationDependencyError struct {
	Dependency string
	cause      error
}

func (e *PublicationDependencyError) Error() string {
	return "publication dependency unavailable: " + e.Dependency
}
func (e *PublicationDependencyError) Unwrap() error { return e.cause }

func publicationDependencyFailure(stage string, cause error) error {
	if cause == nil {
		cause = c.ErrExecutionAuthority
	}
	return &PublicationDependencyError{Dependency: stage, cause: cause}
}

type publicationDependencyWindow struct{ notBefore, until time.Time }

func (w *publicationDependencyWindow) include(now, notBefore, until time.Time) error {
	if now.IsZero() || notBefore.IsZero() || !notBefore.Before(until) || now.Before(notBefore) || !now.Before(until) {
		return c.ErrExecutionAuthority
	}
	if w.notBefore.IsZero() || w.notBefore.Before(notBefore) {
		w.notBefore = notBefore
	}
	if w.until.IsZero() || until.Before(w.until) {
		w.until = until
	}
	return nil
}

// CheckPublicationDependencies checks actual independently installed C
// dependencies without inventing a task/claim, calling ForTask/ForPart, creating
// a Job, signing or accessing the object provider. It returns original upper
// bounds, never a renewed grant or a cached approval. Existing A deployment
// validation still owns its current authority/fence/capability checks.
//
// Missing authenticated current provider-permission observations return the
// completed partial observation AND a specific non-nil error. D must propagate
// that error; neither the observation nor its expiry is a readiness approval.
// This is necessary but not sufficient for D's six-part readiness. A's original
// task guards remain authoritative, including which task purposes they accept;
// a nil result here cannot override an acceptance-only task signing guard.
func (s *DeploymentService) CheckPublicationDependencies(ctx context.Context) (PublicationDependencyObservation, error) {
	var zero PublicationDependencyObservation
	fail := func(stage string, err error) (PublicationDependencyObservation, error) {
		return zero, publicationDependencyFailure(stage, err)
	}
	if ctx == nil || ctx.Err() != nil || s == nil {
		return fail("composition", nil)
	}
	if !s.ForwardEnabled || s.Config.CaptureScope != "six-part" || s.Runtime == nil || s.Runtime.Owner == nil {
		return fail("complete-six-part-runtime", nil)
	}
	if s.publisherVerifierDB == nil || s.publicationDB == nil || s.publicationDB != s.publisherVerifierDB {
		return fail("original-publisher-sql-source", nil)
	}
	if s.Config.PublicationTarget == nil || s.publicationTargetInput == nil || s.publicationTarget == nil {
		return fail("original-artifact-target-source", nil)
	}
	if s.Config.PublicationSigners == nil || s.publicationInput == nil || s.publicationFactory == nil {
		return fail("original-signing-owner-source", nil)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := s.publicationBinding(); err != nil {
		return fail("original-deployment-binding", err)
	}
	// Read original sources first: absent fences/mappings are errors, not input
	// for the existing verifier's Bind path to initialize a replacement ledger.
	initial, err := s.readPublicationDependencySQL(ctx, nil, nil)
	if err != nil {
		return zero, err
	}
	if err = s.CheckPublisherVerifierReadiness(ctx); err != nil {
		return fail("current-publisher-verifier-and-policy", err)
	}
	signing, err := s.checkPublicationDependencySigning(ctx, initial.now)
	if err != nil {
		return zero, err
	}
	store, err := s.publicationStore(ctx)
	if err != nil {
		return fail("artifact-transport-material", err)
	}
	defer store.Close()
	catalog, err := s.currentPublicationCatalog(ctx)
	if err != nil {
		return fail("independent-catalog-material", err)
	}
	catalogStore, err := s.catalogStore(ctx)
	if err != nil {
		return fail("catalog-transport-material", err)
	}
	defer catalogStore.Close()
	if _, err = s.publicationStagingNode(ctx); err != nil {
		return fail("current-staging-location", err)
	}
	window := initial.window
	if err = window.include(initial.now, signing.notBefore, signing.until); err != nil {
		return fail("signing-original-window", err)
	}
	for _, use := range []struct {
		name  string
		store *nativePublicationS3
		write bool
	}{
		{"artifact-read-credential", store, false}, {"artifact-write-credential", store, true},
		{"catalog-read-credential", catalogStore, false}, {"catalog-append-credential", catalogStore, true},
	} {
		credential, err := use.store.credential(use.write)
		if err == nil {
			err = window.include(initial.now, credential.NotBefore, credential.Until)
		}
		credential = nativePublicationCredential{}
		if err != nil {
			return fail(use.name, err)
		}
	}
	if store.config.RemoteStagingRoot == "" || store.config.DeleteCredentialFile == "" {
		return fail("original-candidate-delete-mapping", nil)
	}
	deletion, err := loadNativePublicationCredential(store.config.DeleteCredentialFile, store.config.DeleteCredentialSHA256)
	if err == nil {
		err = window.include(initial.now, deletion.NotBefore, deletion.Until)
	}
	deletion = nativePublicationCredential{}
	if err != nil {
		return fail("artifact-delete-credential", err)
	}
	final, err := s.readPublicationDependencySQL(ctx, &store.config, &catalog)
	if err != nil {
		return zero, err
	}
	if final.now.Before(initial.now) || final.identity != initial.identity || ctx.Err() != nil {
		return fail("current-sql-observation-changed", nil)
	}
	if err = window.include(final.now, final.window.notBefore, final.window.until); err != nil {
		return fail("original-authority-window", err)
	}
	// Repeat live current-source checks after the short SQL read has ended.
	if err = s.CheckPublisherVerifierReadiness(ctx); err != nil {
		return fail("final-current-publisher-verifier-and-policy", err)
	}
	lastSigning, err := s.checkPublicationDependencySigning(ctx, final.now)
	if err != nil {
		return zero, err
	}
	if lastSigning != signing {
		return fail("signing-material-changed", nil)
	}
	if err = s.publicationBinding(); err != nil {
		return fail("final-original-deployment-binding", err)
	}
	if _, err = s.publicationStagingNode(ctx); err != nil {
		return fail("final-current-staging-location", err)
	}
	tail, err := s.readPublicationDependencySQL(ctx, &store.config, &catalog)
	if err != nil {
		return zero, err
	}
	if tail.now.Before(final.now) || tail.identity != initial.identity {
		return fail("final-sql-observation-changed", nil)
	}
	if err = window.include(tail.now, tail.window.notBefore, tail.window.until); err != nil {
		return fail("final-original-authority-window", err)
	}
	if ctx.Err() != nil || tail.now.Before(window.notBefore) || !tail.now.Before(window.until) || !time.Now().Before(window.until) {
		return fail("observation-expired", errors.Join(c.ErrExecutionAuthority, ctx.Err()))
	}
	observed := PublicationDependencyObservation{checkedAt: tail.now, notBefore: window.notBefore, until: window.until}
	return observed, publicationDependencyFailure("object-provider-permission-observation-unavailable", ErrPublicationProviderPermissionObservationMissing)
}
