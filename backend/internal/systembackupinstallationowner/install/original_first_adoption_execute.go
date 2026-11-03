package install

import "context"

// The sole production session execution consumes actual source-owner issuance
// on this SAME prepared coverage. Neither record JSON nor reconstructed
// inspection facts are accepted. The independently pinned definition locates
// real authorized role material; A's real source-owning API derives the facts.
func (r *PreparedOriginalFirstAdoption) AdoptOriginalFilesystem(ctx context.Context, issuerDefinitionFile, issuerDefinitionSHA string) (OriginalAdoptionCommitInspection, error) {
	var zero OriginalAdoptionCommitInspection
	if r == nil {
		return zero, ErrInstall
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.executionStarted || issuerDefinitionFile == "" || !digestPattern.MatchString(issuerDefinitionSHA) || !r.local(ctx) {
		return zero, ErrInstall
	}
	// All retries/partial failures belong to this original operation. A second
	// invocation cannot issue another batch or start another adoption; known
	// failure uses actual source recovery, COMMIT unknown uses original journal.
	r.executionStarted = true
	issued, err := r.prep.IssueOriginalFilesystemAdoptionControls(ctx, r.hold, r.coverage, BootstrapSourceFilePin{File: issuerDefinitionFile, SHA256: issuerDefinitionSHA})
	if err != nil {
		return zero, err
	}
	if issued == nil {
		return zero, ErrInstall
	}
	records, preparation, err := issued.originalCommitInputs(ctx, r.prep, r.hold, r.coverage)
	if err != nil || preparation == nil {
		return zero, ErrInstall
	}
	// Original Stage writes/accounting, independent A authentication, source
	// locks and KEK operation all remain owned by this actual existing entry.
	return r.prep.CommitOriginalOwnerAdoption(ctx, r.hold, records, preparation, r.coverage)
}
