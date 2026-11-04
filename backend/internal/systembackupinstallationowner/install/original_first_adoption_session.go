package install

import (
	"context"
	"sort"
	"sync"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// The production handoff retains the SAME actual source preparation and
// coverage for owner issuance and final commit. No inspection/claim/record DTO
// can manufacture a session, and constructing one neither stages nor commits.
type PreparedOriginalFirstAdoption struct {
	mu               sync.Mutex
	executionStarted bool
	origin           *PreparedOriginalFirstAdoption
	ctx              context.Context
	prep             *PreparedOriginalAdoptionSQLCut
	hold             *OriginalWriterHold
	coverage         *PreparedOriginalAdoptionCoverage
	until            time.Time
}

func (*PreparedOriginalFirstAdoption) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*PreparedOriginalFirstAdoption) String() string               { return "PreparedOriginalFirstAdoption" }
func (*PreparedOriginalFirstAdoption) GoString() string             { return "PreparedOriginalFirstAdoption" }

// Derive correlation only from the genuine original node's recorded prepare.
// Do not ask the operator to write an authorization JSON or replace original
// acquiring epoch/RV with the later held gate values. Actual current held gate
// and all native observations are rechecked before and after selection.
func (h *OriginalWriterHold) prepareOriginalFirstAdoptionSQL(ctx context.Context, password []byte, enrollment EnrollmentPin) (*PreparedOriginalAdoptionSQLCut, error) {
	if h == nil || h.set == nil {
		return nil, ErrInstall
	}
	s := h.set
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.origin != h || s.origin != s || s.actualHold != h || s.owner == nil || s.owner.operator == nil || s.owner.enrollment != enrollment || !consumerSameContext(ctx, h.ctx) || h.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	nodes := append([]*originalWholeNodeScope(nil), s.nodes...)
	for _, node := range nodes {
		if node == nil || node.set != s || node.prepare == nil || node.current == nil || node.claim.Phase != c.GateAcquiring || node.claim.ControlKind != "platform-quiesce" || node.claim.OperationID != s.owner.operation || node.claim.SourceWritersSHA256 != s.inventorySHA {
			return nil, ErrInstall
		}
		response := node.prepare.Response()
		b := node.request.Binding
		if node.claim.NativeRequestSHA256 != response.RequestSHA256 || node.claim.ReservationID != b.ReservationID || node.claim.InstallationID != b.InstallationID || node.claim.WriterID != "node/"+b.Node || node.claim.GateGeneration != b.Generation || node.claim.AcquisitionEpoch != b.FenceEpoch || !node.claim.ExpiresAt.Equal(b.ExpiresAt) {
			return nil, ErrInstall
		}
	}
	if len(nodes) == 0 {
		return nil, OriginalWriterSourceFailure{Dependency: "original_first_adoption_native_reservation_required"}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].claim.WriterID < nodes[j].claim.WriterID })
	for i := 1; i < len(nodes); i++ {
		if nodes[i-1].claim.WriterID == nodes[i].claim.WriterID {
			return nil, ErrInstall
		}
	}
	claim := nodes[0].claim
	claim.Phase = c.GateHeld
	if _, err := c.OriginalAdoptionReservationIdentitySHA256(claim); err != nil {
		return nil, ErrInstall
	}
	i := s.owner.operator.installer
	p, err := i.PrepareOriginalAdoptionSQLCut(ctx, password, enrollment, claim)
	if err != nil {
		return nil, err
	}
	if p.operator.installer != i || p.reservation != claim || h.recheckBeforeSQL(ctx) != nil || !originalEmptyHistoryOwner(ctx, p, h, false) {
		return nil, ErrInstall
	}
	return p, nil
}

// This is the actual production source preparation used by the first-adoption
// caller, distinct from CheckControls' always-rollback diagnostic route.
func (h *OriginalWriterHold) PrepareOriginalFirstAdoption(ctx context.Context, password []byte, enrollment EnrollmentPin, runtimeMetadata ...BootstrapSourceFilePin) (*PreparedOriginalFirstAdoption, error) {
	p, err := h.prepareOriginalFirstAdoptionSQL(ctx, password, enrollment)
	if err != nil {
		return nil, err
	}
	if len(runtimeMetadata) > 1 {
		return nil, ErrInstall
	}
	if len(runtimeMetadata) == 1 && p.AttachOriginalRuntimeInstalledSQLMetadata(ctx, runtimeMetadata[0]) != nil {
		return nil, ErrInstall
	}
	producer, err := p.PrepareOriginalBackupConsumerHistorySource(ctx, h)
	if err != nil {
		return nil, err
	}
	coverage, err := p.PrepareOriginalFilesystemHistoryCoverage(ctx, h, producer)
	if err != nil {
		return nil, err
	}
	if coverage == nil || coverage.origin != coverage || coverage.sourceSet == nil || coverage.hold != h || coverage.tx != nil || !consumerSameContext(ctx, coverage.ctx) || !time.Now().Before(coverage.until) {
		return nil, ErrInstall
	}
	r := &PreparedOriginalFirstAdoption{ctx: ctx, prep: p, hold: h, coverage: coverage, until: coverage.until}
	r.origin = r
	return r, nil
}

func (r *PreparedOriginalFirstAdoption) local(ctx context.Context) bool {
	return r != nil && r.origin == r && consumerSameContext(ctx, r.ctx) && r.prep != nil && r.coverage != nil && r.coverage.origin == r.coverage && r.coverage.hold == r.hold && r.coverage.tx == nil && r.coverage.sourceSet != nil && r.coverage.sourceSet.prep == r.prep && r.coverage.sourceSet.hold == r.hold && r.until.Equal(r.coverage.until) && time.Now().Before(r.until) && originalEmptyHistoryOwner(ctx, r.prep, r.hold, false)
}
