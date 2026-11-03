package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"clawreef/internal/systembackup/quiesce"
	archive "clawreef/internal/systembackuphostpatharchive"
)

// NativeObservedOriginalArchive retains ACTUAL authenticated B observations
// bracketing the real D-journal/C-custody copy. It is not the global complete
// writer fence, deployment custody access closure, classified history or
// PreparedCoverage. The actual D owner must compose those separate sources.
type NativeObservedOriginalArchive struct {
	origin        *NativeObservedOriginalArchive
	provider      *OriginalAdoptionArchiveProvider
	retained      *RetainedOriginalArchive
	client        *quiesce.NodeObservationClient
	request       quiesce.NodeObservationRequest
	before, after *quiesce.VerifiedNodeObservation
	boot          string
}

func (*NativeObservedOriginalArchive) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (s *NativeObservedOriginalArchive) SnapshotRevision() string {
	if s == nil || s.origin != s {
		return ""
	}
	return s.retained.SnapshotRevision()
}

// D supplies the actual PREPARE DTO retained in its original stop ledger AND
// the opaque verified response from the real B mTLS client. Original native
// request hash must equal D's frozen NativeRequestSHA256. No caller Passed flag
// or deserialized response can enter this constructor.
// Binding uses the ORIGINAL acquisition epoch, not a guessed current/new gate.
func (p *OriginalAdoptionArchiveProvider) CreateNativeObservedOriginalArchive(ctx context.Context,
	native archive.NativeStream, readerFile, readerSHA string, client *quiesce.NodeObservationClient,
	prepare quiesce.NodeObservationRequest, verifiedPrepare *quiesce.VerifiedNodeObservation) (*NativeObservedOriginalArchive, error) {
	if p == nil || client == nil || verifiedPrepare == nil || !consumerSameContext(ctx, p.outer) || p.current() != nil {
		return nil, ErrInstall
	}
	response := verifiedPrepare.Response()
	binding := response.Binding
	if response.Action != "prepare" || response.Anchor == "" || response.RequestSHA256 != p.reservation.NativeRequestSHA256 ||
		binding.Kind != quiesce.NodeObservationWholePodColdCut || binding.InstallationID != p.reservation.InstallationID ||
		binding.OperationID != p.reservation.OperationID || binding.ReservationID != p.reservation.ReservationID ||
		binding.InventorySHA256 != p.reservation.SourceWritersSHA256 || binding.Generation != p.reservation.GateGeneration ||
		binding.FenceEpoch != p.reservation.AcquisitionEpoch || !binding.ExpiresAt.Equal(p.reservation.ExpiresAt) ||
		binding.Namespace != p.minio.Grant.Namespace || binding.NamespaceUID != p.minio.Grant.NamespaceUID ||
		binding.Node != p.minio.Grant.Provider.Node || binding.NodeUID != p.minio.Grant.Provider.NodeUID {
		return nil, ErrInstall
	}
	// Rebuild the exact client-generated prepare request using its actual
	// response nonce/deadline. This authenticates original Pods/root paths,
	// including ALL containers, rather than making a list from API disappearance.
	if prepare.Action != "prepare" || prepare.Anchor != "" || len(prepare.RecoveredPods) != 0 || prepare.RecoveredGeneration != 0 {
		return nil, ErrInstall
	}
	prepare.Version = response.Version
	prepare.Nonce = response.Nonce
	prepare.Deadline = response.ValidUntil
	raw, err := json.Marshal(prepare)
	if err != nil {
		return nil, ErrInstall
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != response.RequestSHA256 {
		return nil, ErrInstall
	}
	path, boot, _, err := p.sourcePath()
	if err != nil || response.BootID != boot {
		return nil, ErrInstall
	}
	matchedPath, matchedPod := false, false
	for _, root := range prepare.SourcePaths {
		if root == path {
			matchedPath = true
		}
	}
	for _, pod := range prepare.Pods {
		if pod.UID == p.minio.Grant.Provider.Pod.UID && pod.Name == p.minio.Grant.Provider.Pod.Name && pod.Node == binding.Node {
			matchedPod = true
		}
	}
	if !matchedPath || !matchedPod {
		return nil, ErrInstall
	}
	request := quiesce.NodeObservationRequest{Action: "stopped", Binding: binding, Pods: prepare.Pods, Anchor: response.Anchor}
	before, err := client.ObserveVerified(p.ctx, request)
	if err != nil || before.Recheck(p.ctx, binding, "stopped", boot, time.Now()) != nil {
		return nil, ErrInstall
	}
	retained, err := p.CreateRetainedOriginalAdoptionCopy(ctx, native, readerFile, readerSHA)
	if err != nil {
		return nil, ErrInstall
	}
	after, err := client.ObserveVerified(p.ctx, request)
	if err != nil || after.Recheck(p.ctx, binding, "stopped", boot, time.Now()) != nil || p.RecheckRetainedOriginalArchive(ctx, retained) != nil {
		return nil, ErrInstall
	}
	source := &NativeObservedOriginalArchive{provider: p, retained: retained, client: client, request: request,
		before: before, after: after, boot: boot}
	source.origin = source
	return source, nil
}

// Fresh real native stopped observation and current original custody/authority
// before D opens its original final SQL/evidence prefix. No original cap is
// extended; this cannot be called under held final source/KEK SQL locks.
func (s *NativeObservedOriginalArchive) RecheckBeforeOriginalSQL(ctx context.Context) error {
	if s == nil || s.origin != s || !consumerSameContext(ctx, s.provider.outer) ||
		s.provider.RecheckRetainedOriginalArchive(ctx, s.retained) != nil {
		return ErrInstall
	}
	observation, err := s.client.ObserveVerified(s.provider.ctx, s.request)
	if err != nil || observation.Recheck(s.provider.ctx, s.request.Binding, "stopped", s.boot, time.Now()) != nil {
		return ErrInstall
	}
	s.after = observation
	return nil
}
