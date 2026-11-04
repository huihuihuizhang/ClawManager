package install

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strconv"
	"time"
)

// All fields are private original constructor state. No supplied facts/passed
// flag can construct one. The same process retains the original D services,
// opaque handle, A Prepared and publication claim through Result and readback.
type originalC1Run struct {
	stsJWT, authenticationJWT BootstrapSourceFilePin
	authenticationAudience    string
	parent                    *OriginalC1Production
	ctx                       context.Context
	capacityDB                *sql.DB
	capacity                  sec.CapacityCollectorConfig
	native                    *originalC1NativeObservation
	command                   pd.CommandRequest
	commandReceipt            pd.CommandReceiptRecord
	lifecycle                 *pd.Lifecycle
	execution                 *pd.Execution
	calls                     *originalC1ExecutionSwitch
	handle                    *pd.ExecutionHandle
	probe                     *pd.CallSnapshot
	observation               pd.ObservationRequest
	preparation               ev.SystemExecutionPreparationPolicy
	prepared                  ev.Prepared
	history                   pd.HistoricalBindingRecord
	pending                   pd.PendingRequest
	claimRequest              pd.ClaimRequest
	claim                     *pd.PublicationClaim
	publication               ev.SystemSTSPolicy
	publisher                 *ev.SystemPublisher
	result                    pd.ResultRequest
	source                    *ev.OriginalC1EvidenceSource
	ciphertext                []byte
	until                     time.Time
	failed                    bool
}

func (r *originalC1Run) local(ctx context.Context) error {
	if r == nil || r.parent == nil || r.failed || !r.parent.live(ctx) || !consumerSameContext(ctx, r.ctx) || r.native == nil || r.native.local(ctx) != nil || !time.Now().Before(r.until) {
		return ErrInstall
	}
	return nil
}
func (r *originalC1Run) before(ctx context.Context) (*originalC1SQLStage, error) {
	if r.local(ctx) != nil || r.parent.recheckPrepared() != nil || r.native.recheckFiles(ctx) != nil {
		return nil, ErrInstall
	}
	// Actual trusted Linux collector: real auto.cnf + SQL server/data directory,
	// exact own SELECT grants, complete pinned table list, statfs and DB bytes.
	// It MUST run beside the original MySQL volume; no caller available-byte DTO.
	report, err := sec.CollectPinnedRegistrationCapacity(ctx, r.capacityDB, r.capacity)
	if err != nil || report.ServerUUID != string(r.parent.domain.Scope.ServerUUID) || report.Database != string(r.parent.domain.Scope.Database) || !originalC1CapacityFresh(report, time.Now().UTC()) {
		return nil, ErrInstall
	}
	frozen := *r.parent
	frozen.origin = &frozen
	frozen.report = report
	base := &originalC1DomainSession{source: &frozen, request: pd.DomainOpenRequest{Scope: r.parent.domain.Scope, Operation: "provision", ExpectedEpoch: "0", ExpectedRowVersion: "0", DeploymentHash: pd.Hash(r.parent.profileSHA)}}
	return &originalC1SQLStage{run: r, base: base, sample: report.ObservedAt}, nil
}

type originalC1SQLStage struct {
	run         *originalC1Run
	base        *originalC1DomainSession
	sample      time.Time
	requestHash pd.Hash
	phase       string
}

func (s *originalC1SQLStage) lock(ctx context.Context, tx pd.SQL) error {
	if s == nil || s.run.local(ctx) != nil {
		return ErrInstall
	}
	return s.base.LockInstallation(ctx, tx, s.base.request)
}
func (s *originalC1SQLStage) auth(ctx context.Context, tx pd.ReadSQL, d pd.DomainRecord) error {
	r := s.run
	if r.local(ctx) != nil || s.base.current(ctx, tx) != nil || d.Scope != r.parent.domain.Scope || d.State != "open" || d.Epoch != r.parent.domain.Epoch || d.IssuerIdentityHash != r.parent.domain.IssuerIdentityHash || !reflect.DeepEqual(d.Admission, r.parent.domain.Admission) {
		return ErrInstall
	}
	return nil
}
func (s *originalC1SQLStage) host(ctx context.Context, g pd.GrantRecord) error {
	r := s.run
	if r.local(ctx) != nil || r.command.Next == nil || g.Scope != r.parent.domain.Scope || g.SubjectIdentityHash != r.command.Next.SubjectIdentityHash || g.IssuerIdentityHash != r.command.Next.IssuerIdentityHash || !reflect.DeepEqual(g.Host, r.command.Next.Host) || !reflect.DeepEqual(g.Target, r.command.Target) {
		return ErrInstall
	}
	return nil
}
func (s *originalC1SQLStage) reserve(ctx context.Context, tx pd.SQL, cost uint64) error {
	if cost == 0 || cost > math.MaxInt64 {
		return ErrInstall
	}
	return s.base.Reserve(ctx, tx, s.base.request, cost)
}
func (s *originalC1SQLStage) audit(ctx context.Context, tx pd.SQL, phase string) error {
	if s.run.local(ctx) != nil || !s.base.reserved || phase != "intent" && phase != "result" || phase == "intent" && s.base.intent || phase == "result" && (!s.base.intent || s.base.result) {
		return ErrInstall
	}
	body, err := canonical(struct{ Version, Stage, Request string }{"original-c1-production-audit.v1", s.phase, string(s.requestHash)})
	if err != nil {
		return ErrInstall
	}
	write, ok := tx.(*pd.Transaction)
	if !ok || write.CAS(ctx, "INSERT INTO audit_logs(user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", s.run.parent.operator.userID, "system_backup.c1_"+s.phase+"."+phase, string(body)) != nil {
		return ErrInstall
	}
	if phase == "intent" {
		s.base.intent = true
	} else {
		s.base.result = true
	}
	return nil
}
func (s *originalC1SQLStage) final(ctx context.Context, tx pd.ReadSQL, d pd.DomainRecord, now time.Time, mutate bool) error {
	if s.auth(ctx, tx, d) != nil || s.run.native.lockOriginalReference(ctx, tx) != nil || !now.Before(s.run.until) || now.Before(s.run.native.started) {
		return ErrInstall
	}
	if mutate {
		if !s.base.reserved || !s.base.intent || !s.base.result || !originalC1CapacityFresh(s.base.source.report, now) {
			return ErrInstall
		}
		var sample time.Time
		var reserved int64
		if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &reserved) != nil || !sample.Equal(s.base.sample) || reserved < s.base.floor || reserved > s.base.source.capacity-s.base.source.report.AllocatedBytes {
			return ErrInstall
		}
	}
	return nil
}
func (s *originalC1SQLStage) refs(ctx context.Context, tx pd.ReadSQL, request, policy pd.Hash) (pd.ReferenceApproval, error) {
	if s.run.local(ctx) != nil || request == "" || policy == "" || s.run.native.lockOriginalReference(ctx, tx) != nil {
		return pd.ReferenceApproval{}, ErrInstall
	}
	return pd.ReferenceApproval{RequestHash: request, PolicyHash: policy, VersionHash: pd.Hash(s.run.native.referenceHash), DependencyExpiresAt: c1stamp(s.run.until)}, nil
}
func c1stamp(t time.Time) pd.Timestamp {
	return pd.Timestamp(t.UTC().Format("2006-01-02T15:04:05.000000Z"))
}
func c1bodySource(raw []byte) ev.Source {
	owned := bytes.Clone(raw)
	return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(owned)), nil }
}
func c1wire(v any) []byte           { b, _ := json.Marshal(v); return b }
func c1counter(v uint64) pd.Counter { return pd.Counter(strconv.FormatUint(v, 10)) }
