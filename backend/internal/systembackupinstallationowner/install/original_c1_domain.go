package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	bs "clawreef/internal/systembackupbootstrapsecurity"
	controller "clawreef/internal/systembackupcontroller"
	ev "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const originalC1DomainSourceVersion = "original-enrolled-c1-domain-source.v1"

// These select actual original producer files, never a result/management flag.
// Channel is comparison data selected by this explicit original owner action;
// it grants no Wrap/STS/publication permission. Those need their own native
// execution authorities and provider proofs later in the SAME Go producer.
type OriginalC1DomainInputs struct {
	Request                 RequestFiles
	Channel, CapacityReport BootstrapSourceFilePin
	OutputDirectory         string
}

// OriginalC1Production is process-local original enrollment state. It is not
// reconstructible from a historical command receipt, JSON or matching hashes.
// The complete producer must retain this object and its original context.
type OriginalC1Production struct {
	origin         *OriginalC1Production
	ctx            context.Context
	operator       *authenticatedOperator
	request        *originalRequest
	enrollment     EnrollmentPin
	input          OriginalC1DomainInputs
	channel        ev.ProducerEvidenceChannel
	admission      pd.UnconfiguredAdmission
	domain         pd.DomainRecord
	profile        []byte
	signature      []byte
	profileSHA     string
	report         sec.CapacityReport
	capacity       int64
	until          time.Time
	failed         bool
	backing        *ev.OriginalC1BackingStoreSource
	backingBinding *OriginalC1BackingReceipt
}

func (*OriginalC1Production) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*OriginalC1Production) String() string               { return "OriginalC1Production" }
func (*OriginalC1Production) GoString() string             { return "OriginalC1Production" }

// Close invalidates this local producer, not the committed domain or retained
// reservation. The enclosing single-process producer must first drain calls.
func (p *OriginalC1Production) Close() {
	if p == nil || p.origin == nil {
		return
	}
	p.origin.failed = true
	if p.origin.request != nil && p.origin.request.observer != nil {
		p.origin.request.observer.Close()
	}
}

type OriginalC1DomainStartReceipt struct {
	Version, State    string
	Source, Signature BootstrapSourceFilePin
	Domain            pd.DomainRecord
}

type originalC1DomainSource struct {
	Version, PlanSHA256        string
	Enrollment                 EnrollmentPin
	Request                    RequestFiles
	Channel, CapacityReport    BootstrapSourceFilePin
	Scope                      pd.Scope
	ActorID                    int64
	Username, InstallerAccount string
	Admission                  pd.UnconfiguredAdmission
	NotBefore, Until           time.Time
}

// BeginOriginalC1Production is the actual first-domain constructor. It performs
// native original SQL/local-admin and Kubernetes enrollment authentication,
// freezes and signs a separate PRE-CAPTURE domain association, then calls the
// real guarded DomainOpener. It does not sign a capture, mint a run handle,
// certify provider health or declare complete C1/selection/adoption success.
func (i *Installer) BeginOriginalC1Production(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalC1DomainInputs, issuerPrivate []byte) (*OriginalC1Production, OriginalC1DomainStartReceipt, error) {
	var zero OriginalC1DomainStartReceipt
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil || privateDirectory(in.OutputDirectory) != nil {
		return nil, zero, ErrInstall
	}
	before, now, err := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if err != nil || before.cas != (HeadCAS{}) {
		return nil, zero, ErrInstall
	}
	request, err := readRequest(i, in.Request)
	if err != nil {
		return nil, zero, ErrInstall
	}
	ok := false
	defer func() {
		if !ok {
			request.observer.Close()
		}
	}()
	g := request.grant
	if g.UserID != op.userID || g.Username != i.plan.LocalAdminUsername || g.InstallationID != i.plan.Target.InstallationID || g.ServerUUID != i.plan.Target.ServerUUID || g.Database != i.plan.Target.Database || now.Before(request.start) {
		return nil, zero, ErrInstall
	}
	channelRaw, err := readBootstrapSourcePin(in.Channel, 262144)
	var channel ev.ProducerEvidenceChannel
	if err != nil || decodeExact(channelRaw, &channel) != nil || channel.Root == "" || !digestPattern.MatchString(channel.RecoveryProfileHash) {
		return nil, zero, ErrInstall
	}
	// This is the independently selected control-evidence channel, not a
	// permission inferred from a candidate's evidence_store/evidence_write.
	// The real native channel constructor/authority must authenticate it;
	// domain provisioning alone grants no provider access.
	if !digestPattern.MatchString(channel.Store.Identity) || !digestPattern.MatchString(channel.Write.Identity) || channel.Store.Version == "" || channel.Write.Version == "" {
		return nil, zero, ErrInstall
	}

	reportRaw, err := readBootstrapSourcePin(in.CapacityReport, 65536)
	if err != nil {
		return nil, zero, ErrInstall
	}
	report, err := sec.ParseCapacityReport(reportRaw)
	if err != nil || report.ServerUUID != g.ServerUUID || report.Database != g.Database || report.ObservedAt.IsZero() || report.AllocatedBytes < 0 || report.AvailableBytes < 0 {
		return nil, zero, ErrInstall
	}
	report.ObservedAt = report.ObservedAt.UTC()
	var fields map[string]json.RawMessage
	if json.Unmarshal(request.config.CanonicalJSON(), &fields) != nil {
		return nil, zero, ErrInstall
	}
	capacity, err := strconv.ParseInt(string(fields["control_metadata_capacity_bytes"]), 10, 64)
	if err != nil || capacity < 1<<30 || capacity > 1<<40 {
		return nil, zero, ErrInstall
	}
	digests, err := bs.ConfigCandidateHashes(request.config)
	if err != nil {
		return nil, zero, ErrInstall
	}
	entropy := make([]byte, 16)
	if _, err = rand.Read(entropy); err != nil {
		return nil, zero, ErrInstall
	}
	policy, err := canonical(struct{ Version, Plan, Enrollment, Config string }{"original-enrolled-c1-dependency-policy.v1", i.planHash, enrollment.DocumentSHA256, request.config.SHA256()})
	if err != nil {
		return nil, zero, ErrInstall
	}
	admission := pd.UnconfiguredAdmission{Scenario: "unconfigured", DeploymentAdmissionID: pd.ID("c1-" + hex.EncodeToString(entropy)), CandidateHash: pd.Hash(digests.CandidateHash), RegistrySetHash: pd.Hash(digests.RegistrySetHash), RefSetHash: pd.Hash(digests.RefSetHash), PolicyHash: pd.Hash(hash(policy)), ChannelProfileHash: pd.Hash(hash(channelRaw))}
	until := minTime(op.until, request.end)
	if !now.Before(until) || !originalC1CapacityFresh(report, now) {
		return nil, zero, ErrInstall
	}
	scope := pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)}
	source := originalC1DomainSource{Version: originalC1DomainSourceVersion, PlanSHA256: i.planHash, Enrollment: enrollment, Request: in.Request, Channel: in.Channel, CapacityReport: in.CapacityReport, Scope: scope, ActorID: op.userID, Username: g.Username, InstallerAccount: i.plan.InstallerDatabaseAccount, Admission: admission, NotBefore: now, Until: until}
	raw, err := canonical(source)
	if err != nil {
		return nil, zero, ErrInstall
	}
	key, err := op.privateKey(issuerPrivate)
	if err != nil {
		return nil, zero, ErrInstall
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(originalC1DomainSourceVersion+"\x00"), raw...))
	// No earlier source file is overwritten, including after a lost commit reply.
	if request.recheck(i) != nil || op.authority(ctx, enrollment) != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"c1-domain.source.json": raw, "c1-domain.source.signature": signature}) != nil {
		return nil, zero, ErrInstall
	}
	p := &OriginalC1Production{ctx: ctx, operator: op, request: request, enrollment: enrollment, input: in, channel: channel, admission: admission, profile: bytes.Clone(raw), signature: bytes.Clone(signature), profileSHA: hash(raw), report: report, capacity: capacity, until: until}
	p.origin = p
	if p.recheckPrepared() != nil {
		return nil, zero, ErrInstall
	}
	open := pd.DomainOpenRequest{Scope: scope, Operation: "provision", ExpectedEpoch: "0", ExpectedRowVersion: "0", DeploymentHash: pd.Hash(p.profileSHA)}
	service, err := pd.NewDomainOpener(i.db, scope, &originalC1DomainEnvironment{source: p, request: open})
	if err != nil {
		return nil, zero, err
	}
	domain, err := service.OpenDomain(ctx, open)
	receipt := OriginalC1DomainStartReceipt{Version: "original-c1-domain-start.v1", State: "original_domain_commit_unconfirmed_no_retry", Source: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "c1-domain.source.json"), SHA256: hash(raw)}, Signature: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "c1-domain.source.signature"), SHA256: hash(signature)}, Domain: domain}
	if err != nil {
		p.failed = true
		return nil, receipt, err
	}
	p.domain = domain
	receipt.State = "original_domain_committed_not_a_complete_producer"
	ok = true
	return p, receipt, nil
}

func originalC1CapacityFresh(r sec.CapacityReport, now time.Time) bool {
	return !now.IsZero() && !now.Before(r.ObservedAt) && now.Sub(r.ObservedAt) <= 5*time.Second
}

func (p *OriginalC1Production) live(ctx context.Context) bool {
	return p != nil && p.origin == p && !p.failed && consumerSameContext(ctx, p.ctx) && p.operator.live(ctx) && time.Now().Before(p.until)
}
func (p *OriginalC1Production) recheckPrepared() error {
	if !p.live(p.ctx) || p.request.recheck(p.operator.installer) != nil || p.operator.authority(p.ctx, p.enrollment) != nil {
		return ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{p.input.Channel, p.input.CapacityReport, {File: filepath.Join(p.input.OutputDirectory, "c1-domain.source.json"), SHA256: p.profileSHA}} {
		if _, err := readBootstrapSourcePin(pin, 262144); err != nil {
			return ErrInstall
		}
	}
	signature, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: filepath.Join(p.input.OutputDirectory, "c1-domain.source.signature"), SHA256: hash(p.signature)}, 64)
	if err != nil || !ed25519.Verify(p.operator.installer.public, append([]byte(originalC1DomainSourceVersion+"\x00"), p.profile...), signature) {
		return ErrInstall
	}
	return nil
}

type originalC1DomainEnvironment struct {
	source  *OriginalC1Production
	request pd.DomainOpenRequest
}
type originalC1DomainSession struct {
	source         *OriginalC1Production
	request        pd.DomainOpenRequest
	hash           pd.Hash
	connection     uint64
	reserved       bool
	sample         time.Time
	floor          int64
	intent, result bool
	gateFound      bool
}

func (e *originalC1DomainEnvironment) PrepareDomainOpen(ctx context.Context, request pd.DomainOpenRequest) (pd.PreparedDomainOpen, error) {
	if e == nil || e.source == nil || !e.source.live(ctx) || request != e.request || e.source.recheckPrepared() != nil {
		return pd.PreparedDomainOpen{}, ErrInstall
	}
	hash, err := pd.DomainOpenHash(request)
	if err != nil {
		return pd.PreparedDomainOpen{}, err
	}
	return pd.PreparedDomainOpen{Session: &originalC1DomainSession{source: e.source, request: request, hash: hash}, CapacityObservedAt: e.source.report.ObservedAt}, nil
}

// Complete common installation/config absence ranges precede the C1 domain.
func (s *originalC1DomainSession) LockInstallation(ctx context.Context, tx pd.SQL, request pd.DomainOpenRequest) error {
	if !s.source.live(ctx) || request != s.request {
		return ErrInstall
	}
	// Match original provider/adoption order: gate before config/domain/admin.
	var gate string
	gateErr := tx.QueryRowContext(ctx, "SELECT gate_state FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE", string(request.Scope.Installation), controller.CaptureGateScope).Scan(&gate)
	if gateErr == nil {
		s.gateFound = true
		if gate != "idle" {
			return ErrInstall
		}
	} else if !errors.Is(gateErr, sql.ErrNoRows) {
		return ErrInstall
	}

	var account, server, database, role string
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),CURRENT_ROLE(),CONNECTION_ID()").Scan(&account, &server, &database, &role, &s.connection) != nil || account != s.source.operator.installer.plan.InstallerDatabaseAccount || server != string(request.Scope.ServerUUID) || database != string(request.Scope.Database) || role != "NONE" || s.connection == 0 {
		return ErrInstall
	}
	rows, err := tx.QueryContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE")
	if err != nil {
		return ErrInstall
	}
	count := 0
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || id == string(request.Scope.Installation) || count >= 10000 {
			rows.Close()
			return ErrInstall
		}
		count++
	}
	if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
		return ErrInstall
	}
	rows, err = tx.QueryContext(ctx, "SELECT id,origin_installation_id,version,config_sha256,enabled,nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version FOR UPDATE")
	if err != nil {
		return ErrInstall
	}
	for rows.Next() {
		var id, version, config, enabled, nonceVersion, nonceIdentity any
		var installation string
		if rows.Scan(&id, &installation, &version, &config, &enabled, &nonceVersion, &nonceIdentity) != nil || installation == string(request.Scope.Installation) {
			rows.Close()
			return ErrInstall
		}
	}
	if rows.Err() != nil || rows.NextResultSet() || rows.Close() != nil {
		return ErrInstall
	}
	return nil
}

func (s *originalC1DomainSession) current(ctx context.Context, tx pd.ReadSQL) error {
	p := s.source
	if !p.live(ctx) {
		return ErrInstall
	}
	var connection uint64
	if tx.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&connection) != nil || connection != s.connection {
		return ErrInstall
	}
	var username, stored, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT username,password_hash,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE", p.operator.userID).Scan(&username, &stored, &role, &active, &provider) != nil || username != p.operator.installer.plan.LocalAdminUsername || stored != p.operator.password || role != "admin" || !active || provider != "local" {
		return ErrInstall
	}
	var revision uint64
	err := tx.QueryRowContext(ctx, "SELECT head_revision FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=? FOR SHARE", p.request.grant.InstallationID, p.operator.installer.plan.EnrollmentID).Scan(&revision)
	if !errors.Is(err, sql.ErrNoRows) {
		return ErrInstall
	}
	return nil
}

func (s *originalC1DomainSession) Authorize(ctx context.Context, tx pd.SQL, request pd.DomainOpenRequest, prior *pd.DomainRecord) (pd.DomainOpenAdmission, error) {
	if request != s.request || prior != nil || s.current(ctx, tx) != nil {
		return pd.DomainOpenAdmission{}, ErrInstall
	}
	p := s.source
	// ManagementAllowed is produced ONLY after the actual original native
	// enrollment + live independent local-admin/first-head SQL checks above.
	until := pd.Timestamp(p.until.UTC().Format("2006-01-02T15:04:05.000000Z"))
	return pd.DomainOpenAdmission{VerifiedRequestHash: s.hash, IdentityExpiresAt: until, IssuerIdentityHash: pd.Hash(hash(p.operator.installer.public)), Admission: pd.Admission{Unconfigured: &p.admission}, AdmissionExpiresAt: until, AdditionalCost: "16384", ManagementAllowed: true}, nil
}

func (s *originalC1DomainSession) Reserve(ctx context.Context, tx pd.SQL, request pd.DomainOpenRequest, cost uint64) error {
	if request != s.request || !s.source.live(ctx) || s.reserved || cost == 0 || cost > math.MaxInt64 {
		return ErrInstall
	}
	write, ok := tx.(*pd.Transaction)
	if !ok {
		return ErrInstall
	}
	now, err := write.SampleTime(ctx)
	p := s.source
	if err != nil || !originalC1CapacityFresh(p.report, now) {
		return ErrInstall
	}
	reserve := p.capacity / 20
	if reserve < 67108864 {
		reserve = 67108864
	}
	if p.report.AvailableBytes < p.capacity+reserve+int64(cost) {
		return ErrInstall
	}
	if _, err = tx.ExecContext(ctx, "INSERT IGNORE INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES (1,?,0)", p.report.ObservedAt); err != nil {
		return ErrInstall
	}
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&s.sample, &outstanding) != nil || s.sample.IsZero() || p.report.ObservedAt.Before(s.sample) || outstanding < 0 || int64(cost) > p.capacity || outstanding > p.capacity-int64(cost) || p.report.AllocatedBytes > p.capacity-outstanding-int64(cost) {
		return ErrInstall
	}
	if write.CAS(ctx, "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=reserved_bytes+? WHERE id=1 AND sample_at=? AND reserved_bytes=?", int64(cost), s.sample, outstanding) != nil {
		return ErrInstall
	}
	s.floor = outstanding + int64(cost)
	s.reserved = true
	return nil
}

func (s *originalC1DomainSession) Audit(ctx context.Context, tx pd.SQL, request pd.DomainOpenRequest, phase string) error {
	if request != s.request || !s.source.live(ctx) || !s.reserved || phase != "intent" && phase != "result" || phase == "intent" && s.intent || phase == "result" && (!s.intent || s.result) {
		return ErrInstall
	}
	details, err := canonical(struct{ Version, Request, Installation string }{"original-enrolled-c1-domain-audit.v1", string(s.hash), string(request.Scope.Installation)})
	if err != nil || len(details) > 4096 {
		return ErrInstall
	}
	write, ok := tx.(*pd.Transaction)
	if !ok || write.CAS(ctx, "INSERT INTO audit_logs (user_id,action,resource_type,details) VALUES (?,?,'system_backup',?)", s.source.operator.userID, "system_backup.c1_domain."+phase, string(details)) != nil {
		return ErrInstall
	}
	if phase == "intent" {
		s.intent = true
	} else {
		s.result = true
	}
	return nil
}

func (s *originalC1DomainSession) Recheck(ctx context.Context, tx pd.ReadSQL, request pd.DomainOpenRequest, domain pd.DomainRecord, now time.Time) error {
	if request != s.request || !s.reserved || !s.intent || !s.result || !s.source.live(ctx) || !originalC1CapacityFresh(s.source.report, now) || !now.Before(s.source.until) || s.current(ctx, tx) != nil || domain.Scope != request.Scope || domain.State != "open" || domain.Epoch != "1" || domain.RowVersion != "1" || !reflect.DeepEqual(domain.Admission, pd.Admission{Unconfigured: &s.source.admission}) || domain.IssuerIdentityHash != pd.Hash(hash(s.source.operator.installer.public)) {
		return ErrInstall
	}
	var gate string
	gateErr := tx.QueryRowContext(ctx, "SELECT gate_state FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR SHARE", string(request.Scope.Installation), controller.CaptureGateScope).Scan(&gate)
	if s.gateFound {
		if gateErr != nil || gate != "idle" {
			return ErrInstall
		}
	} else if !errors.Is(gateErr, sql.ErrNoRows) {
		return ErrInstall
	}

	// The callback argument is not a readback proof. Re-read the original
	// already-locked C1 domain with the closed storage decoder/projections.
	var actual pd.DomainRecord
	found, err := pd.ReadOriginalSharedRecord(ctx, tx, request.Scope, pd.RecordKey{}, &actual)
	if err != nil || !found || !reflect.DeepEqual(actual, domain) {
		return ErrInstall
	}
	// These target absence ranges were already held by the complete L0/1
	// locks. Detect same-transaction side effects without a new lock range.
	var present string
	if !errors.Is(tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_installation_state WHERE origin_installation_id=?", string(request.Scope.Installation)).Scan(&present), sql.ErrNoRows) {
		return ErrInstall
	}
	if !errors.Is(tx.QueryRowContext(ctx, "SELECT origin_installation_id FROM system_backup_v2_configs WHERE origin_installation_id=?", string(request.Scope.Installation)).Scan(&present), sql.ErrNoRows) {
		return ErrInstall
	}
	var sample time.Time
	var outstanding int64
	if tx.QueryRowContext(ctx, "SELECT sample_at,reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1 FOR UPDATE").Scan(&sample, &outstanding) != nil || !sample.Equal(s.sample) || outstanding < s.floor || outstanding > s.source.capacity-s.source.report.AllocatedBytes {
		return ErrInstall
	}
	return nil
}

var _ pd.DomainOpenEnvironment = (*originalC1DomainEnvironment)(nil)
var _ pd.DomainOpenSession = (*originalC1DomainSession)(nil)
