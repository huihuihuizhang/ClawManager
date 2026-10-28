package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sort"
	"strings"
	"time"

	metadata "clawreef/internal/systembackupgcmetadata"
)

var ErrDownloadRetentionGCReleaseUnknown = errors.New("download_retention_gc_release_unknown")

// DownloadGCFullFreezeConfig is trusted, opt-in deployment configuration, not
// an HTTP DTO or permission approval. The existing mandatory Policy must still
// cover current worker authority and ALL owner/catalog/import/logical ranges.
// This adapter adds actual session/grant checks, protected structural/program
// observations and the sole freeze/transaction owner; it supplies no allow
// policy for missing domains. Exact grants, pins, DDL coverage, capacity and
// failure takeover require deployment review and actual MySQL acceptance.
type DownloadGCFullFreezeConfig struct {
	// Connect must create a new physical session, not return a borrowed pool
	// session with temporary tables or stale settings. No shared DB is used.
	Connector   driver.Connector
	WaitSeconds int
	Worker      DownloadGCEarlyReferenceConfig
	// Independent privileged account, pinned to the same server/database.
	Observer       metadata.Config
	ProgramsSHA256 string
}

func (DownloadGCFullFreezeConfig) String() string               { return "DownloadGCFullFreezeConfig" }
func (DownloadGCFullFreezeConfig) GoString() string             { return "DownloadGCFullFreezeConfig" }
func (DownloadGCFullFreezeConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

type downloadGCFullFreeze struct {
	connector driver.Connector
	wait      int
	worker    *SQLDownloadGCEarlyReferences
	observer  *metadata.Source
	programs  string
	authority DownloadGCFullFreezeAuthority
	scope     DownloadGCFreezeScope
}

// No implementation is supplied here. Deployment authority must authenticate
// current reviewed protocol evidence for the exact MySQL/profile/metadata
// scope, including empty-to-new program DDL, cancellation and takeover. A pin
// alone or a caller-supplied boolean is not that evidence. Reads only; no DDL,
// GRANT, nested transaction, unlock, renewed authority or mutation is allowed.
type DownloadGCFullFreezeAuthority interface {
	DownloadRetentionGCPolicy
	AdmitFreezeSession(context.Context, *sql.Conn, DownloadGCFreezeScope) error
}

type DownloadGCFreezeScope struct {
	ServerUUID, Database, Installation, WorkerOperation      string
	WorkerAccount, ObserverAccount, MySQLVersion             string
	WorkerGrantsSHA256, ObserverGrantsSHA256, ProgramsSHA256 string
	Metadata                                                 DownloadGCMetadataPins
	MaintenanceReceipts                                      string
	SessionID                                                int64
	BackupLockHeld                                           bool
	ConfigVersion, WorkerRowVersion                          int64
	ConfigSHA256, PeerCertificateSHA256                      string
	AuthorityExpiresAt                                       time.Time
}

func (DownloadGCFreezeScope) String() string               { return "DownloadGCFreezeScope" }
func (DownloadGCFreezeScope) GoString() string             { return "DownloadGCFreezeScope" }
func (DownloadGCFreezeScope) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

func newDownloadGCFullFreeze(c DownloadGCFullFreezeConfig, collector DownloadRetentionGCConfig) (*downloadGCFullFreeze, error) {
	r := collector.Registry
	authority, approvedProfile := collector.Policy.(DownloadGCFullFreezeAuthority)
	if !approvedProfile || nilSystemAdapter(authority) || nilSystemAdapter(c.Connector) || c.WaitSeconds < 1 || c.WaitSeconds > 5 ||
		c.Worker.Database.ServerUUID != r.ServerUUID || c.Worker.Database.Database != r.Database || c.Worker.Installation != r.Installation ||
		collector.References == nil || c.Worker.MaintenanceReceipts != collector.References.c.MaintenanceReceipts ||
		c.Observer.ServerUUID != r.ServerUUID || c.Observer.Database != r.Database || c.Observer.Account == c.Worker.Account ||
		!digestPattern.MatchString(c.ProgramsSHA256) {
		return nil, ErrDenied
	}
	worker, err := NewSQLDownloadGCEarlyReferences(c.Worker)
	if err != nil {
		return nil, ErrDenied
	}
	observer, err := metadata.New(c.Observer)
	if err != nil {
		return nil, ErrDenied
	}
	return &downloadGCFullFreeze{connector: c.Connector, wait: c.WaitSeconds, worker: worker, observer: observer, programs: c.ProgramsSHA256, authority: authority,
		scope: DownloadGCFreezeScope{ServerUUID: r.ServerUUID, Database: r.Database, Installation: r.Installation, WorkerOperation: collector.OperationID,
			WorkerAccount: c.Worker.Account, ObserverAccount: c.Observer.Account, MySQLVersion: c.Observer.Version, WorkerGrantsSHA256: c.Worker.GrantsSHA256, ObserverGrantsSHA256: c.Observer.GrantsSHA256,
			ProgramsSHA256: c.ProgramsSHA256, Metadata: c.Worker.Metadata, MaintenanceReceipts: c.Worker.MaintenanceReceipts,
			ConfigVersion: collector.ConfigVersion, WorkerRowVersion: collector.OperationRowVersion, ConfigSHA256: collector.ConfigSHA256, PeerCertificateSHA256: collector.CertificateSHA256, AuthorityExpiresAt: collector.ExpiresAt}}, nil
}

type downloadGCFullQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// This is a separate profile. Strip the three exact global/observer additions
// and exact reservation-table INSERT for shape validation using Early; hash
// the ORIGINAL complete statement set, including all stripped privileges.
// Early's validator and its historically accepted role are unchanged.
func (f *downloadGCFullFreeze) grants(statements []string) error {
	if f == nil || f.worker == nil || len(statements) < 1 || len(statements) > 256 {
		return ErrDenied
	}
	a := gcSQLAccount.FindStringSubmatch(f.worker.c.Account)
	if len(a) != 3 {
		return ErrDenied
	}
	recipients := []string{"'" + a[1] + "'@'" + a[2] + "'", "`" + a[1] + "`@`" + a[2] + "`"}
	required := map[string]bool{"BACKUP_ADMIN ON *.*": false, "SELECT ON `performance_schema`.`metadata_locks`": false, "SELECT ON `performance_schema`.`threads`": false}
	seen := map[string]bool{}
	reservationInsert := false
	reservationObject := "`" + f.worker.c.Database.Database + "`.`system_backup_v2_metadata_reservations`"
	var base []string
	for _, statement := range statements {
		if len(statement) > 2048 || seen[statement] || !strings.HasPrefix(statement, "GRANT ") {
			return ErrDenied
		}
		seen[statement] = true
		to := strings.LastIndex(statement, " TO ")
		if to < 0 || !oneOf(statement[to+4:], recipients...) {
			return ErrDenied
		}
		body := statement[len("GRANT "):to]
		if used, extra := required[body]; extra {
			if used {
				return ErrDenied
			}
			required[body] = true
		} else {
			// Reserve unconditionally executes INSERT IGNORE before its UPDATE,
			// even when row 1 already exists. Full therefore needs this exact
			// extra table privilege; Early's historical profile is unchanged.
			parts := strings.Split(body, " ON ")
			if len(parts) == 2 && parts[1] == reservationObject {
				var retained []string
				for _, field := range strings.Split(parts[0], ",") {
					field = strings.TrimSpace(field)
					if field == "INSERT" {
						if reservationInsert {
							return ErrDenied
						}
						reservationInsert = true
					} else {
						retained = append(retained, field)
					}
				}
				if len(retained) == 0 {
					continue
				}
				statement = "GRANT " + strings.Join(retained, ", ") + " ON " + reservationObject + " TO " + statement[to+4:]
			}
			base = append(base, statement)
		}
	}
	for _, ok := range required {
		if !ok {
			return ErrDenied
		}
	}
	if !reservationInsert || f.worker.grants(base) != nil {
		return ErrDenied
	}
	// Freeze gets a closed read catalog, independently of the supplied pin.
	// A re-pinned new system_* table must not inherit Early's candidate shape.
	allowed := gcFullReadTables(f.worker.c.MaintenanceReceipts == "installed")
	for _, statement := range base {
		to := strings.LastIndex(statement, " TO ")
		parts := strings.Split(statement[len("GRANT "):to], " ON ")
		if len(parts) != 2 {
			return ErrDenied
		}
		if table := gcSQLTable.FindStringSubmatch(parts[1]); len(table) == 3 && !allowed[table[2]] {
			return ErrDenied
		}
	}
	ss := append([]string(nil), statements...)
	sort.Strings(ss)
	if hash(canonical(ss)) != f.worker.c.GrantsSHA256 {
		return ErrDenied
	}
	return nil
}

func gcFullReadTables(maintenance bool) map[string]bool {
	allowed := map[string]bool{"users": true, "system_backup_v2_evidence": true, "system_backup_v2_evidence_chunks": true}
	for _, table := range gcRequiredReadTables(maintenance) {
		allowed[table] = true
	}
	for key := range gcDirectColumns(maintenance) {
		allowed[strings.SplitN(key, ".", 2)[0]] = true
	}
	for _, table := range []string{"system_backup_v2_backups", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_artifact_lease_states", "system_backup_v2_artifact_leases", "system_backup_v2_staging_resources", "system_backup_v2_restore_drill_resources", "system_backup_v2_promotions", "system_backup_v2_prune_items"} {
		allowed[table] = true
	}
	for _, table := range taskDownloadSystemProducerTables {
		allowed[table] = true
	}
	return allowed
}

func (f *downloadGCFullFreeze) admit(ctx context.Context, q downloadGCFullQuery) error {
	var server, database, account, role string
	var version string
	if ctx == nil || ctx.Err() != nil || q.QueryRowContext(ctx, downloadGCEarlyAccountSQL).Scan(&server, &database, &account, &role) != nil ||
		server != f.worker.c.Database.ServerUUID || database != f.worker.c.Database.Database || account != f.worker.c.Account || role != "NONE" {
		return ErrDenied
	}
	if q.QueryRowContext(ctx, "SELECT @@version").Scan(&version) != nil || version != f.scope.MySQLVersion {
		return ErrDenied
	}
	rows, err := q.QueryContext(ctx, downloadGCEarlyGrantsSQL)
	if err != nil {
		return ErrDenied
	}
	defer rows.Close()
	var statements []string
	for rows.Next() {
		var statement string
		if len(statements) >= 256 || rows.Scan(&statement) != nil {
			return ErrDenied
		}
		statements = append(statements, statement)
	}
	if rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return ErrDenied
	}
	return f.grants(statements)
}

func (f *downloadGCFullFreeze) observe(ctx context.Context, _ *sql.Conn) error {
	// Invoked only by the fixed owner after exact holder acquisition, before
	// Begin. No observer network call occurs in the post-ticket finalizer.
	o, err := f.observer.Read(ctx)
	if err != nil || o.Digests().Combined != f.programs || ctx.Err() != nil {
		return ErrDenied
	}
	return nil
}

func (f *downloadGCFullFreeze) admitSession(ctx context.Context, conn *sql.Conn, held bool) error {
	if f.admit(ctx, conn) != nil {
		return ErrDenied
	}
	var server, database, account, role, zone string
	var id int64
	var tickets int
	expected := 0
	if held {
		expected = 1
	}
	if conn.QueryRowContext(ctx, downloadGCFreezeSessionSQL).Scan(&server, &database, &account, &role, &zone, &id) != nil || server != f.scope.ServerUUID || database != f.scope.Database || account != f.scope.WorkerAccount || role != "NONE" || zone != "+00:00" || id <= 0 || conn.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&tickets) != nil || tickets != expected {
		return ErrDenied
	}
	scope := f.scope
	scope.SessionID = id
	scope.BackupLockHeld = tickets == 1
	if f.authority.AdmitFreezeSession(ctx, conn, scope) != nil || ctx.Err() != nil {
		return ErrDenied
	}
	return nil
}

// The domain policy remains mandatory; a structural/program pin is not a
// substitute for semantic reference/hold/catalog eligibility or revocation.
type downloadGCFullFreezePolicy struct {
	freeze *downloadGCFullFreeze
	domain DownloadRetentionGCPolicy
}

func (p *downloadGCFullFreezePolicy) verify(ctx context.Context, tx *sql.Tx) error {
	var tickets int
	if p.freeze.admit(ctx, tx) != nil || tx.QueryRowContext(ctx, downloadGCFreezeHeldSQL).Scan(&tickets) != nil || tickets != 1 || p.freeze.worker.metadata(ctx, tx) != nil {
		return ErrDenied
	}
	return nil
}

func (p *downloadGCFullFreezePolicy) Early(ctx context.Context, tx *sql.Tx, h DownloadGCEarlyScope, now time.Time) (DownloadRetentionGCGuard, error) {
	if p == nil || p.freeze == nil || ctx == nil || ctx.Err() != nil || tx == nil || !validGCEarlyScope(p.freeze.worker.c, h) || p.verify(ctx, tx) != nil {
		return nil, ErrDenied
	}
	g, err := p.domain.Early(ctx, tx, h, now)
	if err != nil || nilSystemAdapter(g) {
		return nil, ErrDenied
	}
	return &downloadGCFullFreezeGuard{policy: p, tx: tx, hint: h, domain: g, state: &downloadGCEarlyReferenceState{}}, nil
}

func (p *downloadGCFullFreezePolicy) Lock(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, now time.Time) (DownloadRetentionGCGuard, error) {
	return p.domain.Lock(ctx, tx, scope, now)
}

type downloadGCFullFreezeGuard struct {
	policy *downloadGCFullFreezePolicy
	tx     *sql.Tx
	hint   DownloadGCEarlyScope
	domain DownloadRetentionGCGuard
	state  *downloadGCEarlyReferenceState
}

func (g *downloadGCFullFreezeGuard) Recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, now time.Time) error {
	if g == nil || g.state == nil {
		return ErrDenied
	}
	g.state.Lock()
	defer g.state.Unlock()
	fail := func() error { g.state.failed = true; return ErrDenied }
	h := g.hint
	if g.state.failed || ctx == nil || ctx.Err() != nil || tx == nil || tx != g.tx || s.Database != h.Database || s.Installation != h.Installation || s.WorkerOperation != h.WorkerOperation || s.PrincipalSHA256 != h.PrincipalSHA256 || s.Operation != h.Operation || s.OperationID != h.OperationID || s.ActorID != h.ActorID || s.IntentAuditID != h.IntentAuditID || s.ResultAuditID != h.ResultAuditID || g.policy.verify(ctx, tx) != nil || g.domain.Recheck(ctx, tx, s, now) != nil {
		return fail()
	}
	return nil
}

func (s *SQLDownloadRetentionGC) collectWithFullFreeze(ctx context.Context, operation string) error {
	// Bound work by the original peer and caller, without extending either.
	peer, err := pinnedPeerExpiry(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt)
	if err != nil {
		return ErrDenied
	}
	ctx, cancel := context.WithDeadline(ctx, earlier(peer, time.Now().Add(30*time.Second)))
	defer cancel()
	capacity, err := s.c.Capacity.PreparePinned(ctx, s.c.MeasuredReservationBytes)
	if err != nil {
		return ErrAudit
	}
	f := s.freeze
	admissions := 0
	out, err := s.collectFrozenWithPreparedCapacity(ctx, downloadGCFreezeConfig{
		Connector: f.connector, Server: f.worker.c.Database.ServerUUID, Database: f.worker.c.Database.Database,
		Account: f.worker.c.Account, WaitSeconds: f.wait,
		Admit: func(ctx context.Context, conn *sql.Conn) error {
			held := admissions > 0
			admissions++
			return f.admitSession(ctx, conn, held)
		}, Observe: f.observe,
	}, operation, capacity)
	// Preserve all unknown outcomes; no private driver error/identity escapes.
	var failures []error
	if errors.Is(err, errDownloadGCFreezeCommitUnknown) {
		failures = append(failures, ErrDownloadRetentionGCCommitUnknown)
	}
	if errors.Is(err, errDownloadGCFreezeRollbackUnknown) {
		failures = append(failures, ErrDownloadRetentionGCRollbackUnknown)
	}
	if out.Unlock == "unknown" {
		failures = append(failures, ErrDownloadRetentionGCReleaseUnknown)
	}
	if len(failures) == 1 {
		return failures[0]
	}
	if len(failures) > 1 {
		return errors.Join(failures...)
	}
	if err != nil {
		if err == errDownloadGCFreezeDenied {
			return ErrDenied
		}
		return boundary(err)
	}
	return nil
}
