package systembackupapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	contract "clawreef/internal/systembackupcontract"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

// TaskWriter performs local decoding/defaults/JCS before SQL. Prepare must not
// contact providers, create resources or read credentials: current SQL authority
// has not yet been checked. There is no default/no-op implementation.
type TaskWriter interface {
	Prepare(context.Context, read.TaskKind, string, json.RawMessage) (PreparedTaskWrite, error)
}

// Stage runs after A's action authorization, inside the ONLY transaction. It
// must implement current effective-enabled, existing key/hash/history replay,
// capacity/audit and atomic task + config snapshot + next_reconcile_at enqueue.
// It must not call providers, dispatch a Job, commit, or retain SQL capabilities.
// It applies the existing domain lock order and completes its own fixed final
// SQL guards before returning. No owner callback runs after A's final recheck.
type PreparedTaskWrite interface {
	Stage(TaskWriteSQL, TaskSubmissionIdentity) (read.TaskHeader, error)
}

type TaskSubmissionIdentity struct {
	InstallationID, ActorID, Endpoint, IdempotencyKey string
}

type TaskWriteSQL interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) TaskRow
}
type TaskRow interface{ Scan(...any) error }

// Details must use these exact request-bound read scopes and the existing
// repeatable-read/final-authority boundary. Persisted hints alone cannot replace
// current B/C provider facts in a complete Backup/PreflightDetailResource.
type TaskDetails interface {
	Backup(context.Context, *security.SystemBackupReadScope, string) (contract.BackupDetailResource, error)
	Preflight(context.Context, *security.SystemBackupReadScope, string) (contract.PreflightDetailResource, error)
}

type SQLApplication struct {
	db                       *sql.DB
	actions                  *security.SystemBackupActionAuthorizer
	reads                    *security.SystemBackupReadAuthorizer
	writer                   TaskWriter
	details                  TaskDetails
	budget                   time.Duration
	cancellationCapacityFile string
}

func NewSQLApplication(db *sql.DB, actions *security.SystemBackupActionAuthorizer, reads *security.SystemBackupReadAuthorizer,
	writer TaskWriter, details TaskDetails, admissionBudget time.Duration) (*SQLApplication, error) {
	if db == nil || actions == nil || reads == nil || nilDependency(writer) || nilDependency(details) || admissionBudget <= 0 || admissionBudget > time.Minute {
		return nil, &Error{"not_ready"}
	}
	app := &SQLApplication{db: db, actions: actions, reads: reads, writer: writer, details: details, budget: admissionBudget}
	if w, ok := writer.(*SQLTaskWriter); ok {
		app.cancellationCapacityFile = w.capacityFile
	}
	return app, nil
}

// WithCancellationCapacityReport keeps recovery independent of the capture
// profile/runner. It returns a copy; live requests never observe a partial edit.
func (s *SQLApplication) WithCancellationCapacityReport(path string) *SQLApplication {
	if s == nil {
		return nil
	}
	copy := *s
	copy.cancellationCapacityFile = path
	return &copy
}

func (s *SQLApplication) CreateAndEnqueue(r *http.Request, kind read.TaskKind, endpoint, key string, body json.RawMessage) (read.TaskHeader, error) {
	if s == nil || s.db == nil || s.actions == nil || nilDependency(s.writer) {
		return read.TaskHeader{}, &Error{"not_ready"}
	}
	_, expected, _ := taskRoute(kind)
	if expected == "" || expected != endpoint || r == nil || key != r.Header.Get("Idempotency-Key") {
		return read.TaskHeader{}, &Error{"validation_failed"}
	}
	scope, err := s.actions.Scope(r, endpoint)
	if err != nil {
		return read.TaskHeader{}, applicationError(err)
	}
	ctx, cancel := context.WithTimeout(scope.Context(), s.budget)
	defer cancel()
	prepared, err := s.writer.Prepare(ctx, kind, endpoint, append(json.RawMessage(nil), body...))
	if err != nil {
		return read.TaskHeader{}, applicationError(err)
	}
	if nilDependency(prepared) || ctx.Err() != nil {
		return read.TaskHeader{}, &Error{"not_ready"}
	}
	return s.submit(ctx, scope, prepared, kind, endpoint, key)
}

// Private seam permits a SQL-driver model to test the transaction owner. The
// public API above can obtain a scope only from the concrete A authorizer.
type taskActionScope interface {
	AuthorizeAction(context.Context, *sql.Tx) (string, error)
	RecheckAction(context.Context, *sql.Tx, string) error
	Actor() security.RegistrationActor
	IdempotencyKey() string
}

func (s *SQLApplication) submit(ctx context.Context, scope taskActionScope, prepared PreparedTaskWrite, kind read.TaskKind, endpoint, key string) (read.TaskHeader, error) {
	var zero read.TaskHeader
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, &Error{"not_ready"}
	}
	defer tx.Rollback()
	installation, err := scope.AuthorizeAction(ctx, tx)
	if err != nil {
		return zero, applicationError(err)
	}
	identity := TaskSubmissionIdentity{installation, strconv.FormatInt(scope.Actor().UserID, 10), endpoint, scope.IdempotencyKey()}
	if scope.Actor().UserID < 1 || identity.IdempotencyKey != key {
		return zero, &Error{"permission_denied"}
	}
	capability := newTaskSQLCapability(ctx, tx)
	defer capability.close()
	task, err := prepared.Stage(capability, identity)
	closedOK := capability.close()
	if err != nil {
		var expired *ExpiredTaskError
		if errors.As(err, &expired) {
			if !closedOK || ctx.Err() != nil {
				return zero, &Error{"not_ready"}
			}
			if e := scope.RecheckAction(ctx, tx, installation); e != nil {
				return zero, applicationError(e)
			}
		}
		return zero, applicationError(err)
	}
	if !closedOK || ctx.Err() != nil {
		return zero, &Error{"not_ready"}
	}
	if _, err = read.ProjectTask(task); err != nil || task.Kind != kind || task.InstallationID != installation || task.ActorType != "admin" || task.ActorID != identity.ActorID || task.Endpoint != endpoint || task.IdempotencyKey != key {
		return zero, &Error{"not_ready"}
	}
	if err = scope.RecheckAction(ctx, tx, installation); err != nil {
		return zero, applicationError(err)
	}
	if !capability.close() || ctx.Err() != nil {
		return zero, &Error{"not_ready"}
	}
	// Unknown commit is never retried here. The exact original body/key must
	// re-enter Stage's authorized durable history branch on a later request.
	if err = tx.Commit(); err != nil || ctx.Err() != nil {
		return zero, &Error{"not_ready"}
	}
	return task, nil
}

func (s *SQLApplication) ReadBackup(r *http.Request, id string) (contract.BackupDetailResource, error) {
	if s == nil || s.reads == nil || nilDependency(s.details) {
		return contract.BackupDetailResource{}, &Error{"not_ready"}
	}
	scope, err := s.reads.Scope(r)
	if err != nil {
		return contract.BackupDetailResource{}, applicationError(err)
	}
	result, err := s.details.Backup(scope.Context(), scope, id)
	return result, applicationError(err)
}
func (s *SQLApplication) ReadPreflight(r *http.Request, id string) (contract.PreflightDetailResource, error) {
	if s == nil || s.reads == nil || nilDependency(s.details) {
		return contract.PreflightDetailResource{}, &Error{"not_ready"}
	}
	scope, err := s.reads.Scope(r)
	if err != nil {
		return contract.PreflightDetailResource{}, applicationError(err)
	}
	result, err := s.details.Preflight(scope.Context(), scope, id)
	return result, applicationError(err)
}
func applicationError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, security.ErrSystemBackupReadAuthentication):
		return &Error{"authentication_required"}
	case errors.Is(err, security.ErrSystemBackupActionValidation), errors.Is(err, read.ErrInvalid):
		return &Error{"validation_failed"}
	case errors.Is(err, security.ErrRegistrationPermission), errors.Is(err, read.ErrDenied):
		return &Error{"permission_denied"}
	case errors.Is(err, read.ErrNotFound):
		return &Error{"not_found"}
	case errors.Is(err, security.ErrRegistrationUnavailable), errors.Is(err, security.ErrProviderEvidenceStorage), errors.Is(err, read.ErrUnavailable):
		return &Error{"not_ready"}
	default:
		return err
	}
}

// The shared pointer closes retained/copy capabilities before final authority.
// It binds the original context and offers no Tx/DB/Begin/Commit/Rollback handle.
type taskSQLCapability struct{ state *taskSQLState }
type taskSQLState struct {
	mu           sync.Mutex
	ctx          context.Context
	tx           *sql.Tx
	open, failed bool
	rows         map[*sql.Rows]bool
}

func newTaskSQLCapability(ctx context.Context, tx *sql.Tx) *taskSQLCapability {
	return &taskSQLCapability{&taskSQLState{ctx: ctx, tx: tx, open: true, rows: map[*sql.Rows]bool{}}}
}
func (c *taskSQLCapability) close() bool {
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open = false
	for rows := range s.rows {
		if err := rows.Close(); err != nil {
			s.failed = true
		}
		delete(s.rows, rows)
	}
	return !s.failed
}
func (s *taskSQLState) allow(query string) bool {
	query = strings.ToUpper(strings.TrimSpace(query))
	return s.open && !s.failed && s.ctx.Err() == nil && !strings.ContainsAny(query, ";\x00") &&
		(strings.HasPrefix(query, "SELECT ") || strings.HasPrefix(query, "INSERT INTO ") || strings.HasPrefix(query, "UPDATE ") || strings.HasPrefix(query, "DELETE FROM "))
}
func (c *taskSQLCapability) Exec(query string, args ...any) (sql.Result, error) {
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allow(query) {
		s.failed = true
		return nil, &Error{"not_ready"}
	}
	result, err := s.tx.ExecContext(s.ctx, query, args...)
	if err != nil {
		s.failed = true
	}
	return result, err
}

type taskSQLRow struct {
	scope *taskSQLState
	rows  *sql.Rows
	err   error
}

func (c *taskSQLCapability) QueryRow(query string, args ...any) TaskRow {
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allow(query) {
		s.failed = true
		return taskSQLRow{scope: s, err: &Error{"not_ready"}}
	}
	rows, err := s.tx.QueryContext(s.ctx, query, args...)
	if err != nil {
		s.failed = true
		return taskSQLRow{scope: s, err: err}
	}
	s.rows[rows] = true
	return taskSQLRow{scope: s, rows: rows}
}
func (r taskSQLRow) Scan(values ...any) error {
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if !r.scope.open || r.err != nil || !r.scope.rows[r.rows] {
		r.scope.failed = true
		return &Error{"not_ready"}
	}
	defer func() {
		if err := r.rows.Close(); err != nil {
			r.scope.failed = true
		}
		delete(r.scope.rows, r.rows)
	}()
	var err error
	if !r.rows.Next() {
		err = r.rows.Err()
		if err == nil {
			err = sql.ErrNoRows
		}
	} else {
		err = r.rows.Scan(values...)
	}
	// An authorized same-key lookup miss is a normal new-creation branch.
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		r.scope.failed = true
	}
	return err
}
