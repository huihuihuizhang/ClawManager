//go:build linux

package install

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	c "clawreef/internal/systembackupcontroller"
	owner "clawreef/internal/systembackupinstallationowner"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// SQL/API permission protocol MODEL plus real private durable journal and real
// bcrypt/Ed25519 validation. Actors below are fixtures, never physical proofs.
// This suite does not execute native source recovery, MySQL or a real cluster.
type originalRecoveryTestModel struct {
	f                *authorityFixture
	set              *PreparedOriginalWriterSet
	permissionDenied atomic.Bool
	gateDrift        bool
	order            []string
}
type originalRecoveryTestConnector struct{ m *originalRecoveryTestModel }

func (d originalRecoveryTestConnector) Driver() driver.Driver { return authDriver{} }
func (d originalRecoveryTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &originalRecoveryTestConn{m: d.m, base: &authorityConn{s: d.m.f.s, base: &authConn{s: d.m.f.s.auth}}}, nil
}

type originalRecoveryTestConn struct {
	m     *originalRecoveryTestModel
	base  *authorityConn
	stage int
}

func (d *originalRecoveryTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}
func (d *originalRecoveryTestConn) Close() error { return nil }
func (d *originalRecoveryTestConn) Begin() (driver.Tx, error) {
	return d.BeginTx(context.Background(), driver.TxOptions{})
}
func (d *originalRecoveryTestConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	d.stage = 0
	return d.base.BeginTx(ctx, o)
}
func (d *originalRecoveryTestConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("recovery authorization must not write SQL")
}
func (d *originalRecoveryTestConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := d.m.set
	guard := func(want int, label string) error {
		if d.stage != want || !strings.HasSuffix(q, " FOR SHARE") || d.base.working == nil {
			return errors.New("wrong recovery lock order")
		}
		d.stage++
		d.m.order = append(d.m.order, label)
		return nil
	}
	switch {
	case strings.Contains(q, "FROM system_backup_gate_admissions"):
		if err := guard(0, "admission"); err != nil {
			return nil, err
		}
		if len(args) != 1 || args[0].Value != s.application.scope {
			return nil, ErrInstall
		}
		return row(s.application.owner), nil
	case strings.Contains(q, "FROM system_backup_gate WHERE"):
		if err := guard(1, "application"); err != nil {
			return nil, err
		}
		return row(s.application.phase, s.application.owner, int64(s.application.generation), int64(s.application.token), s.inventorySHA), nil
	case strings.Contains(q, "FROM system_backup_v2_maintenance_locks"):
		if err := guard(2, "v2"); err != nil {
			return nil, err
		}
		if len(args) != 2 || args[0].Value != s.owner.token.Key.InstallationID || args[1].Value != s.owner.token.Key.Scope {
			return nil, ErrInstall
		}
		token := s.owner.token
		if d.m.gateDrift {
			token.RowVersion++
		}
		return row(string(token.State), int64(token.Generation), int64(token.FencingToken), token.Owner, int64(token.RowVersion)), nil
	case strings.Contains(q, "FROM users WHERE id="):
		if err := guard(3, "administrator"); err != nil {
			return nil, err
		}
	case strings.Contains(q, "FROM system_backup_installation_owner_heads"):
		if err := guard(4, "head"); err != nil {
			return nil, err
		}
	case strings.Contains(q, "FROM system_backup_installation_owner_grants"):
		if err := guard(5, "grant"); err != nil {
			return nil, err
		}
	}
	return d.base.QueryContext(ctx, q, args)
}

func newOriginalRecoveryTest(t *testing.T, signedState string) *originalRecoveryTestModel {
	t.Helper()
	f := newAuthorityFixture(t)
	oldCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	operator, err := f.i.authenticate(oldCtx, f.password)
	if err != nil {
		t.Fatal("fixture original authentication", err)
	}
	if signedState != "" {
		r := f.record
		r.NotBefore = time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Microsecond)
		r.Until = r.NotBefore.Add(5 * time.Minute)
		r.Probe.Until = r.NotBefore.Add(time.Minute)
		raw, _ := canonical(r)
		h, err := nextHead(currentAuthority{}, r, r.NotBefore.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		h.RecordSHA256 = hash(raw)
		h.State = "active"
		head, _ := owner.EncodeHead(h)
		f.s.data.head = []driver.Value{int64(h.Revision), hash(head), head, ed25519.Sign(f.key, append([]byte(owner.HeadDomain), head...)), "active", int64(1)}
		f.s.data.grants[grantKey(r.GrantID, int64(r.Revision))] = []driver.Value{hash(raw), raw, ed25519.Sign(f.key, append([]byte(owner.RecordDomain), raw...)), "active", int64(1)}
	}
	current, _, err := snapshot(oldCtx, operator)
	if err != nil {
		t.Fatal("fixture signed provenance", err)
	}
	p := &OriginalWriterMaintenance{ctx: oldCtx, operator: operator, enrollment: f.enrollment, initial: current.cas,
		operation: strings.Repeat("a", 32), until: operator.until, instances: []domain.SourceInstance{}}
	p.origin = p
	p.token = c.GateToken{GateSnapshot: c.GateSnapshot{Key: c.GateKey{InstallationID: f.i.plan.Target.InstallationID, Scope: c.CaptureGateScope},
		State: c.GateAcquiring, Generation: 2, FencingToken: 3, Owner: "adoption:" + p.operation, RowVersion: 4}}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("private journal directory", err)
	}
	j, err := newOriginalWriterJournal(oldCtx, p, directory, strings.Repeat("c", 64))
	if err != nil {
		t.Fatal("fixture original journal constructor", err)
	}
	t.Cleanup(func() { _ = j.close() })
	w := &originalDeploymentMaintenance{owner: p, journal: j, namespace: f.i.plan.Target.Namespace,
		selection: OriginalDeploymentSelection{Name: "original-writer", UID: "deployment-uid", Role: "writer"},
		original:  flow.State{UID: "deployment-uid", Generation: 1, Running: true, Checkpoint: "actual-original-checkpoint"}, replicas: 1, stopDispatched: true}
	s := &PreparedOriginalWriterSet{owner: p, used: true, journal: j, inventorySHA: j.inventory, deployments: []*originalDeploymentMaintenance{w},
		application: originalApplicationGate{scope: "application-original", owner: p.token.Owner, generation: 8, token: 9, phase: "acquiring"}}
	s.origin = s
	states := map[string]any{w.ID(): w.original}
	if j.append(oldCtx, "", "prepared_original_complete_set", nil, struct {
		Selection BootstrapSourceFilePin
		Instances []domain.SourceInstance
		Census    originalMaintenanceKubernetesCensus
		States    map[string]any
	}{s.selectionPin, p.instances, s.initial, states}) != nil || j.append(oldCtx, "", "capture_gate_acquire_send_unknown", nil, p.policy) != nil ||
		j.append(oldCtx, w.ID(), "scale_zero_send_unknown", &w.original, struct{ Replicas int32 }{0}) != nil {
		t.Fatal("actual journal write")
	}
	cancel() // simulate the real expired/cancelled original capture context
	p.until = time.Now().Add(-time.Minute)
	operator.until = p.until
	if signedState == "revoked" {
		var h owner.Head
		if json.Unmarshal(f.s.data.head[2].([]byte), &h) != nil {
			t.Fatal("head")
		}
		h.Revision++
		h.State = "revoked"
		raw, _ := owner.EncodeHead(h)
		f.s.data.head = []driver.Value{int64(h.Revision), hash(raw), raw, ed25519.Sign(f.key, append([]byte(owner.HeadDomain), raw...)), "revoked", int64(2)}
		for _, grant := range f.s.data.grants {
			grant[3] = "revoked"
			grant[4] = int64(2)
		}
	}
	m := &originalRecoveryTestModel{f: f, set: s}
	kube := f.i.kube.(*kubefake.Clientset)
	kube.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		requireNoOpenAuthorityTx(t, f.s)
		a := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).Spec.ResourceAttributes
		if a != nil && a.Resource == "deployments" {
			allowed := !m.permissionDenied.Load() && a.Group == "apps" && a.Name == w.selection.Name && a.Namespace == w.namespace && (a.Verb == "get" || a.Verb == "patch")
			return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed, Denied: !allowed}}, nil
		}
		return false, nil, nil
	})
	db := sql.OpenDB(originalRecoveryTestConnector{m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	f.i.db = db
	return m
}

func TestOriginalWriterFreshRecoveryAuthorization(t *testing.T) {
	for _, state := range []string{"", "active"} {
		t.Run("expired_capture_"+state, func(t *testing.T) {
			m := newOriginalRecoveryTest(t, state)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			oldCtx, oldUntil, oldOperator := m.set.owner.ctx, m.set.owner.until, m.set.owner.operator
			a, err := m.f.i.PrepareOriginalWriterRecovery(ctx, m.f.password, m.f.enrollment, m.set)
			if err != nil {
				t.Fatal("fresh admin cannot recover expired original capture", err)
			}
			if a.fence.check(ctx) != nil || !m.set.recovering || !m.set.owner.failed ||
				m.set.owner.ctx != oldCtx || !m.set.owner.until.Equal(oldUntil) || m.set.owner.operator != oldOperator || oldOperator.live(ctx) {
				t.Fatal("old capture renewed")
			}
			if _, err := m.set.Acquire(oldCtx); err == nil {
				t.Fatal("capture reopened")
			}
			if m.f.s.openTx.Load() != 0 || m.f.s.writes != 0 || m.f.s.commits != 0 {
				t.Fatal("authorization wrote/retained a SQL transaction")
			}
			want := "admission,application,v2,administrator,head"
			if state != "" {
				want += ",grant"
			}
			if !strings.HasPrefix(strings.Join(m.order, ","), want) {
				t.Fatal("lock order", m.order)
			}
			copy := *a
			if _, err := copy.recoveryFence(ctx, m.set); err == nil {
				t.Fatal("copied capability accepted")
			}
			if jsonRaw, err := json.Marshal(a); err == nil || jsonRaw != nil {
				t.Fatal("serialized authority")
			}
		})
	}
}

func TestOriginalWriterFreshRecoveryRefusals(t *testing.T) {
	for _, mode := range []string{"wrong_password", "wrong_installer", "wrong_database_identity", "wrong_enrollment", "revoked", "head_drift", "gate_drift", "target_permission", "admin_disabled", "unused_set", "foreign_operation", "missing_intent", "journal_changed", "unknown_commit", "no_gate"} {
		t.Run(mode, func(t *testing.T) {
			state := ""
			if mode == "revoked" {
				state = "revoked"
			}
			if mode == "head_drift" {
				state = "active"
			}
			m := newOriginalRecoveryTest(t, state)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			i, password, enrollment := m.f.i, m.f.password, m.f.enrollment
			s := m.set
			switch mode {
			case "wrong_password":
				password = []byte("wrong")
			case "wrong_database_identity":
				m.f.s.auth.server = "foreign-server-uuid"
			case "wrong_installer":
				copy := *i
				i = &copy
			case "wrong_enrollment":
				enrollment.ConfigMapUID = "other-installation"
			case "head_drift":
				m.f.s.data.head[5] = int64(2)
			case "gate_drift":
				m.gateDrift = true
			case "target_permission":
				m.permissionDenied.Store(true)
			case "admin_disabled":
				m.f.s.auth.active = false
			case "unused_set":
				s.used = false
			case "foreign_operation":
				s.owner.operation = strings.Repeat("b", 32)
			case "missing_intent":
				s.deployments[0].stopDispatched = false
			case "journal_changed":
				name := fmt.Sprintf("original-writers-%s-%08d.json", s.owner.operation, 2)
				if err := os.Remove(s.journal.directory + string(os.PathSeparator) + name); err != nil {
					t.Fatal(err)
				}
			case "unknown_commit":
				s.owner.commitUnknown = true
			case "no_gate":
				s.owner.token.Generation = 0
			}
			if a, err := i.PrepareOriginalWriterRecovery(ctx, password, enrollment, s); err == nil || a != nil {
				t.Fatal("invalid recovery accepted", mode)
			}
			if m.f.s.openTx.Load() != 0 || m.f.s.writes != 0 {
				t.Fatal("failed authorization leaked transaction/result")
			}
		})
	}
}

func TestOriginalWriterRecoveryRechecksAndProviderStop(t *testing.T) {
	for _, mode := range []string{"fresh_expired", "wrong_context", "revoke_after_auth", "permission_after_auth", "admin_after_auth", "replaced_authorization", "actual_provider_wait", "provider_timeout"} {
		t.Run(mode, func(t *testing.T) {
			m := newOriginalRecoveryTest(t, "")
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			var provider *OriginalAdoptionArchiveProvider
			var stopped atomic.Bool
			if mode == "actual_provider_wait" || mode == "provider_timeout" {
				provider = &OriginalAdoptionArchiveProvider{outer: m.set.owner.ctx, operator: m.set.owner.operator, enrollment: m.f.enrollment,
					until: m.set.owner.until, done: make(chan struct{}), cancel: func() { stopped.Store(true) }}
				provider.origin = provider
				provider.reservation.OperationID = m.set.owner.operation
				provider.used.Store(true)
				h := &OriginalWriterHold{set: m.set, ctx: m.set.owner.ctx, providers: []*OriginalAdoptionArchiveProvider{provider}}
				h.origin = h
				m.set.actualHold = h
				if err := m.set.journal.append(ctx, "node/original", "archive_provider_prepare", nil, originalRecoveryProviderIntent{provider.reservation, "", ""}); err != nil {
					t.Fatal(err)
				}
				if mode == "actual_provider_wait" {
					go func() {
						for !stopped.Load() {
							time.Sleep(time.Millisecond)
						}
						close(provider.done)
					}()
				} else {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
					defer cancel()
				}
			}
			a, err := m.f.i.PrepareOriginalWriterRecovery(ctx, m.f.password, m.f.enrollment, m.set)
			if mode == "provider_timeout" {
				defer close(provider.done)
				if err == nil || a != nil || !stopped.Load() || !m.set.actualHold.closed || !m.set.recovering {
					t.Fatal("timeout treated as stopped ACK", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			checkCtx := ctx
			switch mode {
			case "fresh_expired":
				a.operator.until = time.Now().Add(-time.Second)
			case "wrong_context":
				var cc context.CancelFunc
				checkCtx, cc = context.WithCancel(ctx)
				defer cc()
			case "revoke_after_auth":
				m.f.s.data.head = []driver.Value{int64(1), "invalid", []byte("revoked"), []byte("invalid"), "revoked", int64(1)}
			case "permission_after_auth":
				m.permissionDenied.Store(true)
			case "admin_after_auth":
				m.f.s.auth.active = false
			case "replaced_authorization":
				otherCtx, cc := context.WithTimeout(context.Background(), time.Minute)
				defer cc()
				if _, err := m.f.i.PrepareOriginalWriterRecovery(otherCtx, m.f.password, m.f.enrollment, m.set); err != nil {
					t.Fatal(err)
				}
			case "actual_provider_wait":
				if !stopped.Load() || !m.set.actualHold.closed || a.fence.check(ctx) != nil {
					t.Fatal("actual cancel/wait missing")
				}
				return
			}
			if a.fence.check(checkCtx) == nil {
				t.Fatal("live authorization recheck missed", mode)
			}
		})
	}
}
