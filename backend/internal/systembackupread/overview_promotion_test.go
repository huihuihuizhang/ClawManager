package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type promotionFixture struct {
	*overviewFixture
	promotions                      [][]driver.Value
	backup, drill, evidence, config []driver.Value
	promotionStreamError            bool
}

func newPromotionFixture() *promotionFixture {
	f := &promotionFixture{overviewFixture: newOverviewFixture()}
	f.tasks = append(f.tasks, []driver.Value{"backup", "succeeded", int64(1)}, []driver.Value{"drill", "succeeded", int64(1)})
	now := f.state[14].(time.Time)
	created := now.Add(-time.Minute)
	backup := "sbk_00000000-0000-4000-8000-000000000001"
	drill := "sdr_00000000-0000-4000-8000-000000000001"
	evidence := "sev_00000000-0000-4000-8000-000000000001"
	h := func(c string) string { return strings.Repeat(c, 64) }
	f.promotions = [][]driver.Value{{"system-backup-promotion.v1", "spm_00000000-0000-4000-8000-000000000001", "installation_test", "k8s-cluster", "active",
		backup, drill, h("a"), h("b"), "registration-fixture", h("c"), h("d"), evidence, h("e"), int64(3), int64(4), int64(2), int64(1),
		"healthy", "healthy", "healthy", "healthy", "healthy", "healthy", "healthy", h("f"), created.Add(-time.Second), "42", int64(1), created, created, true}}
	f.backup = []driver.Value{"system-backup-task.v1", backup, "installation_test", "k8s-cluster", "backup", "succeeded", "acceptance", true, "eligible", h("d"), h("a"), h("b"), "registration-fixture", h("c"), int64(5), int64(4), "committed", true, "none"}
	f.drill = []driver.Value{"system-backup-task.v1", drill, "installation_test", "drill", "succeeded", "acceptance", "backup", backup, h("a"), h("b"), true, "eligible", h("a"), "delete-on-success", "succeeded", "none", int64(6)}
	f.evidence = []driver.Value{"system-backup-evidence.v1", evidence, "drill", drill, "verifier_report", h("e"), int64(2)}
	f.config = []driver.Value{"system-backup-config.v1", "installation_test", int64(1)}
	return f
}

type promotionConnector struct{ f *promotionFixture }

func (c promotionConnector) Connect(context.Context) (driver.Conn, error) {
	return &promotionConn{c.f}, nil
}
func (promotionConnector) Driver() driver.Driver { return pageDriver{} }

type promotionConn struct{ f *promotionFixture }

func (*promotionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*promotionConn) Close() error { return nil }
func (c *promotionConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *promotionConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return (&overviewConn{c.f.overviewFixture}).BeginTx(ctx, opts)
}
func (c *promotionConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	var columns []string
	var values [][]driver.Value
	switch query {
	case currentPromotionSQL:
		if len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != f.state[8] {
			return nil, errors.New("unscoped installation/matrix")
		}
		columns = make([]string, 32)
		values = f.promotions
	case promotionBackupSQL:
		if len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != "sbk_00000000-0000-4000-8000-000000000001" {
			return nil, errors.New("unscoped backup")
		}
		columns = make([]string, 19)
		if f.backup != nil {
			values = [][]driver.Value{f.backup}
		}
	case promotionDrillSQL:
		if len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != "sdr_00000000-0000-4000-8000-000000000001" {
			return nil, errors.New("unscoped drill")
		}
		columns = make([]string, 17)
		if f.drill != nil {
			values = [][]driver.Value{f.drill}
		}
	case promotionEvidenceSQL:
		if len(args) != 1 || args[0].Value != "sev_00000000-0000-4000-8000-000000000001" {
			return nil, errors.New("unbound evidence")
		}
		columns = make([]string, 7)
		if f.evidence != nil {
			values = [][]driver.Value{f.evidence}
		}
	case promotionConfigSQL:
		if len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != int64(1) {
			return nil, errors.New("unscoped creation config")
		}
		columns = make([]string, 3)
		if f.config != nil {
			values = [][]driver.Value{f.config}
		}
	default:
		return (&overviewConn{f.overviewFixture}).QueryContext(ctx, query, args)
	}
	f.queries = append(f.queries, query)
	if query == f.queryError {
		return nil, errors.New("promotion source SQL failed")
	}
	rows := &pageRows{columns: columns, values: values}
	if query == currentPromotionSQL && f.promotionStreamError {
		return &overviewErrorRows{rows, true}, nil
	}
	return rows, nil
}
func promotionReader(t *testing.T, f *promotionFixture) *Reader {
	t.Helper()
	db := sql.OpenDB(promotionConnector{f})
	t.Cleanup(func() { db.Close() })
	r, err := NewReader(db, f)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOverviewPromotionBindsSourcesAndPreservesHistoricalVersions(t *testing.T) {
	f := newPromotionFixture()
	r := promotionReader(t, f)
	s, err := r.ReadOverviewPromotionControl(context.Background())
	p, present := s.CurrentPromotion()
	if err != nil || !present || p.SourceBackupRowVersion != 3 || p.Backup.RowVersion != 5 || p.SourceDrillRowVersion != 4 || p.Drill.RowVersion != 6 || p.ConfigVersion != 1 || s.Control().state.ConfigVersion != 3 || len(f.queries) != 8 || f.rechecks != 1 || f.commits != 1 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatal("incorrect bound promotion contribution", p, present, err, f.queries)
	}
	for _, query := range f.queries {
		for _, forbidden := range []string{"inline_payload", "artifact_uri", "config_snapshot_json", "storage_relative_key,", "failure_message", "SELECT *"} {
			if strings.Contains(query, forbidden) {
				t.Fatal("private payload selected", forbidden)
			}
		}
	}
	p.CreationHealth[0] = "degraded"
	p.Backup.ManifestSHA256 = "changed"
	copy, ok := s.CurrentPromotion()
	if !ok || copy.CreationHealth[0] != "healthy" || copy.Backup.ManifestSHA256 == "changed" {
		t.Fatal("getter aliased held contribution")
	}
	for _, value := range []any{s, copy, copy.Backup, copy.Drill, copy.Evidence} {
		if _, err = json.Marshal(value); !errors.Is(err, ErrInvalid) {
			t.Fatal("incomplete promotion serialized", err)
		}
	}
}

func TestOverviewPromotionAbsenceIsQueriedAndDoesNotLoadUnboundSources(t *testing.T) {
	f := newPromotionFixture()
	f.promotions = nil
	r := promotionReader(t, f)
	s, err := r.ReadOverviewPromotionControl(context.Background())
	_, present := s.CurrentPromotion()
	if err != nil || present || len(f.queries) != 4 || f.rechecks != 1 || f.commits != 1 || s.Control().state.InstallationID != "installation_test" {
		t.Fatal("queried absence lost authority/control", present, err, f.queries)
	}
}

func TestOverviewPromotionAvailabilityLossDoesNotEraseRecord(t *testing.T) {
	for _, state := range []string{"committed", "corrupt", "deleted", "deleting", "delete_failed"} {
		t.Run(state, func(t *testing.T) {
			f := newPromotionFixture()
			f.backup[16] = state
			f.backup[17] = false
			f.backup[18] = state
			if state == "committed" {
				f.backup[18] = "provider_unavailable"
			}
			r := promotionReader(t, f)
			s, err := r.ReadOverviewPromotionControl(context.Background())
			p, present := s.CurrentPromotion()
			if err != nil || !present || p.Backup.ArtifactUsable || p.CreationHealth[0] != "healthy" {
				t.Fatal("historical baseline overwritten by current availability", p, present, err)
			}
		})
	}
}

func TestOverviewPromotionRejectsDriftAndIncompleteBindings(t *testing.T) {
	cases := map[string]func(*promotionFixture){
		"promotion schema":                  func(f *promotionFixture) { f.promotions[0][0] = "v2" },
		"promotion ID":                      func(f *promotionFixture) { f.promotions[0][1] = "spm_bad" },
		"foreign promotion":                 func(f *promotionFixture) { f.promotions[0][2] = "installation_foreign" },
		"wrong matrix":                      func(f *promotionFixture) { f.promotions[0][3] = "k3s-cluster" },
		"inactive row returned":             func(f *promotionFixture) { f.promotions[0][4] = "revoked" },
		"bad checksum":                      func(f *promotionFixture) { f.promotions[0][7] = "bad" },
		"empty registration":                func(f *promotionFixture) { f.promotions[0][9] = "" },
		"bad evidence ID":                   func(f *promotionFixture) { f.promotions[0][12] = "sop_00000000-0000-4000-8000-000000000001" },
		"zero source version":               func(f *promotionFixture) { f.promotions[0][14] = int64(0) },
		"unsafe version":                    func(f *promotionFixture) { f.promotions[0][28] = int64(maxJSONSafeInteger + 1) },
		"creation health not healthy":       func(f *promotionFixture) { f.promotions[0][21] = "unknown" },
		"creation observation after create": func(f *promotionFixture) { f.promotions[0][26] = f.promotions[0][29].(time.Time).Add(time.Second) },
		"bad creation actor":                func(f *promotionFixture) { f.promotions[0][27] = "system:controller" },
		"lifecycle not active-only":         func(f *promotionFixture) { f.promotions[0][31] = false },
		"duplicate active":                  func(f *promotionFixture) { f.promotions = append(f.promotions, f.promotions[0]) },
		"promotion scan error":              func(f *promotionFixture) { f.promotions[0][14] = "bad" },
		"missing backup":                    func(f *promotionFixture) { f.backup = nil },
		"foreign backup":                    func(f *promotionFixture) { f.backup[2] = "installation_other" },
		"wrong backup schema":               func(f *promotionFixture) { f.backup[0] = "v2" },
		"wrong backup type":                 func(f *promotionFixture) { f.backup[4] = "drill" },
		"backup not succeeded":              func(f *promotionFixture) { f.backup[5] = "failed" },
		"functional backup":                 func(f *promotionFixture) { f.backup[6] = "functional_test" },
		"backup not eligible":               func(f *promotionFixture) { f.backup[7] = false },
		"backup manifest drift":             func(f *promotionFixture) { f.backup[10] = strings.Repeat("b", 64) },
		"backup acceptance drift":           func(f *promotionFixture) { f.backup[11] = strings.Repeat("c", 64) },
		"registration drift":                func(f *promotionFixture) { f.backup[12] = "other-registration" },
		"registration hash drift":           func(f *promotionFixture) { f.backup[13] = strings.Repeat("d", 64) },
		"backup version rollback":           func(f *promotionFixture) { f.backup[14] = int64(2) },
		"prune guard rollback":              func(f *promotionFixture) { f.backup[15] = int64(1) },
		"artifact staging rollback": func(f *promotionFixture) {
			f.backup[16] = "staging"
			f.backup[17] = false
			f.backup[18] = "not_committed"
		},
		"artifact availability mismatch": func(f *promotionFixture) { f.backup[17] = false },
		"missing drill":                  func(f *promotionFixture) { f.drill = nil },
		"foreign drill":                  func(f *promotionFixture) { f.drill[2] = "installation_other" },
		"drill schema":                   func(f *promotionFixture) { f.drill[0] = "v2" },
		"import not local source":        func(f *promotionFixture) { f.drill[6] = "catalog_import" },
		"drill source drift":             func(f *promotionFixture) { f.drill[7] = "sbk_00000000-0000-4000-8000-000000000099" },
		"drill checksum drift":           func(f *promotionFixture) { f.drill[8] = strings.Repeat("c", 64) },
		"drill not eligible":             func(f *promotionFixture) { f.drill[10] = false },
		"drill retained":                 func(f *promotionFixture) { f.drill[13] = "retain-always" },
		"drill cleanup unsettled":        func(f *promotionFixture) { f.drill[14] = "pending" },
		"drill version rollback":         func(f *promotionFixture) { f.drill[16] = int64(3) },
		"missing evidence":               func(f *promotionFixture) { f.evidence = nil },
		"evidence owner substitution":    func(f *promotionFixture) { f.evidence[2] = "backup" },
		"evidence target substitution":   func(f *promotionFixture) { f.evidence[3] = "sdr_00000000-0000-4000-8000-000000000099" },
		"evidence hash drift":            func(f *promotionFixture) { f.evidence[5] = strings.Repeat("a", 64) },
		"invalid drill evidence type":    func(f *promotionFixture) { f.evidence[4] = "provider_deletion_receipt" },
		"missing creation config":        func(f *promotionFixture) { f.config = nil },
		"creation config schema":         func(f *promotionFixture) { f.config[0] = "v2" },
		"creation config foreign":        func(f *promotionFixture) { f.config[1] = "installation_foreign" },
		"creation config version":        func(f *promotionFixture) { f.config[2] = int64(2) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newPromotionFixture()
			mutate(f)
			r := promotionReader(t, f)
			s, err := r.ReadOverviewPromotionControl(context.Background())
			if !errors.Is(err, ErrUnavailable) || !reflect.DeepEqual(s, OverviewPromotionControlSnapshot{}) || f.commits != 0 {
				t.Fatal("partial/mismatched baseline escaped", s, err)
			}
		})
	}
}

func TestOverviewPromotionSQLStreamAndAuthorityFailuresReturnZero(t *testing.T) {
	for _, stage := range []string{"promotion SQL", "backup SQL", "drill SQL", "evidence SQL", "config SQL", "promotion stream", "authorize", "recheck", "commit", "absent revoked"} {
		t.Run(stage, func(t *testing.T) {
			f := newPromotionFixture()
			want := ErrUnavailable
			permission := errors.New("permission-revoked")
			switch stage {
			case "promotion SQL":
				f.queryError = currentPromotionSQL
			case "backup SQL":
				f.queryError = promotionBackupSQL
			case "drill SQL":
				f.queryError = promotionDrillSQL
			case "evidence SQL":
				f.queryError = promotionEvidenceSQL
			case "config SQL":
				f.queryError = promotionConfigSQL
			case "promotion stream":
				f.promotionStreamError = true
			case "authorize":
				f.authorizeErr = permission
				want = ErrDenied
			case "recheck":
				f.recheckErr = permission
				want = ErrDenied
			case "commit":
				f.commitErr = errors.New("commit unknown")
			case "absent revoked":
				f.promotions = nil
				f.recheckErr = permission
				want = ErrDenied
			}
			r := promotionReader(t, f)
			s, err := r.ReadOverviewPromotionControl(context.Background())
			if !errors.Is(err, want) || !reflect.DeepEqual(s, OverviewPromotionControlSnapshot{}) {
				t.Fatal("failed baseline read leaked result", s, err)
			}
			if want == ErrDenied && !errors.Is(err, permission) {
				t.Fatal("lost authority error cause", err)
			}
		})
	}
}

func TestOverviewPromotionBuilderRemainsInsideFinalGuard(t *testing.T) {
	for _, stage := range []string{"success", "owner failure", "revoked", "canceled"} {
		t.Run(stage, func(t *testing.T) {
			f := newPromotionFixture()
			r := promotionReader(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := readOverviewPromotionInTransaction(ctx, r, func(ctx context.Context, q overviewReadSQL, s OverviewPromotionControlSnapshot) (string, error) {
				if _, ok := s.CurrentPromotion(); !ok || f.rechecks != 0 || f.commits != 0 {
					t.Fatal("builder lacks uncommitted promotion")
				}
				if _, ok := q.(*sql.Tx); ok {
					t.Fatal("raw transaction escaped")
				}
				if _, ok := q.(interface{ Commit() error }); ok {
					t.Fatal("Commit escaped")
				}
				var fact string
				if e := q.QueryRowContext(ctx, "SELECT 'owner_fact' WHERE ?", s.control.state.InstallationID).Scan(&fact); e != nil || fact != "verified" {
					t.Fatal("owner read not in shared transaction", fact, e)
				}
				switch stage {
				case "owner failure":
					return "partial", errors.New("Owner unavailable")
				case "revoked":
					f.recheckErr = ErrDenied
				case "canceled":
					cancel()
				}
				return "complete", nil
			})
			if stage == "success" {
				if err != nil || result != "complete" || f.commits != 1 {
					t.Fatal("builder failed", result, err)
				}
			} else {
				if err == nil || result != "" || f.commits != 0 {
					t.Fatal("partial result committed", result, err)
				}
				if stage == "canceled" {
					select {
					case <-f.rollbackDone:
					case <-time.After(time.Second):
						t.Fatal("canceled transaction not rolled back")
					}
				}
			}
		})
	}
}
