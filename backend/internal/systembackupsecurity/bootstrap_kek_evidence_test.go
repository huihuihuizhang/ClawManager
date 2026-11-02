package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"reflect"
	"sort"
	"strings"
	"testing"

	reg "clawreef/internal/systembackupkekregistry"
)

// These deliberately synthetic sources STOP at the original evidence check.
// They exercise D's real sealed candidate transaction, never KEK admission.
type bootstrapEvidenceCoverage struct{ reg.PreparedCoverage }
type bootstrapEvidenceAdmission struct {
	reg.PreparedAdmission
	ids         []string
	observation reg.AdmissionObservation
	lock        func(context.Context, reg.SQLReadView) error
}

func (p *bootstrapEvidenceAdmission) OriginalCoverage() reg.PreparedCoverage {
	return &bootstrapEvidenceCoverage{}
}
func (p *bootstrapEvidenceAdmission) OriginalEvidenceIDs() []string {
	return append([]string(nil), p.ids...)
}
func (p *bootstrapEvidenceAdmission) Observation() reg.AdmissionObservation { return p.observation }
func (p *bootstrapEvidenceAdmission) LockOriginalEvidence(ctx context.Context, tx reg.SQLReadView) error {
	return p.lock(ctx, tx)
}

type bootstrapEvidenceConnector struct {
	state    *consumerIntegrationState
	observed *[]string
}

func (c bootstrapEvidenceConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c bootstrapEvidenceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (consumerIntegrationConnector{c.state}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &bootstrapEvidenceConn{base.(*consumerIntegrationConn), c.observed}, nil
}

type bootstrapEvidenceConn struct {
	*consumerIntegrationConn
	observed *[]string
}

func (c *bootstrapEvidenceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if query == "SELECT id,public_id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE" || query == "SELECT chunk_index FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE" {
		c.integration.queries = append(c.integration.queries, query)
		if strings.HasPrefix(query, "SELECT id,") {
			*c.observed = append(*c.observed, args[0].Value.(string))
		}
		return consumerIntegrationSelect(query, args, c.integration.rows)
	}
	return c.consumerIntegrationConn.QueryContext(ctx, query, args)
}

func TestBootstrapKEKEvidenceLocksSelectedUnionBeforeOriginalCheckAndFence(t *testing.T) {
	for _, mode := range []string{"complete-union", "missing-capability-source", "foreign-source-id", "broken-chunk-order"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentCandidateFixture(t)
			observed := []string{}
			original := &bootstrapEvidenceAdmission{ids: []string{"sev_z_original", "sev_a_original", "sev_z_original"}, observation: reg.AdmissionObservation{GenerateCapabilitySource: reg.SourceRecord{RecordID: "sev_b_generate"}, UnwrapCapabilitySource: reg.SourceRecord{RecordID: "sev_y_unwrap"}}}
			wanted := []string{"sev_a_original", "sev_b_generate", "sev_y_unwrap", "sev_z_original", string(f.sql.evidence.Evidence.EvidenceID)}
			sort.Strings(wanted)
			for i, id := range []string{"sev_a_original", "sev_b_generate", "sev_y_unwrap", "sev_z_original"} {
				f.sql.rows["system_backup_v2_evidence"] = append(f.sql.rows["system_backup_v2_evidence"], map[string]driver.Value{"id": int64(201 + i), "public_id": id})
			}
			switch mode {
			case "missing-capability-source":
				original.observation.GenerateCapabilitySource.RecordID = ""
			case "foreign-source-id":
				original.ids[0] = "../foreign"
			case "broken-chunk-order":
				f.sql.rows["system_backup_v2_evidence_chunks"][0]["chunk_index"] = int64(1)
			}
			calls := 0
			original.lock = func(ctx context.Context, tx reg.SQLReadView) error {
				calls++
				if ctx != f.authority.preparedCtx || tx == nil || !reflect.DeepEqual(observed, wanted) {
					t.Fatal("original source check preceded complete sorted evidence/chunk locks", observed, wanted)
				}
				for _, query := range f.sql.queries {
					if strings.Contains(query, "system_backup_v2_kek_") {
						t.Fatal("KEK fence or registry acquired before original evidence check", query)
					}
				}
				return ErrRegistrationUnavailable // A real authority is intentionally absent.
			}
			f.deployment.kek = &deploymentKEKPreparation{prepare: func(context.Context, *sql.DB, OfflineBootstrapGrant, BootstrapConfig) (reg.PreparedAdmission, error) {
				return original, nil
			}}
			f.deployment.openDatabase = func() (*sql.DB, error) {
				f.opens++
				db := sql.OpenDB(bootstrapEvidenceConnector{f.sql, &observed})
				f.databases = append(f.databases, db)
				return db, nil
			}
			if _, err := f.deployment.Apply(context.Background()); err == nil || f.sql.commits != 0 || f.opens != 1 {
				t.Fatal("synthetic source became admission or escaped original transaction", err)
			}
			if (mode == "complete-union") != (calls == 1) {
				t.Fatal("wrong original evidence callback count", mode, calls, observed, f.sql.queries)
			}
			if mode == "missing-capability-source" || mode == "foreign-source-id" {
				if len(observed) != 0 {
					t.Fatal("invalid source identifier reached row locks", observed)
				}
			}
		})
	}
}
