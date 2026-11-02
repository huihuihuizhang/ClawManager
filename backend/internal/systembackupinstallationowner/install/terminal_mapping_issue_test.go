package install

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Reuse the real authenticated enrollment/capture fixture, with an additional
// exact producer-record SQL model. This is not native SQL or a full thirty-
// owner admission test. The source issuer must finish each owner snapshot
// before querying the original producer domain/grants or the Kubernetes API.
type terminalIssueConnector struct {
	f     *authorityFixture
	t     *testing.T
	rows  map[string]pd.StoredRecord
	reads int
	after func()
}

func (c *terminalIssueConnector) Driver() driver.Driver { return authDriver{} }
func (c *terminalIssueConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (authorityConnector{c.f.s}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &terminalIssueConn{Conn: base, source: c}, nil
}

type terminalIssueConn struct {
	driver.Conn
	source *terminalIssueConnector
}

func (c *terminalIssueConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}

type terminalIssueRows struct {
	*authorityRows
	columns []string
}

func (r *terminalIssueRows) Columns() []string { return r.columns }
func (c *terminalIssueConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, " FROM system_backup_producer_") {
		return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	}
	source := c.source
	requireNoOpenAuthorityTx(source.t, source.f.s)
	if !strings.HasSuffix(query, " FOR SHARE") || strings.Contains(query, "LIMIT") {
		return nil, errors.New("not a complete SELECT-only original source read")
	}
	for table, record := range source.rows {
		if !strings.Contains(query, " FROM "+table+" WHERE ") {
			continue
		}
		if len(args) == 0 || !reflect.DeepEqual(args[0].Value, record.Columns["scope_key"]) {
			return nil, errors.New("foreign original producer scope")
		}
		if value, ok := record.Columns["grant_id"]; ok && (len(args) != 2 || !reflect.DeepEqual(args[1].Value, value)) {
			return nil, errors.New("foreign original grant")
		}
		columns := strings.Split(strings.TrimPrefix(strings.SplitN(query, " FROM ", 2)[0], "SELECT "), ", ")
		values := make([]driver.Value, len(columns))
		for n, column := range columns {
			value, ok := record.Columns[column]
			if !ok {
				return nil, errors.New("unknown original producer column")
			}
			var err error
			values[n], err = driver.DefaultParameterConverter.ConvertValue(value)
			if err != nil {
				return nil, err
			}
		}
		source.reads++
		if source.after != nil {
			source.after()
		}
		return &terminalIssueRows{authorityRows: &authorityRows{width: len(columns), values: [][]driver.Value{values}}, columns: columns}, nil
	}
	return nil, errors.New("unexpected producer source table")
}

func terminalMappingIssueFixture(t *testing.T, ctx context.Context) (*authorityFixture, *terminalIssueConnector, pd.BootstrapConsumptionRequest, []byte) {
	t.Helper()
	f := newAuthorityFixture(t)
	raw, err := os.ReadFile("../../../../contracts/system-backup/v12/producer-authority-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Positive []struct {
			ID    string
			Value json.RawMessage
		}
		Records []struct {
			Definition string
			Value      json.RawMessage
		}
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("strict original producer vectors")
	}
	var result pd.ResultRequest
	var domain pd.DomainRecord
	var grant pd.GrantRecord
	for _, vector := range vectors.Positive {
		if vector.ID == "unconfigured_artifact" && pd.DecodeRecord(vector.Value, &result) != nil {
			t.Fatal("result vector")
		}
	}
	for _, vector := range vectors.Records {
		switch vector.Definition {
		case "DomainRecord":
			if pd.DecodeRecord(vector.Value, &domain) != nil {
				t.Fatal("domain vector")
			}
		case "GrantRecord":
			if pd.DecodeRecord(vector.Value, &grant) != nil {
				t.Fatal("grant vector")
			}
		}
	}
	if result.Admission.Unconfigured == nil || grant.Host.Service == nil {
		t.Fatal("service/unconfigured original source fixture")
	}
	result.Scope = pd.Scope{ServerUUID: pd.ServerUUID(f.record.Target.ServerUUID), Database: pd.Database(f.record.Target.Database), Installation: pd.Installation(f.record.Target.InstallationID)}
	result.Evidence.OwnerID = result.Scope.Installation
	result.Admission.Unconfigured.CandidateHash = pd.Hash(f.record.ConfigSHA256)
	result.Admission.Unconfigured.RegistrySetHash = pd.Hash(f.record.RegistrySetSHA256)
	result.Admission.Unconfigured.RefSetHash = pd.Hash(f.record.ReferenceSetSHA256)
	domain.Scope, domain.Admission = result.Scope, result.Admission
	grant.Scope, grant.Admission, grant.GrantID, grant.Generation, grant.State, grant.IssuerIdentityHash = result.Scope, result.Admission, result.GrantID, result.GrantGeneration, "active", domain.IssuerIdentityHash
	request := pd.BootstrapConsumptionRequest{Scope: result.Scope, OfflineGrantHash: pd.Hash(f.record.GrantSHA256), ConfigHash: pd.Hash(f.record.ConfigSHA256), RegistrySetHash: pd.Hash(f.record.RegistrySetSHA256), RefSetHash: pd.Hash(f.record.ReferenceSetSHA256), ActorID: pd.Counter(strconv.FormatInt(f.record.Actor.UserID, 10)), Username: f.record.Actor.Username, MatrixKey: f.record.MatrixKey, Endpoint: f.record.Endpoint, IdempotencyKey: f.record.IdempotencyKey, Candidates: []pd.BootstrapCandidateSelection{{Purpose: "artifact", ReferenceIdentityHash: pd.Hash(strings.Repeat("b", 64)), ReferenceVersion: "1", MappingHash: pd.Hash(strings.Repeat("c", 64)), Request: result, ResultVersion: "1"}}}
	selection, err := pd.BootstrapConsumptionHash(request)
	if err != nil {
		t.Fatal(err)
	}
	f.record.SelectionSHA256 = string(selection)
	f.draft, err = canonical(f.record)
	if err != nil {
		t.Fatal(err)
	}
	pack := issueFixture(t, f, ctx)
	if _, err := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); err != nil {
		t.Fatal(err)
	}
	source := &terminalIssueConnector{f: f, t: t, rows: map[string]pd.StoredRecord{}}
	for _, record := range []any{&domain, &grant} {
		stored, err := pd.EncodeStoredRecord(record)
		if err != nil {
			t.Fatal("original typed row", err)
		}
		source.rows[stored.Table] = stored
	}
	db := sql.OpenDB(source)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.i.db = db
	return f, source, request, pack
}

func TestBootstrapOriginalMappingIssuerReadsActualSourcesOutsideOwnerLocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, source, request, pack := terminalMappingIssueFixture(t, ctx)
	signed, err := f.i.IssueBootstrapOriginalMapping(ctx, f.password, f.enrollment, pack, hash(pack), request, nil, strings.Repeat("e", 64), filepath.Join(t.TempDir(), "original-report"), f.key)
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := verifyBootstrapOriginalMapping(signed.Record, signed.Signature, f.i.public)
	if err != nil || source.reads != 2 || len(mapping.Hosts) != 1 || len(mapping.Owners) != 1 || mapping.Owners[0].Key != "reference:capture_signing" || !mapping.NotBefore.Equal(f.record.NotBefore) || !mapping.Until.Equal(f.record.Until) {
		t.Fatal("original association skipped actual sources or expanded authority/window", err, source.reads)
	}
	if f.s.openTx.Load() != 0 {
		t.Fatal("retained original owner locks")
	}
	for _, record := range source.rows {
		var grant pd.GrantRecord
		if strings.HasSuffix(record.Table, "_grants") && pd.DecodeStoredRecord(record, request.Scope, &grant) == nil && mapping.Hosts[0].WorkloadIdentitySHA256 != string(grant.Host.Service.WorkloadIdentityHash) {
			t.Fatal("caller supplied workload hash")
		}
	}
}

func TestBootstrapOriginalMappingIssuerRejectsRevocationAfterProducerRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, source, request, pack := terminalMappingIssueFixture(t, ctx)
	source.after = func() {
		if source.reads == 2 {
			f.s.auth.role = "user"
		}
	}
	if signed, err := f.i.IssueBootstrapOriginalMapping(ctx, f.password, f.enrollment, pack, hash(pack), request, nil, strings.Repeat("e", 64), filepath.Join(t.TempDir(), "original-report"), f.key); err == nil || len(signed.Record) != 0 {
		t.Fatal("source issuer ignored final original current authority")
	}
	if source.reads != 2 || f.s.auth.role != "user" {
		t.Fatal("revocation fault did not reach the actual producer source reads", source.reads)
	}
}
