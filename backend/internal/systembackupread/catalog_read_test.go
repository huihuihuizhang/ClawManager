package systembackupread

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	contract "clawreef/internal/systembackupcontract"
)

// SQL/read-boundary fixture only. C's real native/signature reader has its own
// content tests; this fake cannot enter the production server's concrete field.
type catalogBoundaryFixture struct {
	rows                      [][]driver.Value
	deny, revoke              bool
	commits, rechecks, writes int
}

func (f *catalogBoundaryFixture) AuthorizeRead(context.Context, *sql.Tx) (string, error) {
	if f.deny {
		return "", ErrDenied
	}
	return "installation_test", nil
}
func (f *catalogBoundaryFixture) RecheckRead(context.Context, *sql.Tx, string) error {
	f.rechecks++
	if f.revoke {
		return ErrDenied
	}
	return nil
}

type catalogBoundaryConnector struct{ f *catalogBoundaryFixture }
type catalogBoundaryConn struct{ f *catalogBoundaryFixture }
type catalogBoundaryTx struct{ f *catalogBoundaryFixture }

func (c catalogBoundaryConnector) Connect(context.Context) (driver.Conn, error) {
	return &catalogBoundaryConn{c.f}, nil
}
func (c catalogBoundaryConnector) Driver() driver.Driver { return pageDriver{} }
func (c *catalogBoundaryConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("direct query required")
}
func (c *catalogBoundaryConn) Close() error              { return nil }
func (c *catalogBoundaryConn) Begin() (driver.Tx, error) { return catalogBoundaryTx{c.f}, nil }
func (c *catalogBoundaryConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return catalogBoundaryTx{c.f}, nil
}
func (t catalogBoundaryTx) Commit() error   { t.f.commits++; return nil }
func (t catalogBoundaryTx) Rollback() error { return nil }
func (c *catalogBoundaryConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.f.writes++
	return nil, errors.New("READ only")
}
func (c *catalogBoundaryConn) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if q == "SELECT UTC_TIMESTAMP(6)" {
		return &pageRows{columns: []string{"now"}, values: [][]driver.Value{{time.Now().UTC()}}}, nil
	}
	if len(a) == 0 || a[0].Value != "installation_test" {
		return nil, errors.New("unscoped installation")
	}
	if strings.Contains(q, "COALESCE(MAX(id),0)") {
		return &pageRows{columns: []string{"cutoff"}, values: [][]driver.Value{{int64(3)}}}, nil
	}
	if !strings.Contains(q, "artifact_registration_id IS NOT NULL") || !strings.Contains(q, "ORDER BY id DESC LIMIT ?") {
		return nil, errors.New("unreviewed catalog SQL")
	}
	var before uint64
	if _, e := fmt.Sscan(fmt.Sprint(a[2].Value), &before); e != nil {
		return nil, e
	}
	var maximum int
	if _, e := fmt.Sscan(fmt.Sprint(a[len(a)-1].Value), &maximum); e != nil {
		return nil, e
	}
	var values [][]driver.Value
	for _, row := range c.f.rows {
		if before != 0 && uint64(row[0].(int64)) >= before {
			continue
		}
		if len(a) == 6 && row[4] != a[4].Value {
			continue
		}
		values = append(values, row)
		if len(values) == maximum {
			break
		}
	}
	return &pageRows{columns: []string{"id", "task", "rv", "config", "registration", "hash"}, values: values}, nil
}

type catalogBoundaryProvider struct {
	f        *catalogBoundaryFixture
	raw      map[string][]byte
	fault    string
	calls    int
	retained CurrentFactsSQL
}

func (p *catalogBoundaryProvider) Catalog(_ context.Context, q CurrentFactsSQL, c CatalogRecordControl) (contract.CatalogRecordResource, time.Time, error) {
	p.calls++
	p.retained = q
	raw := p.raw[c.RegistrationID]
	sum := sha256.Sum256(raw)
	item := contract.CatalogRecordResource{ID: c.RegistrationID, RecordSHA256: hex.EncodeToString(sum[:]), Record: raw}
	until := time.Now().Add(time.Minute)
	if p.fault == "hash" {
		item.RecordSHA256 = strings.Repeat("a", 64)
	}
	if p.fault == "expired" {
		until = time.Now().Add(-time.Second)
	}
	if p.fault == "revoke" {
		p.f.revoke = true
	}
	return item, until, nil
}
func newCatalogBoundary(t *testing.T) (*Reader, *CatalogCursorCodec, *catalogBoundaryProvider) {
	t.Helper()
	f := &catalogBoundaryFixture{}
	p := &catalogBoundaryProvider{f: f, raw: map[string][]byte{}}
	for id := 3; id > 0; id-- {
		suffix := fmt.Sprintf("00000000-0000-4000-8000-%012d", id)
		registration := "scr_" + suffix
		raw := []byte(fmt.Sprintf(`{"original_content_data":%d}`, id))
		sum := sha256.Sum256(raw)
		p.raw[registration] = raw
		f.rows = append(f.rows, []driver.Value{int64(id), "sbk_" + suffix, int64(7), int64(1), registration, hex.EncodeToString(sum[:])})
	}
	db := sql.OpenDB(catalogBoundaryConnector{f})
	t.Cleanup(func() { db.Close() })
	r, e := NewReader(db, f)
	if e != nil {
		t.Fatal(e)
	}
	codec, e := NewCatalogCursorCodec([]byte(strings.Repeat("c", 32)))
	if e != nil {
		t.Fatal(e)
	}
	return r, codec, p
}
func TestCatalogCurrentV1ScopedPaginationAndCapabilityClosure(t *testing.T) {
	r, codec, p := newCatalogBoundary(t)
	ctx := context.Background()
	token := ""
	seen := map[string]bool{}
	for n := 0; n < 3; n++ {
		page, e := r.ListCatalogRecordsCurrentV1(ctx, 1, token, codec, p)
		if e != nil || len(page.Items) != 1 || page.Consistency != "eventual" || seen[page.Items[0].ID] {
			t.Fatal("bounded local-registration page", e)
		}
		seen[page.Items[0].ID] = true
		var now time.Time
		if p.retained.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now) == nil {
			t.Fatal("catalog SQL capability escaped callback")
		}
		if n < 2 {
			if page.NextCursor == nil {
				t.Fatal("missing continuation")
			}
			token = *page.NextCursor
		} else if page.NextCursor != nil {
			t.Fatal("extra continuation")
		}
	}
	if p.f.writes != 0 || p.f.commits != 3 || p.f.rechecks != 3 {
		t.Fatal("catalog page bypassed read boundary")
	}
	if _, e := codec.decode(token, 2); e == nil {
		t.Fatal("catalog cursor rebound limit")
	}
	foreign, e := codec.encode(catalogCursor{Installation: "installation_foreign", Limit: 1, Cutoff: 3, Before: 3})
	if e != nil {
		t.Fatal(e)
	}
	before := p.calls
	if _, e = r.ListCatalogRecordsCurrentV1(ctx, 1, foreign, codec, p); !errors.Is(e, ErrDenied) || p.calls != before {
		t.Fatal("foreign cursor selected installation", e)
	}
}
func TestCatalogCurrentV1RejectsDriftExpiryAndLateRevocation(t *testing.T) {
	for _, fault := range []string{"hash", "expired", "revoke", "deny"} {
		t.Run(fault, func(t *testing.T) {
			r, codec, p := newCatalogBoundary(t)
			p.fault = fault
			p.f.deny = fault == "deny"
			page, e := r.ListCatalogRecordsCurrentV1(context.Background(), 1, "", codec, p)
			if e == nil || len(page.Items) != 0 || p.f.commits != 0 || p.f.writes != 0 {
				t.Fatal("failed catalog read leaked a page or committed", e)
			}
		})
	}
}
