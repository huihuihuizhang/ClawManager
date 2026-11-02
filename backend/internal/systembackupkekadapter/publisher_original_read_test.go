package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type currentOriginalReadData struct {
	raw, signature                  []byte
	installation, identity, version string
	queries, writes                 int
}
type currentOriginalConnector struct{ data *currentOriginalReadData }
type currentOriginalConn struct{ data *currentOriginalReadData }
type currentOriginalRows struct {
	data *currentOriginalReadData
	done bool
}

func (c currentOriginalConnector) Connect(context.Context) (driver.Conn, error) {
	return &currentOriginalConn{c.data}, nil
}
func (c currentOriginalConnector) Driver() driver.Driver { return currentOriginalDriver{} }

type currentOriginalDriver struct{}

func (currentOriginalDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector only")
}
func (*currentOriginalConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("direct query only")
}
func (*currentOriginalConn) Close() error { return nil }
func (*currentOriginalConn) Begin() (driver.Tx, error) {
	return nil, errors.New("original caller owns transaction")
}
func (c *currentOriginalConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.data.queries++
	if query != originalQuery+" FOR SHARE" || len(args) != 3 || args[0].Value != c.data.installation || args[1].Value != c.data.identity || args[2].Value != c.data.version {
		return nil, errors.New("not original scoped owner read")
	}
	return &currentOriginalRows{data: c.data}, nil
}
func (c *currentOriginalConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.data.writes++
	return nil, errors.New("read only")
}
func (*currentOriginalRows) Columns() []string { return []string{"signed_record", "signature"} }
func (*currentOriginalRows) Close() error      { return nil }
func (r *currentOriginalRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0], dest[1] = r.data.raw, r.data.signature
	return nil
}

// API-shaped signed source data; never a provider permit or mapping admission.
func TestReadCurrentOriginalUnwrapTxAuthenticatesOriginalView(t *testing.T) {
	for _, fault := range []string{"current", "generate-only-revoked", "unwrap-revoked", "expired", "future", "signature", "issuer", "binding"} {
		t.Run(fault, func(t *testing.T) {
			record, issuer, private := ownerRecordFixture(t)
			defer clear(private)
			now := time.Now().UTC()
			binding := record.Binding
			switch fault {
			case "generate-only-revoked":
				record.GenerateRevoked = true
			case "unwrap-revoked":
				record.UnwrapRevoked = true
			case "expired":
				record.Until = now
			case "future":
				record.NotBefore = now.Add(time.Minute)
			case "binding":
				binding.Provider.ScopeHash = strings.Repeat("f", 64)
			}
			raw, signature := signOwner(record, private)
			if fault == "signature" {
				signature[0] ^= 1
			}
			if fault == "issuer" {
				issuer = make(ed25519.PublicKey, ed25519.PublicKeySize)
			}
			data := &currentOriginalReadData{raw: raw, signature: signature, installation: binding.InstallationID, identity: binding.ConfigRef.IdentityHash, version: binding.ConfigRef.Version}
			db := sql.OpenDB(currentOriginalConnector{data})
			defer db.Close()
			got, err := ReadCurrentOriginalUnwrapTx(context.Background(), db, binding, issuer, now)
			if fault == "current" || fault == "generate-only-revoked" {
				if err != nil || got.Revision != record.Revision || got.GenerateRevoked != record.GenerateRevoked {
					t.Fatal("original signed Unwrap comparison", err)
				}
			} else if err == nil {
				t.Fatal("invalid original owner accepted", fault)
			}
			if data.queries != 1 || data.writes != 0 {
				t.Fatal("owner export escaped original read boundary")
			}
		})
	}
}
