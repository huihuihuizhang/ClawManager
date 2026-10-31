package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	k "clawreef/internal/systembackupkms"
)

// Invoked by the actual core -> Forward/Recovery -> independent materials
// bootstrap fixture. Only SQL transport is a strict read-only driver here.
func checkProviderDatabaseAdmission(t *testing.T, cfg DeploymentConfig, coreFile, coreSHA, forwardSHA, recoverySHA string, forward c.ExecutionGrant, materials FormalVerifierDeploymentConfig, materialFile string) {
	t.Helper()
	original, err := os.ReadFile(materialFile)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(materialFile, original, 0600)
	issuer, private, _ := ed25519.GenerateKey(rand.Reader)
	clear(private)
	root, key, _ := ed25519.GenerateKey(rand.Reader)
	clear(key)
	workload := materials.Workload
	workload.GrantSHA256 = strings.Repeat("7", 64)
	materials.ProviderPermits = &ProviderPermitDeploymentConfig{Workload: workload, Grant: a.ProviderPermitIssuerGrantMount{File: filepath.Join(filepath.Dir(materialFile), "original-issuer.json"), SHA256: workload.GrantSHA256, Issuer: root}, SigningKeyFile: filepath.Join(filepath.Dir(materialFile), "original-issuer.key"), DeliveryPin: k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: issuer, IssuerGrantSHA256: workload.GrantSHA256}}
	raw := mustJSON(t, materials)
	if os.WriteFile(materialFile, raw, 0600) != nil {
		t.Fatal("independent issuer materials write failed")
	}
	user := strings.Split(forward.DatabaseAccount, "@")[0]
	correct, err := c.FormalProviderPermitGrantSQL(forward.Database, user, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	old, err := c.FormalCaptureGrantSQL(forward.Database, user, "127.0.0.1", false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "missing-reference-writes", "extra-delete", "missing-materials", "wrong-pin", "recovery"} {
		t.Run("early-database-"+mode, func(t *testing.T) {
			grants := append([]string(nil), correct...)
			if mode == "missing-reference-writes" {
				grants = old
			}
			if mode == "extra-delete" {
				grants = append(grants, "GRANT DELETE ON `"+forward.Database+"`.`system_backup_v2_kek_references` TO '"+user+"'@'127.0.0.1';")
			}
			for i := range grants {
				grants[i] = strings.TrimSuffix(grants[i], ";")
			}
			pool := sql.OpenDB(providerAdmissionConnector{grant: forward, grants: grants})
			defer pool.Close()
			inputs := []FormalVerifierInput{{File: materialFile, SHA256: hash(raw)}}
			if mode == "missing-materials" || mode == "recovery" {
				inputs = nil
			}
			if mode == "wrong-pin" {
				inputs[0].SHA256 = strings.Repeat("0", 64)
			}
			err := CheckDeploymentDatabase(context.Background(), pool, coreFile, coreSHA, forwardSHA, recoverySHA, mode != "recovery", inputs...)
			if (mode == "valid" || mode == "recovery") != (err == nil) {
				t.Fatal("actual early DB material/role admission mismatch", err)
			}
		})
	}
	_ = cfg // Core bytes and signed identities are loaded by CheckDeploymentDatabase.
}

type providerAdmissionConnector struct {
	grant  c.ExecutionGrant
	grants []string
}

func (p providerAdmissionConnector) Connect(context.Context) (driver.Conn, error) {
	return providerAdmissionConn{p}, nil
}
func (p providerAdmissionConnector) Driver() driver.Driver { return providerAdmissionDriver{p} }

type providerAdmissionDriver struct{ p providerAdmissionConnector }

func (p providerAdmissionDriver) Open(string) (driver.Conn, error) {
	return providerAdmissionConn{p.p}, nil
}

type providerAdmissionConn struct{ p providerAdmissionConnector }

func (providerAdmissionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (providerAdmissionConn) Close() error { return nil }
func (providerAdmissionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (p providerAdmissionConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if len(args) != 0 {
		return nil, errors.New("unexpected SQL parameters")
	}
	rows := &providerAdmissionRows{}
	switch q {
	case "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()":
		rows.columns = []string{"now", "account", "server", "database"}
		rows.values = [][]driver.Value{{p.p.grant.NotBefore.Add(p.p.grant.ExpiresAt.Sub(p.p.grant.NotBefore) / 2), p.p.grant.DatabaseAccount, p.p.grant.ServerUUID, p.p.grant.Database}}
	case "SELECT CURRENT_USER()":
		rows.columns = []string{"account"}
		rows.values = [][]driver.Value{{p.p.grant.DatabaseAccount}}
	case "SELECT CURRENT_ROLE()":
		rows.columns = []string{"role"}
		rows.values = [][]driver.Value{{"NONE"}}
	case "SHOW GRANTS":
		rows.columns = []string{"grant"}
		for _, grant := range p.p.grants {
			rows.values = append(rows.values, []driver.Value{grant})
		}
	default:
		return nil, errors.New("unexpected database admission query")
	}
	return rows, nil
}

type providerAdmissionRows struct {
	columns []string
	values  [][]driver.Value
}

func (p *providerAdmissionRows) Columns() []string { return p.columns }
func (*providerAdmissionRows) Close() error        { return nil }
func (p *providerAdmissionRows) Next(out []driver.Value) error {
	if len(p.values) == 0 {
		return io.EOF
	}
	copy(out, p.values[0])
	p.values = p.values[1:]
	return nil
}
