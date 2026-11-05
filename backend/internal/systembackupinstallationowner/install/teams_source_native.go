package install

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	"github.com/go-sql-driver/mysql"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func teamsSourcePins(d TeamsSourceIssueDefinition) error {
	if d.Source.Objects == nil {
		return ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{d.DatabaseCredential, d.PartsRegistry, {File: d.Source.CredentialFile, SHA256: d.Source.CredentialSHA256}, {File: d.Source.Objects.CAFile, SHA256: d.Source.Objects.CASHA256}} {
		raw, e := readBootstrapSourcePin(pin, 8<<20)
		clear(raw)
		if e != nil {
			return ErrInstall
		}
	}
	return nil
}

// No injectable driver/reader/Passed result: the actual native connector is
// constructed here from original pinned TLS and a finite source account.
// SQL RR closes before Kubernetes/S3 or owner-prefix rechecks run.
func (p *SourceMaterialIssuer) readTeamsSQL(ctx context.Context, d TeamsSourceIssueDefinition, mapped *team.Inventory) (*team.Inventory, error) {
	r, e := p.originalDatabaseSourceRequest()
	if e != nil {
		return nil, ErrInstall
	}
	raw, e := readBootstrapSourcePin(d.DatabaseCredential, 16384)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(raw)
	var credential worker.DatabaseCredential
	if teamsExactJSON(raw, &credential) != nil || credential.Username == "root" || !strings.HasPrefix(d.DatabaseAccount, credential.Username+"@") || d.DatabaseAccount == p.intent.DatabaseAccount || d.DatabaseAccount == p.operator.installer.plan.InstallerDatabaseAccount {
		clear(credential.Password)
		return nil, ErrInstall
	}
	defer clear(credential.Password)
	service := DatabaseSourceIssueDefinition{Service: d.DatabaseService, ServiceUID: d.DatabaseServiceUID, Port: d.DatabasePort}
	if p.databaseSourceService(ctx, service, r) != nil {
		return nil, ErrInstall
	}
	var verified atomic.Bool
	cfg, e := databaseSourceConnector(r, credential, &verified)
	if e != nil {
		return nil, ErrInstall
	}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return nil, ErrInstall
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, ErrInstall
	}
	defer tx.Rollback()
	identity := func() error {
		var account, role, database, uuid string
		var now time.Time
		if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)").Scan(&account, &role, &database, &uuid, &now) != nil || !verified.Load() || account != d.DatabaseAccount || role != "NONE" || database != p.intent.Database || uuid != p.intent.ServerUUID || now.Before(p.intent.NotBefore) || !now.Before(p.intent.Until) {
			return ErrInstall
		}
		return nil
	}
	if identity() != nil || domain.CheckBusinessSchemaCensus(ctx, tx, *r.Database.SchemaCensus) != nil {
		return nil, ErrInstall
	}
	rows, e := tx.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
	if e != nil {
		return nil, ErrInstall
	}
	grants := []string{}
	for rows.Next() {
		var s string
		if len(grants) >= 1000 || rows.Scan(&s) != nil || len(s) > 16384 {
			rows.Close()
			return nil, ErrInstall
		}
		grants = append(grants, s)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || domain.ValidateBusinessSourceGrants(p.intent.Database, grants) != nil {
		return nil, ErrInstall
	}
	users, owners := map[int]bool{}, map[int]int{}
	rows, e = tx.QueryContext(ctx, "SELECT id FROM users ORDER BY id")
	if e != nil {
		return nil, ErrInstall
	}
	for rows.Next() {
		var id int
		if ctx.Err() != nil || len(users) >= 100000 || rows.Scan(&id) != nil || id <= 0 || users[id] {
			rows.Close()
			return nil, ErrInstall
		}
		users[id] = true
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, ErrInstall
	}
	instances, e := domain.ReadSourceInstances(ctx, tx)
	if e != nil {
		return nil, ErrInstall
	}
	for _, instance := range instances {
		if !users[instance.UserID] || owners[instance.ID] != 0 {
			return nil, ErrInstall
		}
		owners[instance.ID] = instance.UserID
	}
	actual, e := team.ReadInventory(ctx, tx, *mapped, users, owners)
	if e != nil || !reflect.DeepEqual(actual, mapped) || identity() != nil || tx.Commit() != nil {
		return nil, ErrTeamsSourceUnavailable
	}
	return actual, nil
}

type teamsObjectTransport struct {
	host      string
	transport *http.Transport
}

func (t teamsObjectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.host || r.URL.User != nil {
		return nil, ErrInstall
	}
	return t.transport.RoundTrip(r)
}

func teamsObjectClient(d TeamsSourceIssueDefinition) (*minio.Client, func(), error) {
	m := d.Source.Objects
	if m == nil || m.Address == "" || m.ServerName == "" || strings.ContainsAny(m.Address+m.ServerName, "/\\@?# \t\r\n\x00") {
		return nil, nil, ErrInstall
	}
	u, e := url.Parse("https://" + m.Address)
	if e != nil || u.Host != m.Address || u.Hostname() == "" {
		return nil, nil, ErrInstall
	}
	ca, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: m.CAFile, SHA256: m.CASHA256}, 65536)
	pool := x509.NewCertPool()
	if e != nil || !pool.AppendCertsFromPEM(ca) {
		return nil, nil, ErrInstall
	}
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: d.Source.CredentialFile, SHA256: d.Source.CredentialSHA256}, 16384)
	if e != nil {
		return nil, nil, ErrInstall
	}
	defer clear(raw)
	var credential struct {
		AccessKey string `json:"access_key,omitempty"`
		SecretKey []byte `json:"secret_key,omitempty"`
	}
	if teamsExactJSON(raw, &credential) != nil || credential.AccessKey == "" || len(credential.SecretKey) == 0 {
		clear(credential.SecretKey)
		return nil, nil, ErrInstall
	}
	defer clear(credential.SecretKey)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: m.ServerName}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableCompression: true, MaxResponseHeaderBytes: 32768}
	client, e := minio.New(m.Address, &minio.Options{Secure: true, Creds: credentials.NewStaticV4(credential.AccessKey, string(credential.SecretKey), ""), Transport: teamsObjectTransport{host: m.Address, transport: transport}})
	if e != nil {
		transport.CloseIdleConnections()
		return nil, nil, ErrInstall
	}
	return client, transport.CloseIdleConnections, nil
}

// LIST every version under every disjoint original root, then verify every
// referenced immutable version by exact GET/version/body SHA. SQL references alone are
// never proof of the absence of unreferenced objects in those roots.
func observeTeamsObjects(ctx context.Context, client *minio.Client, d TeamsSourceIssueDefinition, inventory *team.Inventory) error {
	want := map[string]team.ObjectRef{}
	for _, ref := range inventory.Objects {
		want[ref.Bucket+"\x00"+ref.Key] = ref
	}
	seen := map[string]bool{}
	versions := 0
	var total int64
	for _, prefix := range d.Source.ObjectPrefixes {
		versioning, e := client.GetBucketVersioning(ctx, prefix.Bucket)
		if e != nil || !versioning.Enabled() {
			return ErrInstall
		}
		listCtx, cancel := context.WithCancel(ctx)
		for object := range client.ListObjects(listCtx, prefix.Bucket, minio.ListObjectsOptions{Prefix: prefix.Prefix, Recursive: true, WithVersions: true}) {
			versions++
			if object.Err != nil || versions > 100000 || !strings.HasPrefix(object.Key, prefix.Prefix) || object.VersionID == "" || object.VersionID == "null" {
				cancel()
				return ErrInstall
			}
			key := prefix.Bucket + "\x00" + object.Key
			ref, exists := want[key]
			if object.IsDeleteMarker {
				continue
			}
			if len(want) == 0 || object.IsLatest && !exists {
				cancel()
				return ErrTeamsSourceUnavailable
			}
			if !exists || ref.Version != object.VersionID {
				continue
			}
			if seen[key] || ref.Size != object.Size || ref.Size > 64<<20 || ref.Size < 0 || ref.Size > (1<<30)-total {
				cancel()
				return ErrTeamsSourceUnavailable
			}
			seen[key] = true
			total += ref.Size
		}
		err := listCtx.Err()
		cancel()
		if err != nil {
			return ErrInstall
		}
	}
	if len(seen) != len(want) {
		return ErrTeamsSourceUnavailable
	}
	for _, ref := range inventory.Objects {
		object, e := client.GetObject(ctx, ref.Bucket, ref.Key, minio.GetObjectOptions{VersionID: ref.Version})
		if e != nil {
			return ErrInstall
		}
		info, e := object.Stat()
		if e != nil || info.VersionID != ref.Version || info.Size != ref.Size {
			object.Close()
			return ErrInstall
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(object, ref.Size+1))
		closeErr := object.Close()
		if e != nil || closeErr != nil || n != ref.Size || hex.EncodeToString(h.Sum(nil)) != ref.SHA256 {
			return ErrInstall
		}
	}
	return ctx.Err()
}

func (p *SourceMaterialIssuer) observeTeamsSource(ctx context.Context, d TeamsSourceIssueDefinition, inventory *team.Inventory) (time.Time, error) {
	zero := time.Time{}
	if p.Recheck(ctx) != nil || teamsSourcePins(d) != nil || ValidateTeamsSourceInventory(d.Source, inventory) != nil {
		return zero, ErrInstall
	}
	before, e := p.readTeamsSQL(ctx, d, inventory)
	if e != nil {
		return zero, e
	}
	// All native API IO runs after the read-only source transaction is closed.
	if p.observeTeamsClaims(ctx, inventory) != nil {
		return zero, ErrInstall
	}
	client, close, e := teamsObjectClient(d)
	if e != nil {
		return zero, e
	}
	defer close()
	if observeTeamsObjects(ctx, client, d, inventory) != nil || p.Recheck(ctx) != nil {
		return zero, ErrTeamsSourceUnavailable
	}
	after, e := p.readTeamsSQL(ctx, d, inventory)
	if e != nil || !reflect.DeepEqual(before, after) || observeTeamsObjects(ctx, client, d, inventory) != nil || p.observeTeamsClaims(ctx, inventory) != nil || teamsSourcePins(d) != nil || p.Recheck(ctx) != nil {
		return zero, ErrTeamsSourceUnavailable
	}
	return time.Now().Add(15 * time.Second), nil
}

func (p *SourceMaterialIssuer) observeTeamsClaims(ctx context.Context, inventory *team.Inventory) error {
	for _, mount := range inventory.Mounts {
		claim, e := p.operator.installer.kube.CoreV1().PersistentVolumeClaims(mount.Namespace).Get(ctx, mount.PVC, metav1.GetOptions{})
		if e != nil || string(claim.UID) != mount.UID || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
			return ErrInstall
		}
		pv, e := p.operator.installer.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
		if e != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != mount.Namespace || pv.Spec.ClaimRef.Name != mount.PVC {
			return ErrInstall
		}
	}
	return ctx.Err()
}
