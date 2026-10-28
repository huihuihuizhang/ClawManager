package control

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"time"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

type IdentityIssuer struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	ServerRoots []byte
	TrustDomain string
}
type TaskIdentity struct {
	SPIFFE    string
	ExpiresAt time.Time
	Data      map[string][]byte
}

func (i IdentityIssuer) Issue(t Task, invocationHash string) (TaskIdentity, error) {
	if i.Certificate == nil || i.Signer == nil || !i.Certificate.IsCA || i.Certificate.KeyUsage&x509.KeyUsageCertSign == 0 || !identifier.MatchString(t.ID) || !revision.MatchString(invocationHash) || len(validation.IsDNS1123Subdomain(i.TrustDomain)) != 0 {
		return TaskIdentity{}, ErrInvalid
	}
	public, e := x509.MarshalPKIXPublicKey(i.Signer.Public())
	if e != nil || !bytes.Equal(public, i.Certificate.RawSubjectPublicKeyInfo) {
		return TaskIdentity{}, ErrInvalid
	}
	expiry := time.UnixMilli(t.Deadline)
	now := time.Now()
	if !now.Before(expiry) || expiry.After(now.Add(2*time.Hour)) || expiry.After(i.Certificate.NotAfter) || now.Before(i.Certificate.NotBefore) {
		return TaskIdentity{}, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(i.ServerRoots) {
		return TaskIdentity{}, ErrInvalid
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return TaskIdentity{}, ErrNotReady
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil || serial.Sign() == 0 {
		return TaskIdentity{}, ErrNotReady
	}
	uri := &url.URL{Scheme: "spiffe", Host: i.TrustDomain, Path: "/backup/" + t.ID + "/" + invocationHash}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "backup-worker"}, NotBefore: now.Add(-30 * time.Second), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}, BasicConstraintsValid: true}
	cert, e := x509.CreateCertificate(rand.Reader, template, i.Certificate, &key.PublicKey, i.Signer)
	if e != nil {
		return TaskIdentity{}, ErrNotReady
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return TaskIdentity{}, ErrNotReady
	}
	defer clear(private)
	return TaskIdentity{SPIFFE: uri.String(), ExpiresAt: expiry, Data: map[string][]byte{"ca.crt": append([]byte(nil), i.ServerRoots...), "tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), "tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}}, nil
}
func (i *TaskIdentity) Clear() {
	for _, b := range i.Data {
		clear(b)
	}
}

// WorkerIdentities keeps private key material ONLY in encrypted records and
// task-specific immutable Kubernetes Secrets. General resource journals/DTOs
// never contain the private key. Uncertain CREATEs are reconciled, not retried.
type WorkerIdentities struct {
	Vault  Vault
	Client kubernetes.Interface
	Issuer IdentityIssuer
}
type identityRow struct {
	namespace, hash, uid, rv string
	dispatched, deleted      bool
}

func identityHash(i TaskIdentity) string {
	b, _ := json.Marshal(i)
	defer clear(b)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (m WorkerIdentities) payload(ctx context.Context, t Task, name, invocationHash string, create bool) (TaskIdentity, error) {
	raw, e := m.Vault.Get(ctx, t, name, "worker-identity")
	if errors.Is(e, ErrNotFound) && create {
		identity, e := m.Issuer.Issue(t, invocationHash)
		if e != nil {
			return identity, e
		}
		raw, e = json.Marshal(identity)
		identity.Clear()
		if e != nil {
			return TaskIdentity{}, ErrInvalid
		}
		if e = m.Vault.Put(ctx, t, name, "worker-identity", raw); e != nil {
			clear(raw)
			return TaskIdentity{}, e
		}
	} else if e != nil {
		return TaskIdentity{}, e
	}
	defer clear(raw)
	var identity TaskIdentity
	if json.Unmarshal(raw, &identity) != nil {
		return TaskIdentity{}, ErrConflict
	}
	expected := (&url.URL{Scheme: "spiffe", Host: m.Issuer.TrustDomain, Path: "/backup/" + t.ID + "/" + invocationHash}).String()
	if identity.SPIFFE != expected || identity.ExpiresAt.UnixMilli() != t.Deadline || len(identity.Data) != 3 || len(identity.Data["tls.key"]) == 0 {
		identity.Clear()
		return TaskIdentity{}, ErrConflict
	}
	return identity, nil
}
func (m WorkerIdentities) row(ctx context.Context, t Task, namespace, name, hash, action, uid, rv string) (identityRow, error) {
	s := m.Vault.Store
	tx, e := s.begin(ctx)
	if e != nil {
		return identityRow{}, e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return identityRow{}, ErrFence
	}
	var r identityRow
	e = tx.QueryRowContext(ctx, "SELECT namespace_name,payload_sha256,dispatched,uid,resource_version,deleted FROM system_backup_identities WHERE task_id=? AND secret_name=? FOR UPDATE", t.ID, name).Scan(&r.namespace, &r.hash, &r.dispatched, &r.uid, &r.rv, &r.deleted)
	if errors.Is(e, sql.ErrNoRows) && action == "read" {
		// The encrypted payload can precede the resource intent. No CREATE can
		// have been dispatched without that row; cleanup must not create one.
		return identityRow{namespace: namespace, hash: hash, deleted: true}, nil
	}
	if errors.Is(e, sql.ErrNoRows) && action == "prepare" {
		current, e := load(ctx, tx, t.ID)
		if e != nil || !current.CanCancel {
			return r, ErrFence
		}
		r = identityRow{namespace: namespace, hash: hash}
		_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_identities(task_id,secret_name,namespace_name,payload_sha256) VALUES(?,?,?,?)", t.ID, name, namespace, hash)
		if e != nil {
			return r, ErrNotReady
		}
	} else if e != nil {
		return r, ErrNotReady
	}
	if r.namespace != namespace || r.hash != hash {
		return r, ErrConflict
	}
	switch action {
	case "prepare", "read":
	case "dispatch":
		current, e := load(ctx, tx, t.ID)
		n, ne := now(ctx, tx)
		if e != nil || ne != nil || !current.CanCancel || current.Deadline <= n || r.dispatched || r.deleted {
			return r, ErrConflict
		}
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_identities SET dispatched=TRUE WHERE task_id=? AND secret_name=?", t.ID, name)
		r.dispatched = true
		if e != nil {
			return r, ErrNotReady
		}
	case "observe":
		if !r.dispatched || r.deleted || uid == "" || rv == "" || (r.uid != "" && r.uid != uid) {
			return r, ErrConflict
		}
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_identities SET uid=?,resource_version=? WHERE task_id=? AND secret_name=?", uid, rv, t.ID, name)
		r.uid = uid
		r.rv = rv
		if e != nil {
			return r, ErrNotReady
		}
	case "deleted":
		if r.dispatched && r.uid == "" {
			return r, ErrNotReady
		}
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_identities SET deleted=TRUE WHERE task_id=? AND secret_name=?", t.ID, name)
		r.deleted = true
		if e != nil {
			return r, ErrNotReady
		}
	default:
		return r, ErrInvalid
	}
	if s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return r, ErrNotReady
	}
	return r, nil
}
func (m WorkerIdentities) Ensure(ctx context.Context, t Task, namespace, name, invocationHash string) (string, error) {
	if m.Client == nil || !identifier.MatchString(name) || len(name) > 128 || len(validation.IsDNS1123Subdomain(name)) != 0 || len(validation.IsDNS1123Label(namespace)) != 0 {
		return "", ErrInvalid
	}
	identity, e := m.payload(ctx, t, name, invocationHash, true)
	if e != nil {
		return "", e
	}
	defer identity.Clear()
	hash := identityHash(identity)
	r, e := m.row(ctx, t, namespace, name, hash, "prepare", "", "")
	if e != nil || r.deleted {
		return "", ErrConflict
	}
	secrets := m.Client.CoreV1().Secrets(namespace)
	secret, e := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		if r.dispatched {
			return "", ErrNotReady
		}
		if _, e = m.row(ctx, t, namespace, name, hash, "dispatch", "", ""); e != nil {
			return "", e
		}
		immutable := true
		secret, e = secrets.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{kube.OwnerLabel: t.ID}, Annotations: map[string]string{"backup.clawmanager.io/identity-sha256": hash}}, Type: corev1.SecretTypeTLS, Immutable: &immutable, Data: identity.Data}, metav1.CreateOptions{})
		if e != nil {
			return "", ErrNotReady
		}
	} else if e != nil {
		return "", ErrNotReady
	} else if !r.dispatched {
		return "", ErrConflict
	}
	if !ownedIdentity(t, secret, identity, hash) || secret.DeletionTimestamp != nil || (r.uid != "" && r.uid != string(secret.UID)) {
		return "", ErrConflict
	}
	if _, e = m.row(ctx, t, namespace, name, hash, "observe", string(secret.UID), secret.ResourceVersion); e != nil {
		return "", e
	}
	return identity.SPIFFE, nil
}
func ownedIdentity(t Task, s *corev1.Secret, i TaskIdentity, hash string) bool {
	if s == nil || s.UID == "" || s.ResourceVersion == "" || s.Type != corev1.SecretTypeTLS || s.Immutable == nil || !*s.Immutable || s.Labels[kube.OwnerLabel] != t.ID || s.Annotations["backup.clawmanager.io/identity-sha256"] != hash || len(s.Data) != len(i.Data) {
		return false
	}
	for k, b := range i.Data {
		if !bytes.Equal(s.Data[k], b) {
			return false
		}
	}
	return true
}
func (m WorkerIdentities) Delete(ctx context.Context, t Task, namespace, name, invocationHash string) error {
	if m.Client == nil || !identifier.MatchString(name) || len(validation.IsDNS1123Subdomain(name)) != 0 || len(validation.IsDNS1123Label(namespace)) != 0 {
		return ErrInvalid
	}
	identity, e := m.payload(ctx, t, name, invocationHash, false)
	if e != nil {
		return e
	}
	defer identity.Clear()
	hash := identityHash(identity)
	r, e := m.row(ctx, t, namespace, name, hash, "read", "", "")
	if e != nil {
		return e
	}
	if r.deleted {
		return nil
	}
	secrets := m.Client.CoreV1().Secrets(namespace)
	secret, e := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		_, e = m.row(ctx, t, namespace, name, hash, "deleted", "", "")
		return e
	}
	if e != nil || !r.dispatched || !ownedIdentity(t, secret, identity, hash) || (r.uid != "" && r.uid != string(secret.UID)) {
		return ErrConflict
	}
	if _, e = m.row(ctx, t, namespace, name, hash, "observe", string(secret.UID), secret.ResourceVersion); e != nil {
		return e
	}
	uid := types.UID(secret.UID)
	rv := secret.ResourceVersion
	if e = secrets.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); e != nil && !apierrors.IsNotFound(e) {
		return ErrNotReady
	}
	if _, e = secrets.Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(e) {
		return ErrNotReady
	}
	_, e = m.row(ctx, t, namespace, name, hash, "deleted", "", "")
	return e
}
