package install

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	"golang.org/x/crypto/bcrypt"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Real database/sql transaction protocol + actual local TLS API protocol.
// This is not live MySQL, Kubernetes administrator authentication or enrollment.
type authSQLState struct {
	ca                              []byte
	plan                            Plan
	stored                          string
	active                          bool
	role, provider, account, server string
	queries, commits, writes        int
}
type authConnector struct{ s *authSQLState }

func (c authConnector) Driver() driver.Driver                        { return authDriver{} }
func (c authConnector) Connect(context.Context) (driver.Conn, error) { return &authConn{s: c.s}, nil }

type authDriver struct{}

func (authDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type authConn struct {
	s  *authSQLState
	tx bool
}

func (c *authConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *authConn) Close() error                        { return nil }
func (c *authConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *authConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if c.tx || !opts.ReadOnly || opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("unexpected transaction")
	}
	c.tx = true
	return authTx{c}, nil
}

type authTx struct{ c *authConn }

func (t authTx) Commit() error   { t.c.tx = false; t.c.s.commits++; return nil }
func (t authTx) Rollback() error { t.c.tx = false; return nil }

type authRows struct {
	values []driver.Value
	sent   bool
}

func (r *authRows) Columns() []string { return make([]string, len(r.values)) }
func (*authRows) Close() error        { return nil }
func (r *authRows) Next(out []driver.Value) error {
	if r.sent {
		return io.EOF
	}
	r.sent = true
	copy(out, r.values)
	return nil
}
func (c *authConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c.s.queries++
	s := c.s
	var values []driver.Value
	switch q {
	case `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`:
		values = []driver.Value{s.account, s.server, s.plan.Target.Database, time.Now().UTC().Truncate(time.Microsecond)}
	case `SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?`:
		if len(args) != 1 || args[0].Value != s.plan.LocalAdminUsername {
			return nil, errors.New("wrong username")
		}
		values = []driver.Value{int64(7), s.plan.LocalAdminUsername, s.stored, s.role, s.active, s.provider}
	case `SELECT username,password_hash,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`:
		if !c.tx || len(args) != 1 || args[0].Value != int64(7) {
			return nil, errors.New("unbound admin lock")
		}
		values = []driver.Value{s.plan.LocalAdminUsername, s.stored, s.role, s.active, s.provider}
	default:
		return nil, errors.New("unexpected SQL")
	}
	return &authRows{values: values}, nil
}
func (c *authConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.writes++
	return nil, errors.New("enrollment cannot write SQL")
}

func enrollmentFixture(t *testing.T, mode string) (*Installer, *authSQLState, *int, []byte) {
	t.Helper()
	password := []byte("actual-local-password-for-test")
	stored, e := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	clear(private)
	p := Plan{SchemaVersion: PlanVersion, EnrollmentName: "owner-enrollment", EnrollmentID: "enrollment-1", IssuerID: "owner-1", EnrollmentRevision: 1, Target: owner.Target{InstallationID: "installation_test", ServerUUID: "01234567-89ab-cdef-0123-456789abcdef", Database: "owner_fixture", DatabaseAccount: "bootstrap@localhost", ClusterID: "cluster-uid", Namespace: "backup-system", NamespaceUID: "namespace-uid"}, InstallerDatabaseAccount: "installer@localhost", LocalAdminUsername: "actual-admin", OwnerUsername: "original-kube-owner", OwnerUID: "owner-uid", OwnerGroups: []string{"system:authenticated", "system:masters"}, IssuerPublicKeySHA256: hash(pub), DatabaseCASHA256: strings.Repeat("a", 64), DatabaseTLSServerName: "mysql.original.invalid"}
	s := &authSQLState{plan: p, stored: string(stored), active: true, role: "admin", provider: "local", account: p.InstallerDatabaseAccount, server: p.Target.ServerUUID}
	created := new(int)
	var cm *corev1.ConfigMap
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer original-owner-token" {
			w.WriteHeader(403)
			return
		}
		send := func(v any) {
			if e := json.NewEncoder(w).Encode(v); e != nil {
				t.Error(e)
			}
		}
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			username := p.OwnerUsername
			groups := p.OwnerGroups
			if mode == "wrong_subject" {
				username = "other-owner"
			}
			if mode == "wrong_groups" {
				groups = []string{"system:authenticated"}
			}
			send(&authenticationv1.SelfSubjectReview{TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authenticationv1.SelfSubjectReviewStatus{UserInfo: authenticationv1.UserInfo{Username: username, UID: p.OwnerUID, Groups: groups}}})
		case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
			var review authorizationv1.SelfSubjectAccessReview
			if decodeEnrollmentAPIRequest(r, &review, "authorization.k8s.io", "SelfSubjectAccessReview") != nil || review.Spec.ResourceAttributes == nil {
				t.Error("review request")
				w.WriteHeader(400)
				return
			}
			a := review.Spec.ResourceAttributes
			if a.Namespace != p.Target.Namespace || a.Resource != "configmaps" || a.Name != p.EnrollmentName || a.Group != "" || a.Verb != "get" && a.Verb != "create" {
				t.Error("wrong original permission scope")
				w.WriteHeader(400)
				return
			}
			send(&authorizationv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Status: authorizationv1.SubjectAccessReviewStatus{Allowed: mode != "denied", Denied: mode == "denied"}})
		case "/api/v1/namespaces/kube-system", "/api/v1/namespaces/backup-system":
			name, uid := "kube-system", p.Target.ClusterID
			if strings.HasSuffix(r.URL.Path, "backup-system") {
				name, uid = p.Target.Namespace, p.Target.NamespaceUID
			}
			if mode == "wrong_cluster" && name == "kube-system" {
				uid = "other-cluster"
			}
			send(&corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)}})
		case "/api/v1/namespaces/backup-system/configmaps":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			var input corev1.ConfigMap
			if decodeEnrollmentAPIRequest(r, &input, "", "ConfigMap") != nil || input.Name != p.EnrollmentName || input.Immutable == nil || !*input.Immutable || len(input.Data) != 1 {
				t.Error("invalid enrollment create")
				w.WriteHeader(400)
				return
			}
			input.UID = "original-enrollment-uid"
			input.ResourceVersion = "1"
			input.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}
			if mode == "mutable_object" {
				immutable := false
				input.Immutable = &immutable
			}
			cm = &input
			*created++
			if mode == "admin_revoked_after_create" {
				s.active = false
			}
			if mode == "password_changed_after_create" {
				s.stored = "replaced-hash"
			}
			send(cm)
		case "/api/v1/namespaces/backup-system/configmaps/owner-enrollment":
			if cm == nil {
				w.WriteHeader(404)
				send(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: 404})
				return
			}
			send(cm)
		default:
			t.Error("unexpected API request", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	s.ca = ca
	p.KubernetesAPI, p.KubernetesCASHA256 = server.URL, hash(ca)
	s.plan = p
	kube, e := kubernetes.NewForConfig(&rest.Config{Host: server.URL, BearerToken: "original-owner-token", TLSClientConfig: rest.TLSClientConfig{CAData: ca}, Timeout: 5 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	db := sql.OpenDB(authConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	raw, e := canonical(p)
	if e != nil {
		t.Fatal("fixture canonical plan encoding", e)
	}
	var decoded Plan
	decodeErr := decodeExact(raw, &decoded)
	i, e := New(db, kube, raw, hash(raw), pub, hash(pub))
	if e != nil {
		// Public synthetic plan only; never log a password, DSN, key or token.
		t.Fatalf("fixture constructor: %v; strict_decode=%v plan_valid=%v db_nil=%v client_nil=%v key_len=%d fingerprint_match=%v plan=%+v", e, decodeErr, validPlan(decoded), db == nil, nilClient(kube), len(pub), hash(pub) == decoded.IssuerPublicKeySHA256, decoded)
	}
	return i, s, created, password
}

func TestOwnerEnrollAuthenticatedTLSProtocolAndReplay(t *testing.T) {
	i, s, created, password := enrollmentFixture(t, "")
	defer clear(password)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r, e := i.Enroll(ctx, password)
	if e != nil || r.Replayed || r.Pin.ConfigMapUID != "original-enrollment-uid" || !digestPattern.MatchString(r.Pin.DocumentSHA256) || *created != 1 || s.writes != 0 || s.commits != 1 {
		t.Fatal("authenticated original enrollment", e, r, *created, s.writes)
	}
	again, e := i.Enroll(ctx, password)
	if e != nil || !again.Replayed || again.Pin != r.Pin || *created != 1 || s.writes != 0 || s.commits != 2 {
		t.Fatal("same-target enrollment replay", e)
	}
}
func TestOwnerEnrollRejectsUntrustedIdentityAndRevocation(t *testing.T) {
	for _, mode := range []string{"wrong_subject", "wrong_groups", "denied", "wrong_cluster", "mutable_object", "admin_revoked_after_create", "password_changed_after_create", "wrong_password", "wrong_account", "wrong_server", "ldap", "nonadmin"} {
		t.Run(mode, func(t *testing.T) {
			i, s, created, password := enrollmentFixture(t, mode)
			defer clear(password)
			if mode == "wrong_password" {
				password = []byte("wrong-password")
			}
			if mode == "wrong_account" {
				s.account = "other@localhost"
			}
			if mode == "wrong_server" {
				s.server = "other-server"
			}
			if mode == "ldap" {
				s.provider = "ldap"
			}
			if mode == "nonadmin" {
				s.role = "user"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			r, e := i.Enroll(ctx, password)
			if e == nil || r.Pin.ConfigMapUID != "" || s.commits != 0 || s.writes != 0 {
				t.Fatal("untrusted source produced enrollment pin", e, r)
			}
			if (mode == "wrong_password" || mode == "wrong_account" || mode == "wrong_server" || mode == "ldap" || mode == "nonadmin") && *created != 0 {
				t.Fatal("unauthenticated SQL actor reached enrollment write")
			}
		})
	}
}
func TestOwnerEnrollPlanAndCandidateCannotAuthenticate(t *testing.T) {
	i, s, _, password := enrollmentFixture(t, "")
	defer clear(password)
	raw, _ := canonical(i.plan)
	if _, e := New(i.db, i.kube, raw, hash(raw), i.public, strings.Repeat("f", 64)); e == nil {
		t.Fatal("candidate chose its own trusted fingerprint")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("plan")
	}
	fields["UserID"] = json.RawMessage("7")
	modified, _ := canonical(fields)
	if _, e := DecodePlan(modified, hash(modified)); e == nil {
		t.Fatal("caller supplied user ID accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := i.Enroll(ctx, password); e == nil || s.queries != 0 {
		t.Fatal("unbounded/canceled context authorized")
	}
	if _, e := i.Enroll(context.Background(), password); e == nil || s.queries != 0 {
		t.Fatal("unbounded context authorized")
	}
}
