// Package install is linked only by the offline installation-owner tool. It
// authenticates an explicitly selected operator; it supplies no app admission.
package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	owner "clawreef/internal/systembackupinstallationowner"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"golang.org/x/crypto/bcrypt"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

var ErrInstall = errors.New("installation owner authentication or source operation rejected")
var ErrCommitUnknown = errors.New("installation owner commit unknown; inspect exact original enrollment/head/grant before retry")

const PlanVersion = "system-backup-installation-owner-enrollment-plan.v1"
const EnrollmentVersion = "system-backup-installation-owner-enrollment.v1"
const EnrollmentReceiptVersion = "system-backup-installation-owner-enrollment-receipt.v1"

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// Plan is user-selected trusted installation input, SHA-pinned independently
// of the candidate key or any record being imported. No caller UserID exists.
type Plan struct {
	SchemaVersion, EnrollmentName, EnrollmentID, IssuerID string
	EnrollmentRevision                                    uint64
	Target                                                owner.Target
	InstallerDatabaseAccount, LocalAdminUsername          string
	OwnerUsername, OwnerUID                               string
	OwnerGroups                                           []string
	IssuerPublicKeySHA256                                 string
	KubernetesAPI, KubernetesCASHA256                     string
	DatabaseCASHA256, DatabaseTLSServerName               string
}

type Installer struct {
	db       *sql.DB
	kube     kubernetes.Interface
	plan     Plan
	planHash string
	public   ed25519.PublicKey
}

type authenticatedOperator struct {
	installer *Installer
	ctx       context.Context
	until     time.Time
	userID    int64
	password  string // Stored bcrypt hash, never the operator's password.
	sqlTime   time.Time
}

func hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func canonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, ErrInstall
	}
	raw, e = jsoncanonicalizer.Transform(raw)
	if e != nil {
		return nil, ErrInstall
	}
	return raw, nil
}
func decodeExact(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 262144 || !utf8.Valid(raw) {
		return ErrInstall
	}
	c, e := jsoncanonicalizer.Transform(raw)
	if e != nil || !bytes.Equal(c, raw) {
		return ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	roundtrip, e := canonical(out)
	if e != nil || !bytes.Equal(roundtrip, raw) {
		return ErrInstall
	}
	return nil
}
func text(s string) bool {
	if len(s) == 0 || len(s) > 512 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func nilClient(k kubernetes.Interface) bool {
	if k == nil {
		return true
	}
	v := reflect.ValueOf(k)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}
func validPlan(p Plan) bool {
	if p.SchemaVersion != PlanVersion || !namePattern.MatchString(p.EnrollmentID) || !namePattern.MatchString(p.IssuerID) || p.EnrollmentRevision == 0 || p.EnrollmentRevision > 9007199254740991 || len(validation.IsDNS1123Subdomain(p.EnrollmentName)) != 0 || len(validation.IsDNS1123Label(p.Target.Namespace)) != 0 || !regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(p.Target.InstallationID) || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(p.Target.ServerUUID) || !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(p.Target.Database) || !text(p.Target.DatabaseAccount) || !text(p.InstallerDatabaseAccount) || !text(p.Target.ClusterID) || !text(p.Target.NamespaceUID) || !text(p.OwnerUsername) || !text(p.LocalAdminUsername) || !digestPattern.MatchString(p.IssuerPublicKeySHA256) || len(p.OwnerGroups) == 0 || len(p.OwnerGroups) > 64 || len(p.OwnerUID) > 512 {
		return false
	}
	authenticated := false
	for i, group := range p.OwnerGroups {
		if !text(group) || group == "system:unauthenticated" || i > 0 && p.OwnerGroups[i-1] >= group {
			return false
		}
		authenticated = authenticated || group == "system:authenticated"
	}
	return authenticated && p.OwnerUsername != "system:anonymous" && (p.OwnerUID == "" || text(p.OwnerUID)) && validEndpoint(p.KubernetesAPI) && digestPattern.MatchString(p.KubernetesCASHA256) && digestPattern.MatchString(p.DatabaseCASHA256) && text(p.DatabaseTLSServerName) && !strings.ContainsAny(p.DatabaseTLSServerName, "/\\@ ")
}

// DecodePlan returns comparison data, never an authentication capability.
func DecodePlan(raw []byte, expectedSHA string) (Plan, error) {
	var p Plan
	if !digestPattern.MatchString(expectedSHA) || hash(raw) != expectedSHA || decodeExact(raw, &p) != nil || !validPlan(p) {
		return Plan{}, ErrInstall
	}
	return p, nil
}

// New never authenticates from Plan or a candidate. Every action below must
// still authenticate the real SQL local admin and real Kubernetes subject.
func New(db *sql.DB, kube kubernetes.Interface, raw []byte, planSHA string, public []byte, independentlySelectedPublicSHA string) (*Installer, error) {
	var p Plan
	if db == nil || nilClient(kube) || !digestPattern.MatchString(planSHA) || hash(raw) != planSHA || decodeExact(raw, &p) != nil || !validPlan(p) || len(public) != ed25519.PublicKeySize || hash(public) != independentlySelectedPublicSHA || independentlySelectedPublicSHA != p.IssuerPublicKeySHA256 {
		return nil, ErrInstall
	}
	p.OwnerGroups = append([]string(nil), p.OwnerGroups...)
	return &Installer{db, kube, p, planSHA, bytes.Clone(public)}, nil
}

type sqlRead interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (i *Installer) database(ctx context.Context, q sqlRead, until time.Time) (time.Time, error) {
	var account, server, database string
	var now time.Time
	if q.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&account, &server, &database, &now) != nil || account != i.plan.InstallerDatabaseAccount || server != i.plan.Target.ServerUUID || database != i.plan.Target.Database || now.IsZero() || now.Nanosecond()%1000 != 0 || !now.Before(until) || ctx.Err() != nil {
		return time.Time{}, ErrInstall
	}
	return now, nil
}

func (i *Installer) authenticate(ctx context.Context, password []byte) (*authenticatedOperator, error) {
	if i == nil || i.db == nil || nilClient(i.kube) || ctx == nil || ctx.Err() != nil || len(password) == 0 || len(password) > 1024 {
		return nil, ErrInstall
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	until := time.Now().UTC().Add(2 * time.Minute)
	if deadline.Before(until) {
		until = deadline
	}
	now, e := i.database(ctx, i.db, until)
	if e != nil {
		return nil, e
	}
	var id int64
	var username, stored, role, provider string
	var active bool
	if i.db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?`, i.plan.LocalAdminUsername).Scan(&id, &username, &stored, &role, &active, &provider) != nil || id < 1 || username != i.plan.LocalAdminUsername || role != "admin" || !active || provider != "local" || bcrypt.CompareHashAndPassword([]byte(stored), password) != nil {
		return nil, ErrInstall
	}
	s := &authenticatedOperator{i, ctx, until, id, stored, now}
	if s.kubernetes(ctx, "get") != nil {
		return nil, ErrInstall
	}
	return s, nil
}

func (s *authenticatedOperator) live(ctx context.Context) bool {
	return s != nil && s.installer != nil && ctx != nil && reflect.ValueOf(ctx).Comparable() && ctx == s.ctx && ctx.Err() == nil && time.Now().Before(s.until)
}
func (s *authenticatedOperator) kubernetes(ctx context.Context, verb string) error {
	if !s.live(ctx) || (verb != "get" && verb != "create") {
		return ErrInstall
	}
	i, p := s.installer, s.installer.plan
	review, e := i.kube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if e != nil || review.Status.UserInfo.Username != p.OwnerUsername || review.Status.UserInfo.UID != p.OwnerUID {
		return ErrInstall
	}
	groups := append([]string(nil), review.Status.UserInfo.Groups...)
	sort.Strings(groups)
	if !reflect.DeepEqual(groups, p.OwnerGroups) {
		return ErrInstall
	}
	for _, target := range []struct{ name, uid string }{{"kube-system", p.Target.ClusterID}, {p.Target.Namespace, p.Target.NamespaceUID}} {
		ns, e := i.kube.CoreV1().Namespaces().Get(ctx, target.name, metav1.GetOptions{})
		if e != nil || string(ns.UID) != target.uid || ns.DeletionTimestamp != nil {
			return ErrInstall
		}
	}
	access, e := i.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: p.Target.Namespace, Verb: verb, Group: "", Resource: "configmaps", Name: p.EnrollmentName}}}, metav1.CreateOptions{})
	if e != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return ErrInstall
	}
	return nil
}

// Call before head/grant locks. No network or password hashing is performed
// under SQL locks; the exact authenticated credential must remain current.
func (s *authenticatedOperator) lockAdmin(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	if !s.live(ctx) || tx == nil {
		return time.Time{}, ErrInstall
	}
	i := s.installer
	before, e := i.database(ctx, tx, s.until)
	if e != nil || before.Before(s.sqlTime) {
		return time.Time{}, ErrInstall
	}
	var username, stored, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, `SELECT username,password_hash,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, s.userID).Scan(&username, &stored, &role, &active, &provider) != nil || username != i.plan.LocalAdminUsername || stored != s.password || role != "admin" || !active || provider != "local" {
		return time.Time{}, ErrInstall
	}
	after, e := i.database(ctx, tx, s.until)
	if e != nil || after.Before(before) {
		return time.Time{}, ErrInstall
	}
	return after, nil
}
