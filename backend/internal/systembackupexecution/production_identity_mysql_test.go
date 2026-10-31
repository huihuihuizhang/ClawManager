package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

// Actual original claim, signed worker issuer and encrypted SQL identity
// journal. Kubernetes create/unknown response is a named local API fixture.
// It does not claim full six-part source admission or TokenReview execution.
func TestProductionFactoryDistinctIdentitySecretsOriginalSQLJournalAndCertificateScope(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	ctx := context.Background()
	now := time.Now()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local original worker issuer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	options := &consumerFixtureOptions{ConfigureGrant: func(g *c.ExecutionGrant) {
		g.Actions = []string{"capture", "issue_worker"}
		g.WorkerIssuerSHA256 = hash(der)
	}}
	owner, service, admin, db, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, options)
	grant := service.Forward.DeploymentBinding()
	user := strings.Split(grant.DatabaseAccount, "@")[0]
	if !strings.HasPrefix(user, "ad_d_read_") || !strings.HasPrefix(grant.Database, "ad_d_consumer_") {
		t.Fatal("not an owned identity fixture")
	}
	if _, err := admin.Exec("GRANT INSERT ON `" + grant.Database + "`.`system_backup_v2_runtime_resources` TO '" + user + "'@'127.0.0.1'"); err != nil {
		t.Fatal("owned original issuer journal role", err)
	}
	owner.TrustDomain = "local.clawmanager"
	owner.Issuer = control.IdentityIssuer{Certificate: issuer, Signer: private, ServerRoots: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), TrustDomain: owner.TrustDomain}
	client := fake.NewSimpleClientset()
	owner.Client = client
	creates := map[string]int{}
	client.PrependReactor("create", "secrets", func(action ktest.Action) (bool, runtime.Object, error) {
		secret := action.(ktest.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
		creates[secret.Name]++
		secret.UID = types.UID(secret.Name + "-uid")
		secret.ResourceVersion = "1"
		if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("secrets"), secret, secret.Namespace); err != nil {
			return true, nil, err
		}
		// The API created the original, but the caller receives an unknown result.
		return true, nil, apierrors.NewTimeoutError("named local unknown create fixture", 0)
	})
	in, source, hold, writers, operations := productionModuleFixture(t)
	actual, _, _, err := owner.input(ctx, a, false)
	if err != nil {
		t.Fatal(err)
	}
	in.Authority = a
	in.ConfigSnapshot = actual.ConfigSnapshot
	in.ProfileID = actual.ProfileID
	in.ProfileRevision = actual.ProfileRevision
	hold = a.DeadlineAt.Add(-time.Second)
	var metadata productionCaptureMetadata
	json.Unmarshal(source.CaptureMetadata, &metadata)
	expected := metadata.ControlEvidence.Expected
	expected.Scope = ce.Scope{Installation: a.InstallationID, Backup: a.TaskPublicID, Attempt: a.AttemptNo}
	expected.ConfigSHA256 = a.ConfigSHA256
	metadata.ControlEvidence = controlContentProposal(t, expected).Prepared.Locator
	source.CaptureMetadata, _ = json.Marshal(metadata)
	catalog, err := productionCaptureModules(in, source, hold, writers, operations, "r1")
	if err != nil {
		t.Fatal(err)
	}
	parts, err := catalog.BuildParts(in, source, hold)
	if err != nil {
		t.Fatal(err)
	}
	var selected []b.JobPart
	for _, part := range parts {
		if part.Part == ce.Part || part.Part == ce.ProofPart {
			selected = append(selected, part)
		}
	}
	if len(selected) != 2 {
		t.Fatal("missing paired original parts")
	}
	for _, part := range selected {
		// Match the fixture's namespace to the actual generated Job; the signed
		// claim remains the original SQL authority used by ensureIdentity.
		owner.Namespace = part.Intent.Namespace
		refresh()
		if err := owner.ensureIdentity(ctx, a, part); err != nil {
			t.Fatal("original identity creation", part.Part, err)
		}
		refresh()
		if err := owner.ensureIdentity(ctx, a, part); err != nil {
			t.Fatal("original identity replay", err)
		}
		name := part.Intent.Name + "-identity"
		if creates[name] != 1 {
			t.Fatal("unknown create/replay retried", creates[name])
		}
		secret, err := client.CoreV1().Secrets(owner.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var uid, digest string
		var record []byte
		if db.QueryRow("SELECT observed_uid,request_sha256,request_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='IdentitySecret' AND resource_name=?", a.TaskPublicID, name).Scan(&uid, &digest, &record) != nil {
			t.Fatal("original encrypted identity journal missing")
		}
		cert, err := originalWorkerIdentityCertificate(secret, uid, digest, record, owner.TrustDomain, a.TaskPublicID, part.InvocationSHA256)
		if err != nil || cert == nil {
			t.Fatal("original invocation identity rejected", err)
		}
		for _, other := range selected {
			if other.Part != part.Part {
				if _, err := originalWorkerIdentityCertificate(secret, uid, digest, record, owner.TrustDomain, a.TaskPublicID, other.InvocationSHA256); err == nil {
					t.Fatal("one part identity authorized the other")
				}
			}
		}
	}
	var count int
	if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='IdentitySecret' AND attempt_no=? AND phase=?", a.TaskPublicID, a.AttemptNo, a.Phase).Scan(&count) != nil || count != 2 {
		t.Fatal("identities merged in original journal", count)
	}
	// Reproduce the old template collision at the real journal entry point.
	bad := selected[1]
	var job batchv1.Job
	json.Unmarshal(bad.Intent.SpecJSON, &job)
	for index := range job.Spec.Template.Spec.Volumes {
		volume := &job.Spec.Template.Spec.Volumes[index]
		if volume.Name == "worker-identity" {
			volume.Secret.SecretName = selected[0].Intent.Name + "-identity"
		}
	}
	bad.Intent.SpecJSON, _ = json.Marshal(job)
	refresh()
	if err := owner.ensureIdentity(ctx, a, bad); err == nil {
		t.Fatal("original identity journal accepted other part invocation")
	}
	for _, part := range selected {
		if creates[part.Intent.Name+"-identity"] != 1 {
			t.Fatal("collision caused another Secret creation")
		}
	}
	otherAttempt := a
	otherAttempt.AttemptNo++
	refresh()
	if err := owner.ensureIdentity(ctx, otherAttempt, selected[0]); err == nil {
		t.Fatal("other attempt reused original identity")
	}
	if creates[selected[0].Intent.Name+"-identity"] != 1 {
		t.Fatal("other attempt created identity")
	}
	// Invocation ConfigMaps and Jobs use the SAME original mapped row adapter.
	// Exercise its native FK, dispatch CAS and observed identity at attempt 3.
	rows, err := owner.rows(a)
	if err != nil {
		t.Fatal(err)
	}
	journal := kube.SQLJournal{DB: db, Rows: rows, Fence: func(ctx context.Context, tx *sql.Tx) error {
		guard, err := owner.Gate.Authority.Bind(ctx, tx, a)
		if err != nil {
			return err
		}
		return guard.Recheck(ctx, tx)
	}}
	var invocation worker.Invocation
	json.Unmarshal(selected[0].InvocationJSON, &invocation)
	cm, err := kube.WorkerConfigMap(kube.Identity{Namespace: owner.Namespace, Name: selected[0].InvocationConfigMap, Owner: a.TaskPublicID}, invocation)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := kube.Intent("ConfigMap", cm)
	if err != nil {
		t.Fatal(err)
	}
	refresh()
	record, err := journal.Prepare(ctx, intent)
	if err != nil {
		t.Fatal("original Invocation row insert", err)
	}
	refresh()
	record, err = journal.RecordCreate(ctx, record)
	if err != nil {
		t.Fatal("original dispatch CAS", err)
	}
	refresh()
	record, err = journal.Observe(ctx, record, "original-invocation-uid", "1")
	if err != nil {
		t.Fatal("original observe CAS", err)
	}
	refresh()
	again, err := journal.Prepare(ctx, intent)
	if err != nil || again.UID != record.UID || !again.CreateDispatched {
		t.Fatal("original Invocation replay", err)
	}
	foreignRows, err := owner.rows(otherAttempt)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := foreignRows.Load(ctx, tx, intent); err != sql.ErrNoRows {
		t.Fatal("other attempt read original Invocation row", err)
	}
}
