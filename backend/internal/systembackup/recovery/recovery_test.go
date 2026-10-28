package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
)

// All providers below are test-only in-memory stores. No network/database/K8s.
func ref(id string) Reference { return Reference{id, "v1", strings.Repeat("a", 64)} }

type memoryStore struct {
	data                      map[string][]byte
	objects                   map[string]Object
	creates, pages            int
	loseReply, unknownAbsence bool
	snapshot                  []Object
	onOpen                    func(Object)
	identity                  Reference
}

func newStore() *memoryStore {
	return &memoryStore{data: map[string][]byte{}, objects: map[string]Object{}}
}
func (s *memoryStore) Identity() Reference {
	if s.identity.ID != "" {
		return s.identity
	}
	return ref("isolated-provider")
}
func (s *memoryStore) Location() Locator {
	return Locator{"s3", "fixture", "root/origin/backup-1/1", "other-site"}
}
func (s *memoryStore) put(key string, b []byte) Object {
	o := Object{key, "v" + strconv.Itoa(len(s.data)+1), int64(len(b)), Hash(b)}
	s.data[key] = append([]byte(nil), b...)
	s.objects[key] = o
	return o
}
func (s *memoryStore) Open(_ context.Context, o Object) (io.ReadCloser, error) {
	if s.onOpen != nil {
		s.onOpen(o)
	}
	if actual, ok := s.objects[o.Key]; !ok || actual != o {
		return nil, ErrUnavailable
	}
	return io.NopCloser(bytes.NewReader(s.data[o.Key])), nil
}
func (s *memoryStore) Observe(_ context.Context, key string) (Observation, error) {
	o, ok := s.objects[key]
	if ok {
		return Observation{"present", key, o, ref("stat"), true, 10000}, nil
	}
	if s.unknownAbsence {
		return Observation{State: "unknown", Key: key}, nil
	}
	return Observation{State: "absent", Key: key, Proof: ref("stat"), Strong: true, ValidUntil: 10000}, nil
}
func (s *memoryStore) Create(ctx context.Context, r Request) (Observation, error) {
	s.creates++
	if r.Validate() != nil {
		return Observation{}, ErrContract
	}
	if b, ok := s.data[r.Key]; ok {
		if !bytes.Equal(b, r.Payload) {
			return Observation{}, ErrConflict
		}
	} else {
		s.put(r.Key, r.Payload)
	}
	if s.loseReply {
		s.loseReply = false
		return Observation{}, io.ErrUnexpectedEOF
	}
	return s.Observe(ctx, r.Key)
}
func (s *memoryStore) Begin(_ context.Context, deadline int64) (Snapshot, error) {
	s.snapshot = nil
	for _, o := range s.objects {
		s.snapshot = append(s.snapshot, o)
	}
	sort.Slice(s.snapshot, func(i, j int) bool { return s.snapshot[i].Key < s.snapshot[j].Key })
	hash := emptyRolling()
	for _, o := range s.snapshot {
		hash = roll(hash, o)
	}
	return Snapshot{"snapshot-1", "inventory_manifest", ref("inventory"), int64(len(s.snapshot)), hash, deadline + 100}, nil
}
func (s *memoryStore) Page(_ context.Context, snapshot Snapshot, cursor string, n int64) (Page, error) {
	s.pages++
	p := Page{SnapshotID: snapshot.ID, Number: n, Cursor: cursor}
	offset := 0
	if cursor != "" {
		offset, _ = strconv.Atoi(cursor)
	}
	if offset < len(s.snapshot) {
		p.Objects = []Object{s.snapshot[offset]}
		if offset+1 < len(s.snapshot) {
			p.Next = strconv.Itoa(offset + 1)
		}
	}
	return p, nil
}

type memoryActions struct {
	rows       map[string]Action
	beforeSent func() error
}

func newActions() *memoryActions { return &memoryActions{rows: map[string]Action{}} }
func (j *memoryActions) Prepare(_ context.Context, r Request) (Action, error) {
	if a, ok := j.rows[r.ActionID]; ok {
		if !same(a.Request, r) {
			return a, ErrConflict
		}
		return a, nil
	}
	for _, a := range j.rows {
		if a.State != "present" {
			return Action{}, ErrConflict
		}
	}
	a := Action{r, "prepared"}
	j.rows[r.ActionID] = a
	return a, nil
}
func (j *memoryActions) Sent(_ context.Context, a Action) error {
	if j.beforeSent != nil {
		if e := j.beforeSent(); e != nil {
			return e
		}
	}
	a.State = "request_sent"
	j.rows[a.Request.ActionID] = a
	return nil
}
func (j *memoryActions) Observe(_ context.Context, a Action, state string, _ Observation) error {
	a.State = state
	j.rows[a.Request.ActionID] = a
	return nil
}

type memoryScans struct {
	trust      Trust
	state      ScanState
	records    []ScannedRecord
	pages      []ScanPage
	failFinish bool
}

func (s *memoryScans) Load(context.Context, string) (ScanState, error) { return s.state, nil }
func (s *memoryScans) Start(_ context.Context, _ string, v Snapshot) (ScanState, error) {
	s.state = ScanState{Snapshot: v}
	return s.state, nil
}
func (s *memoryScans) CommitPage(_ context.Context, _ string, old, next ScanState, page ScanPage, records []ScannedRecord) error {
	if !same(old, s.state) {
		return ErrConflict
	}
	s.state = next
	s.records = append(s.records, records...)
	s.pages = append(s.pages, page)
	return nil
}
func (s *memoryScans) Finish(_ context.Context, _ string, v ScanState) error {
	if s.failFinish {
		s.failFinish = false
		return ErrUnavailable
	}
	if e := ValidateInventory(v, s.records, s.trust); e != nil {
		return e
	}
	if e := ValidatePages(v, s.pages, s.records); e != nil {
		return e
	}
	s.state.Complete = true
	return nil
}

type testProofs struct{ fail bool }

func (p *testProofs) PreCommit(context.Context, Manifest, Index) error {
	if p.fail {
		return ErrUnavailable
	}
	return nil
}
func (p *testProofs) Cleanup(context.Context, Identity) (Reference, error) {
	return ref("cleanup"), nil
}
func (p *testProofs) VerifyDeleted(context.Context, Registration, DeletionProof) error {
	if p.fail {
		return ErrUnavailable
	}
	return nil
}

type fixtureAuth struct{ key []byte }

func (a fixtureAuth) Authenticate(ctx context.Context, m Manifest, o Object, r io.Reader) error {
	return staging.Open(ctx, r, io.Discard, a.key, staging.Binding{BackupID: m.Identity.Backup, Attempt: strconv.FormatInt(m.Identity.Attempt, 10), Path: o.Key, CaptureContextHash: m.CaptureHash, EnvelopeID: "test-key"}, MaxDocument)
}

func fixture(t *testing.T) (Publisher, PublishInput, *memoryStore, *memoryStore) {
	t.Helper()
	trust := Trust{}
	signers := []Signer{}
	for index, p := range []Purpose{ManifestPurpose, AcceptancePurpose, CatalogPurpose} {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(index + 1)}, 32))
		id := string(p)
		trust = append(trust, TrustKey{id, "v1", p, key.Public().(ed25519.PublicKey), false})
		signers = append(signers, Signer{id, "v1", key})
	}
	store, catalog := newStore(), newStore()
	now := func() int64 { return 1000 }
	auth := fixtureAuth{make([]byte, 32)}
	p := Publisher{Artifact: Finalizer{store, newActions(), now}, Catalog: Finalizer{catalog, newActions(), now}, Trust: trust, ManifestSigner: signers[0], AcceptanceSigner: signers[1], CatalogSigner: signers[2], Proofs: &testProofs{}, Authenticate: auth, Now: now}
	i := Identity{"origin", "backup-1", 1, "kubernetes", "cluster"}
	m := Manifest{Schema: Version, Identity: i, AppVersion: "v1", GitVersion: "abc", CreatedAt: 900, Purpose: "acceptance", MigrationHash: ref("x").SHA256, SchemaHash: ref("x").SHA256, CaptureHash: ref("x").SHA256, Config: ref("config"), SecretPolicy: ref("secrets"), SchemaCoverage: ref("coverage"), Target: Target{"dr-ready-external", []string{}, ref("attestation")}, KEKRecoverable: true, Consistency: "strong", CommitMarker: "_COMMITTED", Parts: map[string]PartSummary{}, Domains: map[string]Summary{}, ControlPlane: Summary{1, "passed", ref("control")}, Warnings: []Warning{}}
	index := Index{Schema: Version, Identity: i}
	for _, name := range append(RequiredParts(), "restore-metadata/envelope.json", "control/evidence.json.enc") {
		key := name + "/0001.enc"
		if strings.Contains(name, "/") {
			key = name
		}
		var ciphertext bytes.Buffer
		binding := staging.Binding{BackupID: i.Backup, Attempt: "1", Path: key, CaptureContextHash: m.CaptureHash, EnvelopeID: "test-key"}
		if e := staging.Seal(context.Background(), &ciphertext, auth.key, binding, func(w io.Writer) error { _, e := io.WriteString(w, "isolated synthetic content for "+name); return e }); e != nil {
			t.Fatal(e)
		}
		o := store.put(key, ciphertext.Bytes())
		index.Objects = append(index.Objects, o)
		if !strings.Contains(name, "/") {
			m.Parts[name] = PartSummary{"completed", []string{key}, ref(name), "strong"}
		}
	}
	sort.Slice(index.Objects, func(i, j int) bool { return index.Objects[i].Key < index.Objects[j].Key })
	for _, name := range SixDomains() {
		m.Domains[name] = Summary{1, "passed", ref(name)}
	}
	input := PublishInput{m, index, Locator{"s3", "fixture", "root/origin/backup-1/1", "other-site"}, Bootstrap{ref("read"), ref("ca"), ref("kek"), ref("bootstrap")}, 1000, 2000}
	return p, input, store, catalog
}
func importer(p Publisher, art, cat *memoryStore) Importer {
	return Importer{Catalog{cat, p.Trust, p.Now}, func(context.Context, Locator, Bootstrap) (Reader, Authenticator, error) {
		return art, p.Authenticate, nil
	}}
}

func TestSixDomainPublishIndependentScanImportAndTombstone(t *testing.T) {
	p, in, art, cat := fixture(t)
	ctx := context.Background()
	result, e := p.Publish(ctx, in)
	if e != nil || result.Registration == nil || !result.LocalAcceptance {
		t.Fatal(e)
	}
	reader := importer(p, art, cat)
	got, e := reader.Import(ctx, result.Registration.ID, result.RegistrationObject.SHA256)
	if e != nil || len(got.Manifest.Domains) != 6 {
		t.Fatal(e)
	}
	// A fresh independent scan has no source database or installation input.
	j := &memoryScans{failFinish: true, trust: p.Trust}
	scan := Scanner{cat, p.Trust, j, p.Now}
	if _, e = scan.Step(ctx, "scan-1", 2000); !errors.Is(e, ErrUnavailable) {
		t.Fatal("finish failure not retained", e)
	}
	pages := cat.pages
	if done, e := scan.Step(ctx, "scan-1", 2000); e != nil || !done || cat.pages != pages {
		t.Fatal("EOF checkpoint fetched a page twice", e)
	}
	proof := DeletionProof{result.Registration.ID, result.RegistrationObject.SHA256, "prune-1", ref("candidate").SHA256, "admin", 1100, ref("deleted-evidence")}
	r, e := Tombstone(ctx, *result.Registration, result.RegistrationObject.SHA256, proof, &testProofs{}, p.CatalogSigner, p.Trust, "tombstone-1", 2000)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Catalog.Execute(ctx, r); e != nil {
		t.Fatal(e)
	}
	if _, e = reader.Import(ctx, result.Registration.ID, result.RegistrationObject.SHA256); !errors.Is(e, ErrTombstoned) {
		t.Fatal("deleted artifact imported", e)
	}
	j = &memoryScans{trust: p.Trust}
	scan = Scanner{cat, p.Trust, j, p.Now}
	for n := 0; n < 3; n++ {
		done, e := scan.Step(ctx, "scan-2", 2000)
		if e != nil {
			t.Fatal(e)
		}
		if done {
			break
		}
	}
	if !j.state.Complete || j.state.Count != 2 {
		t.Fatal("registration and tombstone not inventoried")
	}
}
func TestFinalizationLostReplyIsObservedNeverResent(t *testing.T) {
	s := newStore()
	s.loseReply = true
	j := newActions()
	f := Finalizer{s, j, func() int64 { return 1000 }}
	r := requestFor("action", "manifest.json", []byte(`{"fixture":true}`), 2000)
	if e := f.Execute(context.Background(), r); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if e := f.Execute(context.Background(), r); e != nil || s.creates != 1 {
		t.Fatal("resent uncertain finalization", e)
	}
	r.Payload = []byte(`{"fixture":false}`)
	r.SHA256 = Hash(r.Payload)
	r.Size = int64(len(r.Payload))
	if e := f.Execute(context.Background(), r); !errors.Is(e, ErrConflict) {
		t.Fatal("replaced frozen bytes", e)
	}
}
func TestUnknownAbsenceAndTombstoneAppearingDuringImportFail(t *testing.T) {
	p, in, art, cat := fixture(t)
	result, e := p.Publish(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	reader := importer(p, art, cat)
	cat.unknownAbsence = true
	if _, e = reader.Import(context.Background(), result.Registration.ID, result.RegistrationObject.SHA256); !errors.Is(e, ErrUnavailable) {
		t.Fatal("ordinary absence accepted", e)
	}
	cat.unknownAbsence = false
	proof := DeletionProof{result.Registration.ID, result.RegistrationObject.SHA256, "prune", ref("candidate").SHA256, "admin", 1100, ref("deletion")}
	r, e := Tombstone(context.Background(), *result.Registration, result.RegistrationObject.SHA256, proof, &testProofs{}, p.CatalogSigner, p.Trust, "delete", 2000)
	if e != nil {
		t.Fatal(e)
	}
	art.onOpen = func(o Object) {
		if o.Key == "workspace/0001.enc" {
			cat.put(r.Key, r.Payload)
		}
	}
	if _, e = reader.Import(context.Background(), result.Registration.ID, result.RegistrationObject.SHA256); !errors.Is(e, ErrTombstoned) {
		t.Fatal("missing final tombstone check", e)
	}
}
func TestMissingPartsDomainsAndProofNeverPublish(t *testing.T) {
	for _, failure := range []string{"part", "domain", "failed-verifier", "proof", "corrupt-data"} {
		t.Run(failure, func(t *testing.T) {
			p, in, art, cat := fixture(t)
			switch failure {
			case "part":
				delete(in.Manifest.Parts, "redis")
			case "domain":
				delete(in.Manifest.Domains, "resources")
			case "failed-verifier":
				s := in.Manifest.Domains["teams"]
				s.Status = "failed"
				in.Manifest.Domains["teams"] = s
			case "proof":
				p.Proofs = &testProofs{true}
			case "corrupt-data":
				art.data["workspace/0001.enc"][10] ^= 1
			}
			if _, e := p.Publish(context.Background(), in); e == nil || art.creates != 0 || cat.creates != 0 {
				t.Fatal("incomplete capture published", e)
			}
		})
	}
}
func TestFunctionalAndNonEligibleCannotRegister(t *testing.T) {
	for _, mode := range []string{"functional", "bounded"} {
		t.Run(mode, func(t *testing.T) {
			p, in, art, cat := fixture(t)
			if mode == "functional" {
				in.Manifest.Purpose = "functional_test"
				p.AcceptanceSigner = Signer{}
				p.CatalogSigner = Signer{}
			} else {
				in.Manifest.Consistency = "bounded"
			}
			result, e := p.Publish(context.Background(), in)
			if e != nil || result.Registration != nil || cat.creates != 0 {
				t.Fatal(e)
			}
			_, exists := art.data["_ACCEPTANCE"]
			if exists != (mode == "bounded") {
				t.Fatal("acceptance purpose boundary violated")
			}
		})
	}
}
func TestCanonicalRejectsDuplicatesUnsafeNumbersAndInvalidUnicode(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":"\ud800"}`, `{"x":9007199254740992}`, `{"x":1.1}`, `{"x":1e2}`, `[] []`} {
		if _, e := Canonical([]byte(raw)); e == nil {
			t.Fatal("ambiguous input accepted", raw)
		}
	}
	actual, e := Canonical([]byte(`{"\ue000":1,"\ud83d\ude00":2,"a":"<>&\u2028","z":-0}`))
	expected := "{\"a\":\"<>&\u2028\",\"z\":0,\"😀\":2,\"\ue000\":1}"
	if e != nil || string(actual) != expected {
		t.Fatalf("UTF16/escaping canonicalization: %q %v", actual, e)
	}
}
func TestSigningPurposesCannotShareKeyMaterial(t *testing.T) {
	p, _, _, _ := fixture(t)
	p.Trust[1].Public = p.Trust[0].Public
	if _, e := Seal(map[string]bool{"fixture": true}, ManifestPurpose, p.ManifestSigner.ID, p.ManifestSigner.Version, p.ManifestSigner.Private, p.Trust); e == nil {
		t.Fatal("purpose key material reused")
	}
}
