package install

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func TestOriginalC1UnusedDomainRecoveryAuthenticatesExpiredEpochOne(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opened := time.Date(2026, 11, 20, 2, 43, 43, 0, time.UTC)
	until := opened.Add(time.Minute)
	now := until.Add(time.Second)
	scope := pd.Scope{ServerUUID: "9e0e40fb-d986-11f1-b30a-9e9a498abc54", Database: "fixture", Installation: "installation_fixture"}
	admission := pd.UnconfiguredAdmission{
		Scenario: "unconfigured", DeploymentAdmissionID: "c1-test",
		CandidateHash: pd.Hash(strings.Repeat("a", 64)), RegistrySetHash: pd.Hash(strings.Repeat("b", 64)),
		RefSetHash: pd.Hash(strings.Repeat("c", 64)), PolicyHash: pd.Hash(strings.Repeat("d", 64)),
		ChannelProfileHash: pd.Hash(strings.Repeat("e", 64)),
	}
	plan := Plan{LocalAdminUsername: "fixture-admin", InstallerDatabaseAccount: "fixture-installer@localhost"}
	installer := &Installer{plan: plan, public: public, planHash: strings.Repeat("1", 64)}
	op := &authenticatedOperator{installer: installer, userID: 7}
	enrollment := EnrollmentPin{DocumentSHA256: strings.Repeat("2", 64)}
	source := originalC1DomainSource{
		Version: originalC1DomainSourceVersion, PlanSHA256: installer.planHash, Enrollment: enrollment,
		Scope: scope, ActorID: 7, Username: plan.LocalAdminUsername, InstallerAccount: plan.InstallerDatabaseAccount,
		Admission: admission, NotBefore: opened.Add(-time.Second), Until: until,
	}
	prior := pd.DomainRecord{
		Scope: scope, Epoch: "1", RowVersion: "1", State: "open", IssuerIdentityHash: pd.Hash(hash(public)),
		Admission: pd.Admission{Unconfigured: &admission}, AdmissionExpiresAt: c1stamp(until),
		CreatedAt: c1stamp(opened), UpdatedAt: c1stamp(opened),
	}
	raw, err := canonical(source)
	if err != nil {
		t.Fatal(err)
	}
	record, err := pd.EncodeStoredRecord(&prior)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	save := func(name string, raw []byte) BootstrapSourceFilePin {
		t.Helper()
		p := filepath.Join(directory, name)
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return BootstrapSourceFilePin{File: p, SHA256: hash(raw)}
	}
	input := OriginalC1UnusedDomainRecoveryInputs{
		Source:    save("original.source.json", raw),
		Signature: save("original.source.signature", ed25519.Sign(private, append([]byte(originalC1DomainSourceVersion+"\x00"), raw...))),
		Domain:    save("domain.record.json", record.Columns["record_bytes"].([]byte)),
	}
	if result, err := op.readOriginalC1UnusedDomainRecovery(&input, enrollment, scope, now); err != nil || result == nil {
		t.Fatalf("original expired scope did not qualify: %v", err)
	}
	if _, err := op.readOriginalC1UnusedDomainRecovery(&input, enrollment, scope, opened); err == nil {
		t.Fatal("unexpired domain qualified for recovery")
	}
	for _, change := range []func(*pd.DomainRecord){
		func(d *pd.DomainRecord) { d.Epoch = "2" },
		func(d *pd.DomainRecord) { d.RowVersion = "2" },
		func(d *pd.DomainRecord) { d.Scope.Installation = "installation_other" },
		func(d *pd.DomainRecord) { d.IssuerIdentityHash = pd.Hash(strings.Repeat("9", 64)) },
	} {
		changed := prior
		change(&changed)
		if originalC1UnusedDomainMatches(changed, source, public, "1", now) {
			t.Fatal("unrelated or changed domain matched original signed source")
		}
	}
	bad := input
	bad.Signature = save("untrusted.signature", make([]byte, ed25519.SignatureSize))
	if _, err := op.readOriginalC1UnusedDomainRecovery(&bad, enrollment, scope, now); err == nil {
		t.Fatal("untrusted detached signature authenticated recovery")
	}

	rotated := prior
	rotated.Epoch, rotated.RowVersion = "2", "2"
	rotated.UpdatedAt = c1stamp(until.Add(2 * time.Second))
	later := source
	later.NotBefore = until.Add(time.Second)
	later.Until = later.NotBefore.Add(time.Minute)
	later.Admission.DeploymentAdmissionID = "c1-rotated"
	later.Recovery = &input
	rotated.Admission = pd.Admission{Unconfigured: &later.Admission}
	rotated.AdmissionExpiresAt = c1stamp(later.Until)
	secondRecord, err := pd.EncodeStoredRecord(&rotated)
	if err != nil {
		t.Fatal(err)
	}
	second := saveRotatedC1RecoveryAnchor(t, save, private, later, secondRecord.Columns["record_bytes"].([]byte))
	now = later.Until.Add(time.Second)
	recovery, err := op.readOriginalC1UnusedDomainRecovery(&second, enrollment, scope, now)
	if err != nil || recovery.epoch != "2" || recovery.next != "3" || !recovery.matches(rotated, now) {
		t.Fatalf("expired epoch two did not match the signed lineage: %v", err)
	}
	thirdSource := later
	thirdSource.Recovery = &second
	thirdSource.NotBefore = later.Until.Add(time.Second)
	thirdSource.Until = thirdSource.NotBefore.Add(time.Minute)
	thirdSource.Admission.DeploymentAdmissionID = "c1-third"
	third := rotated
	third.Epoch, third.RowVersion = "3", "3"
	third.UpdatedAt = c1stamp(thirdSource.NotBefore.Add(time.Second))
	third.Admission = pd.Admission{Unconfigured: &thirdSource.Admission}
	third.AdmissionExpiresAt = c1stamp(thirdSource.Until)
	thirdRecord, err := pd.EncodeStoredRecord(&third)
	if err != nil {
		t.Fatal(err)
	}
	thirdAnchor := saveRotatedC1RecoveryAnchor(t, save, private, thirdSource, thirdRecord.Columns["record_bytes"].([]byte))
	final, err := op.readOriginalC1UnusedDomainRecovery(&thirdAnchor, enrollment, scope, thirdSource.Until.Add(time.Second))
	if err != nil || final.epoch != "3" || final.next != "4" || !final.matches(third, thirdSource.Until.Add(time.Second)) {
		t.Fatalf("expired epoch three did not match the signed lineage: %v", err)
	}
	badRoot := input
	badRoot.Domain = save("substituted-epoch-one.bin", secondRecord.Columns["record_bytes"].([]byte))
	later.Recovery = &badRoot
	second = saveRotatedC1RecoveryAnchor(t, save, private, later, secondRecord.Columns["record_bytes"].([]byte))
	recovery, err = op.readOriginalC1UnusedDomainRecovery(&second, enrollment, scope, now)
	if err == nil || recovery != nil {
		t.Fatal("different root SQL bytes qualified through the signed lineage")
	}
}

func saveRotatedC1RecoveryAnchor(t *testing.T, save func(string, []byte) BootstrapSourceFilePin, private ed25519.PrivateKey, source originalC1DomainSource, record []byte) OriginalC1UnusedDomainRecoveryInputs {
	t.Helper()
	raw, err := canonical(source)
	if err != nil {
		t.Fatal(err)
	}
	name := string(source.Admission.DeploymentAdmissionID)
	return OriginalC1UnusedDomainRecoveryInputs{
		Source:    save(name+".source.json", raw),
		Signature: save(name+".source.signature", ed25519.Sign(private, append([]byte(originalC1DomainSourceVersion+"\x00"), raw...))),
		Domain:    save(name+".record.bin", record),
	}
}

func TestOriginalC1UnusedDomainRecoveryAcquireDeadlinePrecision(t *testing.T) {
	signed, err := time.Parse(time.RFC3339Nano, "2026-11-20T05:46:34.295032246Z")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := c1stamp(signed).Time()
	if err != nil {
		t.Fatal(err)
	}
	guard := c1SQLTime(signed)
	if !guard.Equal(lease) || !guard.Before(signed) || guard.Nanosecond()%1000 != 0 {
		t.Fatalf("producer deadline %v does not match the signed lease %v", guard, lease)
	}
}

func TestOriginalC1UnusedDomainRecoveryExpiredAcquire(t *testing.T) {
	now := time.Date(2026, 11, 20, 6, 17, 0, 0, time.UTC)
	end := c1stamp(now.Add(-time.Minute))
	next := &pd.CommandNext{GrantID: "c1-grant-test", RunID: "c1-run-test", AuthorizationExpiresAt: end, OwnerWriteExpiresAt: end}
	q := pd.CommandRequest{ExpectedDomainEpoch: "4", Next: next, LeaseExpiresAt: &end}
	digests := pd.CommandDigests{Request: pd.Hash(strings.Repeat("a", 64)), Key: pd.Hash(strings.Repeat("b", 64))}
	receipt := pd.CommandReceiptRecord{
		Request: q, RequestHash: digests.Request, ReceiptKeyHash: digests.Key,
		Outcome: pd.CommandExpected{GrantID: next.GrantID, GrantGeneration: "1", GrantRowVersion: "1", RunID: next.RunID, TargetGeneration: "1"},
	}
	grant := pd.GrantRecord{GrantID: next.GrantID, DomainEpoch: "4", Generation: "1", RowVersion: "1", State: "active", LeaseExpiresAt: end, AuthorizationExpiresAt: end}
	run := pd.RunRecord{RunID: next.RunID, GrantID: next.GrantID, GrantGeneration: "1", TargetGeneration: "1", State: "acquired", RowVersion: "1", OwnerWriteExpiresAt: end}
	target := pd.TargetRecord{CurrentRunID: next.RunID, Generation: "1", RowVersion: "1", ResultVersion: "0"}
	if !originalC1AcquireIsUnused(q, digests, receipt, grant, run, target, now) {
		t.Fatal("exact expired and unobserved acquire did not qualify")
	}
	if originalC1AcquireIsUnused(q, digests, receipt, grant, run, target, now.Add(-2*time.Minute)) {
		t.Fatal("a live grant qualified")
	}
	changed := run
	changed.ObservedAt = &end
	if originalC1AcquireIsUnused(q, digests, receipt, grant, changed, target, now) {
		t.Fatal("an observed run qualified")
	}
	changed = run
	changed.RowVersion = "2"
	if originalC1AcquireIsUnused(q, digests, receipt, grant, changed, target, now) {
		t.Fatal("an advanced run qualified")
	}
	receipt.RequestHash = ""
	if originalC1AcquireIsUnused(q, digests, receipt, grant, run, target, now) {
		t.Fatal("a different receipt qualified")
	}
}
