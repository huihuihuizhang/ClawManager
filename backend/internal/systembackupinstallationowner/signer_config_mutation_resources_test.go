package systembackupinstallationowner

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

func TestSignerMutationFirstEnableRequiresExactOriginalFlip(t *testing.T) {
	bootstrap := captureConfigFixture(t, sec.BootstrapSecretRef{Purpose: "capture_signing", IdentityHash: strings.Repeat("c", 64), Version: "original-v1"})
	current, e := sec.DecodeConfigValues(bootstrap.CanonicalJSON())
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(current.CanonicalJSON(), &fields) != nil {
		t.Fatal("config fixture")
	}
	fields["enabled"] = json.RawMessage("true")
	raw, e := canonical(fields)
	if e != nil {
		t.Fatal(e)
	}
	proposed, e := sec.DecodeConfigValues(raw)
	if e != nil {
		t.Fatal(e)
	}
	wanted := []sec.BootstrapSecretRef{}
	for _, ref := range current.References() {
		if ref.Purpose == "capture_signing" || ref.Purpose == "acceptance_signing" || ref.Purpose == "catalog_signing" {
			wanted = append(wanted, ref)
		}
	}
	if !OriginalSignerFirstEnableScope(current, proposed, current.SHA256(), wanted) {
		t.Fatal("exact original false-to-true scope refused")
	}
	if OriginalSignerFirstEnableScope(proposed, proposed, proposed.SHA256(), wanted) || OriginalSignerFirstEnableScope(current, current, current.SHA256(), wanted) || OriginalSignerFirstEnableScope(current, proposed, strings.Repeat("f", 64), wanted) {
		t.Fatal("wrong transition or original config admitted")
	}
	fields["alert_profile"] = json.RawMessage(`"production"`)
	raw, e = canonical(fields)
	if e != nil {
		t.Fatal(e)
	}
	changed, e := sec.DecodeConfigValues(raw)
	if e != nil {
		t.Fatal(e)
	}
	if OriginalSignerFirstEnableScope(current, changed, current.SHA256(), wanted) {
		t.Fatal("additional config change silently admitted")
	}
	changedPins := append([]sec.BootstrapSecretRef(nil), wanted...)
	changedPins[0].Version = "new-v2"
	if OriginalSignerFirstEnableScope(current, proposed, current.SHA256(), changedPins) || OriginalSignerFirstEnableScope(current, proposed, current.SHA256(), []sec.BootstrapSecretRef{wanted[0], wanted[0], wanted[2]}) {
		t.Fatal("rotated or duplicate signer reference admitted")
	}
}

// Association DATA comparison only; no positive native/SQL admission or
// source issuance is inferred from these deliberately assembled declarations.
func TestSignerMutationSourceScopeRejectsForeignOriginalAssociation(t *testing.T) {
	f := ownerRecordFixture(t)
	auth, e := VerifyRecord(f.raw, f.sig, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	resource := originalSigningResourceFixture(t, "acceptance_record")
	grants := [2]SigningResourceGrant{resource.grant, resource.grant}
	resources := &SigningResources{}
	for n := range grants {
		g := &grants[n]
		g.Target = auth.record.Target
		g.Actor = auth.record.Actor
		g.ConfigSHA256 = auth.record.ConfigSHA256
		g.BootstrapGrantSHA256 = auth.record.GrantSHA256
		g.EnrollmentID = auth.record.EnrollmentID
		g.EnrollmentRevision = auth.record.EnrollmentRevision
		g.IssuerID = auth.record.IssuerID
		g.Histories = auth.record.Histories
		g.Bindings = append([]Binding(nil), resource.grant.Bindings...)
		g.Bindings[1] = auth.record.Binding
		resources.inputs[n].Pin.Issuer = append(ed25519.PublicKey(nil), auth.pin.Issuer...)
	}
	if !originalSignerSourceScope(auth, resources, grants) {
		t.Fatal("same original association data refused")
	}
	changed := grants
	changed[1].Target.NamespaceUID = "foreign-namespace"
	if originalSignerSourceScope(auth, resources, changed) {
		t.Fatal("foreign target admitted")
	}
	changed = grants
	changed[1].ConfigSHA256 = strings.Repeat("f", 64)
	if originalSignerSourceScope(auth, resources, changed) {
		t.Fatal("foreign config admitted")
	}
	changed = grants
	changed[0].Actor.UserID++
	if originalSignerSourceScope(auth, resources, changed) {
		t.Fatal("foreign actor admitted")
	}
	changed = grants
	changed[1].Bindings = append([]Binding(nil), grants[1].Bindings...)
	changed[1].Bindings[1].Role = "foreign-role"
	if originalSignerSourceScope(auth, resources, changed) {
		t.Fatal("capture role substitution admitted")
	}
	resources.inputs[1].Pin.Issuer = append(ed25519.PublicKey(nil), auth.pin.Issuer...)
	resources.inputs[1].Pin.Issuer[0] ^= 1
	if originalSignerSourceScope(auth, resources, grants) {
		t.Fatal("foreign independent issuer admitted")
	}
}

func TestSignerMutationSQLClockRetainsAuthoritativeNowAndFailureFloor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	// An uninitialized Tx would panic if the fixed mode queried SQL. The real
	// config path supplies its already-sampled authoritative transaction time.
	q := &signerMutationSQLRead{Tx: new(sql.Tx), fixed: &now}
	actual, e := q.SampleTime(context.Background())
	if e != nil || !actual.Equal(now) {
		t.Fatal("guarded time changed", e)
	}
	older := now.Add(-time.Microsecond)
	q.fixed = &older
	if _, e = q.SampleTime(context.Background()); e == nil {
		t.Fatal("clock regression admitted")
	}
	q.fixed = &now
	if _, e = q.SampleTime(context.Background()); e == nil {
		t.Fatal("failed clock revived")
	}
	if _, e = (&signerMutationSQLRead{fixed: &now}).SampleTime(context.Background()); e == nil {
		t.Fatal("missing transaction admitted")
	}
}
