package systembackupminioauthority

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// These are signature/SQL transport MODEL checks, not an actual stop,
// archive, restoration, MySQL deployment or issuance-source qualification.
func recoveryProjectionFixture(t *testing.T) (*sqlRecordFixture, MinIORecoveryDescriptor, MinIORecoveryProjection, *SQLCurrentSnapshot, time.Time) {
	t.Helper()
	f := newSeptemberRecordFixture(t)
	ctx, tx := openSQLSourceModel(t, &sqlSourceModel{f: f})
	current, e := ReadSQLCurrent(ctx, tx, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	expected, now, e := current.Comparison()
	if e != nil {
		t.Fatal(e)
	}
	h := digest([]byte("comparison-only-synthetic-resource"))
	p := f.grant.Provider
	resources := MinIORecoveryResources{Version: "original-minio-resource-comparison.v1", NamespaceUID: f.pin.Target.NamespaceUID, Deployment: p.Deployment, ReplicaSet: p.ReplicaSet, Service: p.Service, ServiceAccount: p.ServiceAccount, Node: p.Node, NodeUID: p.NodeUID, DeploymentSpecSHA256: h, ReplicaSetSpecSHA256: h, ServiceSpecSHA256: h, ServiceAccountSHA256: h, PodSpecSHA256: h, NodeSpecSHA256: h, Materials: []MinIORecoveryMaterial{{"Secret", "original-secret", "secret-uid", "17", h}}, Storage: []MinIORecoveryStorage{}}
	directory := t.TempDir()
	d := MinIORecoveryDescriptor{Version: MinIORecoveryDescriptorVersion, ProjectionFile: filepath.Join(directory, "projection.json"), Pin: f.pin, Actor: f.grant.Actor, DefinitionSHA256: f.grant.Observation.DefinitionSHA256, PermissionSourceFile: filepath.Join(directory, "original-permission.json"), PermissionSourceSHA256: h, PermissionProfile: f.grant.PermissionSource.Profile}
	r := MinIORecoveryProjection{Version: MinIORecoveryProjectionVersion, Target: f.grant.Target, Enrollment: f.grant.Enrollment, AuthorityID: f.grant.AuthorityID, GrantID: f.grant.GrantID, DefinitionSHA256: d.DefinitionSHA256, PermissionSourceSHA256: d.PermissionSourceSHA256, PermissionGrantSHA256: f.grant.PermissionSource.GrantSHA256, OriginalSQL: expected, OriginalProvider: p, NotBefore: f.grant.NotBefore, Until: f.grant.Until, SignedAt: now, Transition: MinIORecoveryTransition{OperationID: "operation-real-source-required", ReservationID: "reservation-real-source-required", InventorySHA256: h, NativeRequestSHA256: h, NativeResponseSHA256: h, OriginalNativeSHA256: h, ColdTreeSHA256: h, ArchiveReadbackSHA256: h, FormatSHA256: h, OriginalContainerID: "containerd://old", NewPod: ObjectIdentity{"minio-restored-pod", "restored-pod-uid"}, NewContainerID: "containerd://new", OriginalResources: resources, RecoveredAt: now.Add(-time.Second), OriginalProofUntil: now.Add(5 * time.Second)}}
	return f, d, r, current, now
}
func recoveryProjectionWire(t *testing.T, key ed25519.PrivateKey, r MinIORecoveryProjection) []byte {
	t.Helper()
	raw, e := canonical(r)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := canonical(SignedMinIORecoveryProjection{Record: raw, Signature: ed25519.Sign(key, append([]byte(MinIORecoveryProjectionDomain), raw...))})
	if e != nil {
		t.Fatal(e)
	}
	return wire
}
func TestMinIORecoveryProjectionOriginalSQLAndHistoricalExplanation(t *testing.T) {
	f, d, r, current, now := recoveryProjectionFixture(t)
	wire := recoveryProjectionWire(t, f.key, r)
	encoded, e := EncodeMinIORecoveryDescriptor(d)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeMinIORecoveryDescriptor(encoded); e != nil {
		t.Fatal(e)
	}
	proof, e := VerifyMinIORecoveryProjection(wire, d, current, now)
	if e != nil {
		t.Fatal(e)
	}
	// The original 5s stopped/recovered witness is historical at use time.
	// Fresh native/SQL guards are still mandatory; no window is reissued.
	if _, e = VerifyMinIORecoveryProjection(wire, d, current, now.Add(10*time.Second)); e != nil {
		t.Fatal("historical explanation incorrectly minted as fresh proof", e)
	}
	if _, e = VerifyMinIORecoveryProjection(wire, d, current, r.Until); e == nil {
		t.Fatal("original SQL expiry accepted")
	}
	if e = proof.CompareCurrentResources(r.Transition.OriginalResources); e != nil {
		t.Fatal(e)
	}
	copyRecord, e := proof.Record()
	if e != nil {
		t.Fatal(e)
	}
	copyRecord.Transition.OriginalResources.Materials[0].UID = "foreign"
	if proof.CompareCurrentResources(copyRecord.Transition.OriginalResources) == nil {
		t.Fatal("native secret UID drift accepted")
	}
	original, e := proof.Record()
	if e != nil || original.Transition.OriginalResources.Materials[0].UID != "secret-uid" {
		t.Fatal("record accessor leaked mutable authority")
	}
	copied := *proof
	if copied.Matches(wire) {
		t.Fatal("copied opaque projection accepted")
	}
	if _, e = json.Marshal(proof); e == nil {
		t.Fatal("opaque proof serialized")
	}
}
func TestMinIORecoveryProjectionRejectsResignedScopeAndWindowChanges(t *testing.T) {
	cases := []struct {
		name   string
		change func(*MinIORecoveryProjection)
	}{
		{"wrong-installation", func(r *MinIORecoveryProjection) { r.Target.InstallationID = "foreign" }},
		{"wrong-enrollment", func(r *MinIORecoveryProjection) { r.Enrollment.ID = "foreign" }},
		{"wrong-authority", func(r *MinIORecoveryProjection) { r.AuthorityID = "foreign" }},
		{"wrong-definition", func(r *MinIORecoveryProjection) { r.DefinitionSHA256 = digest([]byte("other")) }},
		{"wrong-source", func(r *MinIORecoveryProjection) { r.PermissionSourceSHA256 = digest([]byte("other")) }},
		{"wrong-original-permission", func(r *MinIORecoveryProjection) { r.PermissionGrantSHA256 = digest([]byte("other")) }},
		{"rewritten-old-provider", func(r *MinIORecoveryProjection) { r.OriginalProvider.Pod.UID = "successor" }},
		{"wrong-sql-reference-version", func(r *MinIORecoveryProjection) { r.OriginalSQL.ReferenceRows[0].RowVersion++ }},
		{"same-old-pod", func(r *MinIORecoveryProjection) { r.Transition.NewPod = r.OriginalProvider.Pod }},
		{"missing-history", func(r *MinIORecoveryProjection) { r.Transition.ColdTreeSHA256 = "" }},
		{"extended-original-until", func(r *MinIORecoveryProjection) { r.Until = r.Until.Add(time.Second) }},
		{"future-signing", func(r *MinIORecoveryProjection) { r.SignedAt = r.SignedAt.Add(time.Second) }},
		{"expired-at-issuance", func(r *MinIORecoveryProjection) { r.Transition.OriginalProofUntil = r.SignedAt }},
		{"missing-native-baseline", func(r *MinIORecoveryProjection) { r.Transition.OriginalResources.Materials = nil }},
		{"empty-secret-hash", func(r *MinIORecoveryProjection) { r.Transition.OriginalResources.Materials[0].ContentSHA256 = "" }},
		{"duplicate-secret", func(r *MinIORecoveryProjection) {
			m := r.Transition.OriginalResources.Materials[0]
			r.Transition.OriginalResources.Materials = append(r.Transition.OriginalResources.Materials, m)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, d, r, current, now := recoveryProjectionFixture(t)
			tc.change(&r)
			if _, e := VerifyMinIORecoveryProjection(recoveryProjectionWire(t, f.key, r), d, current, now); e == nil {
				t.Fatal("signed but out-of-scope comparison accepted")
			}
		})
	}
}
func TestMinIORecoveryProjectionRejectsForeignPinRevocationAndTamper(t *testing.T) {
	f, d, r, current, now := recoveryProjectionFixture(t)
	wire := recoveryProjectionWire(t, f.key, r)
	wrong := d
	wrong.Actor.LocalAdminUserID++
	if _, e := VerifyMinIORecoveryProjection(wire, wrong, current, now); e == nil {
		t.Fatal("wrong original admin accepted")
	}
	wrong = d
	wrong.Pin.IssuerPublic = make([]byte, ed25519.PublicKeySize)
	if _, e := VerifyMinIORecoveryProjection(wire, wrong, current, now); e == nil {
		t.Fatal("foreign trust key accepted")
	}
	wire[len(wire)/2] ^= 1
	if _, e := VerifyMinIORecoveryProjection(wire, d, current, now); e == nil {
		t.Fatal("tampered bytes accepted")
	}
	wire = recoveryProjectionWire(t, f.key, r)
	f.head.State = StateRevoked
	f.head.HeadRevision = 2
	resignSeptemberFixture(t, f)
	ctx, tx := openSQLSourceModel(t, &sqlSourceModel{f: f})
	revoked, e := ReadSQLCurrent(ctx, tx, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	_, checked, e := revoked.Comparison()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyMinIORecoveryProjection(wire, d, revoked, checked); e == nil {
		t.Fatal("actual current signed revocation accepted")
	}
}
