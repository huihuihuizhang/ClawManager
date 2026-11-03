//go:build systembackup_mysql

package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
)

// Actual native target/admin/enrollment and ACTUAL A issuance. Kube responses
// and the local TLS Vault API are controlled protocols, not field permission
// evidence. Only existing public material is fixture-signed in its ORIGINAL
// domain; every new resource Grant/Head is produced by IssueSigningResourceInstall.
// No capture grant/table read or other resource success is fabricated.
func issueSigningResourcesForNativeTarget(t *testing.T, ctx context.Context, f *authorityFixture) ([]owner.SigningResourceTrustPin, [][]byte) {
	t.Helper()
	plan := f.i.plan
	var account, uuid, database string
	var now time.Time
	if f.i.db.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&account, &uuid, &database, &now) != nil || account != plan.InstallerDatabaseAccount || uuid != plan.Target.ServerUUID || database != plan.Target.Database || plan.InstallerDatabaseAccount == plan.Target.DatabaseAccount || now.IsZero() {
		t.Fatal("issuer helper requires the exact independently enrolled native target")
	}
	now = now.UTC().Truncate(time.Microsecond)
	start, end := now.Add(-time.Minute), now.Add(10*time.Minute)
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private native signer issuance directory")
	}
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("native signer source file")
		}
		return path
	}
	oldDocRaw, err := ReadPrivateFile(f.files.ObserverFile, 262144)
	var oldDoc observerDocument
	if err != nil || decodeExact(oldDocRaw, &oldDoc) != nil {
		t.Fatal("controlled original runtime projection")
	}
	jwt, err := ReadPrivateFile(oldDoc.RuntimeJWTFile, 16384)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(jwt)
	trust := oldDoc.Trust
	trustRaw, err := a.VaultJWTAuthConfig(trust)
	if err != nil {
		t.Fatal(err)
	}
	var trustValue any
	if json.Unmarshal(trustRaw, &trustValue) != nil {
		t.Fatal("controlled JWT trust")
	}
	trustCanonical, err := canonical(trustValue)
	if err != nil {
		t.Fatal(err)
	}
	metadataToken := []byte("native-signing-private-metadata-token")
	defer clear(metadataToken)
	metadataFile := write("metadata.token", metadataToken)
	observerPolicy := "native-all-signer-public-metadata"
	bindings := make([]owner.Binding, 0, 3)
	histories := make([]owner.PurposeKeys, 0, 3)
	privateKeys := map[string]ed25519.PrivateKey{}
	roles, policies := map[string][]byte{}, map[string]string{}
	for _, purpose := range []string{"acceptance_record", "capture_certificate", "catalog_record"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privateKeys[purpose] = private
		defer clear(private)
		b := f.record.Binding
		b.InstallationID, b.Namespace, b.NamespaceUID = plan.Target.InstallationID, plan.Target.Namespace, plan.Target.NamespaceUID
		b.Purpose, b.KeyID, b.KeyVersion, b.KeyName, b.ProviderVersion = purpose, "installed-"+purpose, "registry-v1", "installed-"+purpose, "1"
		b.ProviderClusterID, b.TransitMount = "native-signing-vault", "transit"
		b.AuthMount, b.Role, b.Policy = "jwt-"+purpose, "role-"+purpose, "policy-"+purpose
		role, err := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
		if err != nil {
			t.Fatal(err)
		}
		var roleValue any
		if json.Unmarshal(role, &roleValue) != nil {
			t.Fatal("controlled role")
		}
		roleCanonical, err := canonical(roleValue)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := owner.CaptureSigningACL(b)
		if err != nil {
			t.Fatal(err)
		}
		b.RoleSHA256, b.PolicySHA256, b.JWTConfigSHA256 = hash(roleCanonical), hash([]byte(policy)), hash(trustCanonical)
		roles[purpose], policies[purpose] = role, policy
		bindings = append(bindings, b)
		histories = append(histories, owner.PurposeKeys{Purpose: purpose, KeyName: b.KeyName, Keys: []owner.PublicKey{{Version: "1", PublicKey: base64.StdEncoding.EncodeToString(public), ProtectedUntil: end.Add(time.Hour)}}})
	}
	signs := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		send := func(value any) { _ = json.NewEncoder(w).Encode(value) }
		data := func(value any) { send(map[string]any{"data": value}) }
		if r.URL.Path == "/v1/sys/health" {
			send(map[string]any{"cluster_id": "native-signing-vault", "initialized": true, "sealed": false})
			return
		}
		if r.Method == "GET" && r.Header.Get("X-Vault-Token") != string(metadataToken) {
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			data(map[string]any{"policies": []string{observerPolicy}, "identity_policies": []string{}, "ttl": 120})
			return
		}
		if r.URL.Path == "/v1/sys/policies/acl/"+observerPolicy {
			policy, err := owner.SigningResourceObserverACL(owner.SigningResourceGrant{Target: plan.Target, Bindings: bindings, Histories: histories}, observerPolicy)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			data(map[string]any{"name": observerPolicy, "policy": policy})
			return
		}
		for n, b := range bindings {
			switch r.URL.Path {
			case "/v1/sys/policies/acl/" + b.Policy:
				data(map[string]any{"name": b.Policy, "policy": policies[b.Purpose]})
				return
			case "/v1/auth/" + b.AuthMount + "/role/" + b.Role:
				data(json.RawMessage(roles[b.Purpose]))
				return
			case "/v1/auth/" + b.AuthMount + "/config":
				data(json.RawMessage(trustRaw))
				return
			case "/v1/" + b.TransitMount + "/keys/" + b.KeyName:
				data(map[string]any{"type": "ed25519", "supports_signing": true, "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "keys": map[string]any{"1": map[string]any{"public_key": histories[n].Keys[0].PublicKey}}})
				return
			case "/v1/auth/" + b.AuthMount + "/login":
				var input map[string]string
				if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&input) != nil || input["role"] != b.Role || input["jwt"] != string(jwt) {
					w.WriteHeader(403)
					return
				}
				send(map[string]any{"auth": map[string]any{"client_token": "native-signer-runtime-" + b.Purpose, "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{b.Policy}, "token_policies": []string{b.Policy}, "identity_policies": []string{}, "metadata": map[string]string{"role": b.Role, "namespace": b.Namespace, "pod_uid": b.PodUID, "service_account_uid": b.ServiceAccountUID}}})
				return
			case "/v1/" + b.TransitMount + "/sign/" + b.KeyName:
				if r.Method != "POST" || r.Header.Get("X-Vault-Token") != "native-signer-runtime-"+b.Purpose || b.Purpose == "capture_certificate" {
					w.WriteHeader(403)
					return
				}
				var input struct {
					Input      string `json:"input"`
					KeyVersion int    `json:"key_version"`
				}
				if json.NewDecoder(r.Body).Decode(&input) != nil || input.KeyVersion != 1 {
					w.WriteHeader(400)
					return
				}
				message, err := base64.StdEncoding.Strict().DecodeString(input.Input)
				if err != nil || !bytes.HasPrefix(message, []byte(owner.SigningResourceProbeDomain)) {
					w.WriteHeader(400)
					return
				}
				signs++
				sig := ed25519.Sign(privateKeys[b.Purpose], message)
				data(map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)})
				return
			}
		}
		w.WriteHeader(404)
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := write("vault.ca", ca)
	for n := range bindings {
		bindings[n].Endpoint, bindings[n].CASHA256 = server.URL, hash(ca)
	}
	var configFields map[string]any
	if json.Unmarshal(f.config.CanonicalJSON(), &configFields) != nil {
		t.Fatal("original disabled config")
	}
	refs := map[string]sec.BootstrapSecretRef{}
	for _, b := range bindings {
		purpose := owner.SigningResourceBootstrapPurpose(b.Purpose)
		var id string
		if b.Purpose == "capture_certificate" {
			purpose = "capture_signing"
			id, err = owner.ReferenceIdentity(b)
		} else {
			id, err = owner.SigningResourceReferenceIdentity(b)
		}
		if err != nil {
			t.Fatal(err)
		}
		refs[purpose] = sec.BootstrapSecretRef{Purpose: purpose, IdentityHash: id, Version: b.KeyVersion}
	}
	for _, value := range configFields["references"].([]any) {
		ref := value.(map[string]any)
		if selected, ok := refs[ref["purpose"].(string)]; ok {
			ref["identity_hash"], ref["version"] = selected.IdentityHash, selected.Version
		}
	}
	configRaw, err := canonical(configFields)
	if err != nil {
		t.Fatal(err)
	}
	config, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil {
		t.Fatal(err)
	}
	configFile := write("native-signer.config.json", config.CanonicalJSON())
	offline := f.grant
	offline.InstallationID, offline.ServerUUID, offline.Database, offline.Username = plan.Target.InstallationID, uuid, database, plan.LocalAdminUsername
	offline.ConfigSHA256 = config.SHA256()
	offlineJSON, err := json.Marshal(offline)
	if err != nil {
		t.Fatal(err)
	}
	grantFileRaw, err := canonical(sec.BootstrapGrantFile{SchemaVersion: "system-backup-offline-bootstrap-grant.v1", NotBefore: start, ExpiresAt: end, Grant: offline})
	if err != nil {
		t.Fatal(err)
	}
	grantFile := write("native-signer.offline-grant.json", grantFileRaw)
	material := sec.InstallationSigningRecord{InstallationID: plan.Target.InstallationID, Revision: 1, NotBefore: start, Until: end.Add(time.Hour)}
	for n, b := range bindings {
		pub, err := base64.StdEncoding.Strict().DecodeString(histories[n].Keys[0].PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		material.Keys = append(material.Keys, sec.ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, PublicKey: pub, NotBefore: start, NotAfter: end.Add(time.Hour)})
		material.Permissions = append(material.Permissions, sec.InstallationSigningPermission{Binding: sec.TransitSigningBinding{InstallationID: b.InstallationID, Purpose: b.Purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, Endpoint: b.Endpoint, KeyName: b.KeyName, ProviderVersion: b.ProviderVersion}, AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, CASHA256: b.CASHA256})
	}
	materialRaw, err := canonical(material)
	if err != nil {
		t.Fatal(err)
	}
	materialSource := owner.SigningResourceMaterial{Files: owner.RecordFiles{RecordFile: write("existing-signing-public.json", materialRaw), SignatureFile: write("existing-signing-public.signature", ed25519.Sign(f.key, append([]byte(sec.InstallationSigningDomain), materialRaw...)))}, Pin: sec.InstallationSigningPin{InstallationID: plan.Target.InstallationID, Revision: 1, RecordSHA256: hash(materialRaw), Issuer: f.i.public}}
	var pins []owner.SigningResourceTrustPin
	var bundles [][]byte
	for _, purpose := range owner.SigningResourcePurposes() {
		var binding owner.Binding
		for _, b := range bindings {
			if b.Purpose == purpose {
				binding = b
			}
		}
		actor := owner.Actor{UserID: offline.UserID, Username: plan.LocalAdminUsername, OwnerSubject: plan.OwnerUsername}
		g := owner.SigningResourceGrant{SchemaVersion: owner.SigningResourceGrantVersion, AuthorityID: "native-original-signers", GrantID: "native-" + purpose, PlanSHA256: f.i.planHash, EnrollmentID: plan.EnrollmentID, IssuerID: plan.IssuerID, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, EnrollmentRevision: plan.EnrollmentRevision, RecordRevision: 1, PermissionEpoch: 1, Target: plan.Target, Actor: actor, BootstrapGrantSHA256: hash(offlineJSON), ConfigSHA256: config.SHA256(), SigningMaterialSHA256: hash(materialRaw), SigningMaterialRevision: 1, Reference: refs[owner.SigningResourceBootstrapPurpose(purpose)], Binding: binding, Bindings: bindings, Histories: histories, NotBefore: start, Until: end}
		raw, err := owner.EncodeSigningResourceGrant(g)
		if err != nil {
			t.Fatal(err)
		}
		p := owner.SigningResourceTrustPin{Target: plan.Target, Actor: actor, EnrollmentID: plan.EnrollmentID, IssuerID: plan.IssuerID, EnrollmentDocumentSHA256: f.enrollment.DocumentSHA256, OwnerSubject: plan.OwnerUsername, EnrollmentRevision: plan.EnrollmentRevision, Issuer: f.i.public, AuthorityID: g.AuthorityID, Purpose: purpose, GrantID: g.GrantID, GrantSHA256: hash(raw), GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1}
		intent, err := canonical(SigningResourceInstallIntent{Version: SigningResourceInstallIntentVersion, Pin: p, Grant: g, Material: materialSource})
		if err != nil {
			t.Fatal(err)
		}
		intentFile := write(purpose+".intent.json", intent)
		observerRaw, err := canonical(observerDocument{Endpoint: server.URL, CASHA256: hash(ca), CAFile: caFile, ObserverPolicy: observerPolicy, ObserverTokenFile: metadataFile, ObserverTokenSHA256: hash(metadataToken), RuntimeJWTFile: write(purpose+".runtime.jwt", jwt), Trust: trust})
		if err != nil {
			t.Fatal(err)
		}
		files := RequestFiles{ConfigFile: configFile, ConfigFileSHA256: hash(config.CanonicalJSON()), GrantFile: grantFile, GrantFileSHA256: hash(grantFileRaw), ObserverFile: write(purpose+".observer.json", observerRaw), ObserverFileSHA256: hash(observerRaw)}
		issued, err := f.i.IssueSigningResourceInstall(ctx, f.password, f.enrollment, intentFile, hash(intent), files, f.key)
		if err != nil {
			t.Fatal("actual native-target original signer issuance", purpose, err)
		}
		if _, err := DecodeSigningResourceBundle(issued, hash(issued), p); err != nil {
			t.Fatal(err)
		}
		pins, bundles = append(pins, p), append(bundles, bytes.Clone(issued))
	}
	if signs != 2 {
		t.Fatal("both actual distinct non-business signer probes required", signs)
	}
	t.Log("A IssueSigningResourceInstall ran twice against actual enrolled native SQL target; local Vault TLS/Kube protocol controlled; provider probe server now closes")
	return pins, bundles
}
