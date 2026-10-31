package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type artifactSigningOwnerFunc func(context.Context, ArtifactSigningAuthorizationRequest) (AuthorizedArtifactSigningUse, error)

func (f artifactSigningOwnerFunc) AuthorizeArtifactSigning(c context.Context, r ArtifactSigningAuthorizationRequest) (AuthorizedArtifactSigningUse, error) {
	return f(c, r)
}

type installationSigningFixture struct {
	t                         *testing.T
	reader                    FileSigningRecordReader
	pin                       InstallationSigningPin
	issuer                    ed25519.PrivateKey
	record                    InstallationSigningRecord
	mounts                    []SigningJWTMount
	task                      ArtifactSigningTask
	owners                    ArtifactSigningAuthorities
	login, signed, authorized int
	mutateOwner               func(*AuthorizedArtifactSigningUse)
	afterSign                 func()
	revoked                   bool
}

func newInstallationSigningFixture(t *testing.T) *installationSigningFixture {
	t.Helper()
	f := &installationSigningFixture{t: t, task: ArtifactSigningTask{BackupPublicID: "sbk_local_signed_material", AttemptNo: 2, OperationID: "original-public-v2-op", Workload: SigningWorkloadIdentity{"isolated-backup", "pod-uid", "sa-uid"}}}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.issuer = private
	f.pin = InstallationSigningPin{InstallationID: "installation_local_only", Revision: 9, Issuer: pub}
	f.record = InstallationSigningRecord{InstallationID: f.pin.InstallationID, Revision: 9, NotBefore: time.Now().Add(-time.Hour), Until: time.Now().Add(time.Hour)}
	f.reader = FileSigningRecordReader{filepath.Join(t.TempDir(), "original-record.json"), filepath.Join(t.TempDir(), "original-record.sig")}
	privateKeys := map[string]ed25519.PrivateKey{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Error("unexpected method")
			w.WriteHeader(405)
			return
		}
		if r.URL.Path == "/v1/auth/original-signing/login" {
			f.login++
			var in struct{ Role, JWT string }
			if json.NewDecoder(r.Body).Decode(&in) != nil {
				t.Error("bad login")
				w.WriteHeader(400)
				return
			}
			purpose := strings.TrimSuffix(in.Role, "-role")
			if _, ok := privateKeys[purpose]; !ok || in.JWT != "projected-jwt-for-"+purpose {
				t.Error("wrong purpose JWT")
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "opaque-token-for-" + purpose, "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{purpose + "-policy"}, "metadata": map[string]string{"role": in.Role, "namespace": f.task.Workload.Namespace, "pod_uid": f.task.Workload.PodUID, "service_account_uid": f.task.Workload.ServiceAccountUID}}})
			return
		}
		purpose := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
		key, ok := privateKeys[purpose]
		if !ok || r.Header.Get("X-Vault-Token") != "opaque-token-for-"+purpose {
			t.Error("wrong purpose token or key")
			w.WriteHeader(403)
			return
		}
		var in struct {
			Input   string `json:"input"`
			Version string `json:"key_version"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Version != "7" {
			t.Error("wrong provider version")
			w.WriteHeader(403)
			return
		}
		input, e := base64.StdEncoding.Strict().DecodeString(in.Input)
		if e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		f.signed++
		if f.afterSign != nil {
			f.afterSign()
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signature": "vault:v7:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, input))}})
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	h := sha256.Sum256(ca)
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		privateKeys[purpose] = key
		b := TransitSigningBinding{InstallationID: f.pin.InstallationID, Purpose: purpose, KeyID: purpose, KeyVersion: "opaque-registry-r19", Endpoint: server.URL, KeyName: purpose, ProviderVersion: "7"}
		f.record.Keys = append(f.record.Keys, ArtifactSigningPublicKey{InstallationID: b.InstallationID, Purpose: purpose, KeyID: b.KeyID, KeyVersion: b.KeyVersion, PublicKey: pub, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
		permission := InstallationSigningPermission{Binding: b, AuthMount: "original-signing", Role: purpose + "-role", Policy: purpose + "-policy", CASHA256: hex.EncodeToString(h[:])}
		f.record.Permissions = append(f.record.Permissions, permission)
		jwtFile := filepath.Join(t.TempDir(), purpose+".jwt")
		if e := os.WriteFile(jwtFile, []byte("projected-jwt-for-"+purpose), 0600); e != nil {
			t.Fatal(e)
		}
		f.mounts = append(f.mounts, SigningJWTMount{Binding: b, AuthMount: permission.AuthMount, Role: permission.Role, Policy: permission.Policy, JWTFile: jwtFile, CAPEM: ca, CASHA256: permission.CASHA256})
	}
	owner := func(purpose string) ArtifactSigningAuthority {
		return artifactSigningOwnerFunc(func(_ context.Context, r ArtifactSigningAuthorizationRequest) (AuthorizedArtifactSigningUse, error) {
			f.authorized++
			if r.Task != f.task || r.Signing.Binding.Purpose != purpose {
				return AuthorizedArtifactSigningUse{}, ErrRegistrationUnavailable
			}
			u := AuthorizedArtifactSigningUse{Task: r.Task, Use: OriginalSigningUse{Request: r.Signing, Workload: r.Task.Workload, NotBefore: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Minute), Recheck: func(_ context.Context, got TransitSigningRequest) error {
				if f.revoked || got != r.Signing {
					return ErrRegistrationUnavailable
				}
				return nil
			}}}
			if f.mutateOwner != nil {
				f.mutateOwner(&u)
			}
			return u, nil
		})
	}
	f.owners = ArtifactSigningAuthorities{owner("capture_certificate"), owner("acceptance_record"), owner("catalog_record")}
	f.writeRecord(true)
	return f
}

func (f *installationSigningFixture) writeRecord(updatePin bool) {
	f.t.Helper()
	raw, err := json.Marshal(f.record)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = os.WriteFile(f.reader.RecordFile, raw, 0600); err != nil {
		f.t.Fatal(err)
	}
	if err = os.WriteFile(f.reader.SignatureFile, ed25519.Sign(f.issuer, append([]byte(InstallationSigningDomain), raw...)), 0600); err != nil {
		f.t.Fatal(err)
	}
	if updatePin {
		h := sha256.Sum256(raw)
		f.pin.RecordSHA256 = hex.EncodeToString(h[:])
		f.pin.Revision = f.record.Revision
	}
}

func (f *installationSigningFixture) build() (*InstallationArtifactSigners, error) {
	f.t.Helper()
	s, err := NewInstallationArtifactSigners(context.Background(), f.reader, f.pin, f.mounts, f.task, f.owners)
	if s != nil {
		f.t.Cleanup(s.Close)
	}
	return s, err
}

func TestInstallationArtifactSignersThreePurposeTLS(t *testing.T) {
	f := newInstallationSigningFixture(t)
	s, err := f.build()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range f.mounts {
		signer, e := s.Signer(m.Binding.Purpose)
		if e != nil {
			t.Fatal(e)
		}
		input := []byte("frozen-owner-input-for-" + m.Binding.Purpose)
		sig, e := signer.Sign(context.Background(), input)
		if e != nil {
			t.Fatalf("%s: %v (owner=%d login=%d sign=%d)", m.Binding.Purpose, e, f.authorized, f.login, f.signed)
		}
		h, e := s.History(context.Background())
		if e != nil || !ed25519.Verify(h.PurposeKeys(m.Binding.Purpose)[0].PublicKey, input, sig) {
			t.Fatal("independent public key readback failed", e)
		}
	}
	if f.login != 3 || f.signed != 3 || f.authorized != 3 {
		t.Fatal("did not traverse all three original owners and provider paths", f.login, f.signed, f.authorized)
	}
	if _, err := s.Signer("manifest"); err == nil {
		t.Fatal("unregistered purpose accepted")
	}
}

func TestInstallationArtifactSignersRejectMaterialAndPermissionSubstitution(t *testing.T) {
	for name, mutate := range map[string]func(*installationSigningFixture){
		"missing record": func(f *installationSigningFixture) {
			if err := os.Remove(f.reader.RecordFile); err != nil {
				t.Fatal(err)
			}
		},
		"wrong issuer":           func(f *installationSigningFixture) { pub, _, _ := ed25519.GenerateKey(rand.Reader); f.pin.Issuer = pub },
		"wrong installation":     func(f *installationSigningFixture) { f.pin.InstallationID = "other-installation" },
		"wrong revision":         func(f *installationSigningFixture) { f.pin.Revision++ },
		"wrong role":             func(f *installationSigningFixture) { f.mounts[0].Role = f.mounts[1].Role },
		"wrong provider version": func(f *installationSigningFixture) { f.mounts[0].Binding.ProviderVersion = "8" },
		"wrong registry version": func(f *installationSigningFixture) { f.mounts[0].Binding.KeyVersion = "7" },
		"wrong CA pin":           func(f *installationSigningFixture) { f.mounts[0].CASHA256 = strings.Repeat("a", 64) },
		"wrong purpose":          func(f *installationSigningFixture) { f.mounts[0].Binding.Purpose = "catalog_record" },
		"revoked current key":    func(f *installationSigningFixture) { f.record.Keys[0].Revoked = true; f.writeRecord(true) },
		"expired record": func(f *installationSigningFixture) {
			f.record.Until = time.Now().Add(-time.Minute)
			f.writeRecord(true)
		},
		"future record": func(f *installationSigningFixture) {
			f.record.NotBefore = time.Now().Add(time.Minute)
			f.writeRecord(true)
		},
		"missing owner":      func(f *installationSigningFixture) { f.owners.Acceptance = nil },
		"signed replacement": func(f *installationSigningFixture) { f.record.Revision++; f.writeRecord(false) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newInstallationSigningFixture(t)
			mutate(f)
			if s, e := f.build(); e == nil || s != nil || f.login != 0 || f.signed != 0 || f.authorized != 0 {
				t.Fatal("bad material reached an owner or provider", e)
			}
		})
	}
}

func TestInstallationArtifactSignersRejectCrossTaskAndCurrentRevocation(t *testing.T) {
	for _, name := range []string{"task", "attempt", "operation", "workload", "digest", "revoked-before", "revoked-during", "material-before", "material-during"} {
		t.Run(name, func(t *testing.T) {
			f := newInstallationSigningFixture(t)
			s, err := f.build()
			if err != nil {
				t.Fatal(err)
			}
			signer, _ := s.Signer("capture_certificate")
			switch name {
			case "task":
				f.mutateOwner = func(u *AuthorizedArtifactSigningUse) { u.Task.BackupPublicID = "sbk_other" }
			case "attempt":
				f.mutateOwner = func(u *AuthorizedArtifactSigningUse) { u.Task.AttemptNo++ }
			case "operation":
				f.mutateOwner = func(u *AuthorizedArtifactSigningUse) { u.Task.OperationID = "other" }
			case "workload":
				f.mutateOwner = func(u *AuthorizedArtifactSigningUse) { u.Use.Workload.PodUID = "other" }
			case "digest":
				f.mutateOwner = func(u *AuthorizedArtifactSigningUse) { u.Use.Request.InputSHA256 = strings.Repeat("a", 64) }
			case "revoked-before":
				f.revoked = true
			case "revoked-during":
				f.afterSign = func() { f.revoked = true }
			case "material-before":
				f.record.Keys[0].Revoked = true
				f.writeRecord(false)
			case "material-during":
				f.afterSign = func() { f.record.Keys[0].Revoked = true; f.writeRecord(false) }
			}
			if sig, e := signer.Sign(context.Background(), []byte("original-frozen-input")); e == nil || len(sig) != 0 {
				t.Fatal("invalid original use produced signature")
			}
			if !strings.HasSuffix(name, "during") && (f.login != 0 || f.signed != 0) {
				t.Fatal("invalid authority reached provider")
			}
			if strings.HasPrefix(name, "material") {
				if _, e := s.History(context.Background()); e == nil {
					t.Fatal("changed material exported as authenticated history")
				}
			}
		})
	}
}

func TestInstallationSigningRecordStrictDecodeAndHistoricalKeys(t *testing.T) {
	f := newInstallationSigningFixture(t)
	old, _, _ := ed25519.GenerateKey(rand.Reader)
	f.record.Keys = append(f.record.Keys, ArtifactSigningPublicKey{InstallationID: f.pin.InstallationID, Purpose: "acceptance_record", KeyID: "old-acceptance", KeyVersion: "old-r1", PublicKey: old, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour), Revoked: true})
	f.writeRecord(true)
	s, err := f.build()
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.History(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	keys := h.PurposeKeys("acceptance_record")
	if len(keys) != 2 || !keys[1].Revoked {
		t.Fatal("revoked historical version lost")
	}
	keys[0].PublicKey[0] ^= 0xff
	if keys[0].PublicKey.Equal(h.PurposeKeys("acceptance_record")[0].PublicKey) {
		t.Fatal("history leaked mutable key material")
	}
	raw, _ := os.ReadFile(f.reader.RecordFile)
	for _, invalid := range [][]byte{[]byte(`{"Revision":9,"Revision":9}`), append(raw[:len(raw)-1:len(raw)-1], []byte(`,"unknown":true}`)...)} {
		hash := sha256.Sum256(invalid)
		pin := f.pin
		pin.RecordSHA256 = hex.EncodeToString(hash[:])
		sig := ed25519.Sign(f.issuer, append([]byte(InstallationSigningDomain), invalid...))
		if _, _, e := authenticateInstallationSigning(invalid, sig, pin, time.Now()); e == nil {
			t.Fatal("ambiguous or unknown owner record accepted")
		}
	}
	if _, _, err := (FileSigningRecordReader{RecordFile: "relative", SignatureFile: "relative.sig"}).ReadSigningRecord(context.Background()); err == nil {
		t.Fatal("relative owner record allowed")
	}
}

func TestInstallationSigningHistorySurvivesSigningExpiry(t *testing.T) {
	f := newInstallationSigningFixture(t)
	f.record.Until = time.Now().Add(-time.Minute)
	f.record.NotBefore = f.record.Until.Add(-time.Hour)
	f.record.Keys[0].NotAfter = f.record.Until
	f.writeRecord(true)
	if _, e := f.build(); e == nil {
		t.Fatal("expired permission allowed new signing")
	}
	h, e := LoadInstallationSigningHistory(context.Background(), f.reader, f.pin)
	if e != nil || len(h.PurposeKeys("capture_certificate")) != 1 {
		t.Fatal("expired signing permission destroyed historical verification material", e)
	}
	f.record.Keys[0].Revoked = true
	f.writeRecord(false)
	if _, e := LoadInstallationSigningHistory(context.Background(), f.reader, f.pin); e == nil {
		t.Fatal("stale unrevoked history accepted after revocation")
	}
	f.writeRecord(true)
	h, e = LoadInstallationSigningHistory(context.Background(), f.reader, f.pin)
	if e != nil || !h.PurposeKeys("capture_certificate")[0].Revoked {
		t.Fatal("revocation not preserved in retained public history", e)
	}
	if f.login != 0 || f.signed != 0 {
		t.Fatal("public history contacted the provider")
	}
}
