package systembackupevidence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recoveryBootstrapAuditStub struct{}

func (recoveryBootstrapAuditStub) AppendRecoveryManagerAudit(context.Context, RecoveryManagerExternalAuditRecord) error {
	return nil
}

type recoveryBootstrapNilAuditStub struct{}

func (*recoveryBootstrapNilAuditStub) AppendRecoveryManagerAudit(context.Context, RecoveryManagerExternalAuditRecord) error {
	return nil
}

func TestRecoveryManagerBootstrapGrantIsPinnedAndBound(t *testing.T) {
	_, _, peerConfig := systemPeerFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	doc := recoveryManagerBootstrapDocument{
		SchemaVersion:         recoveryManagerBootstrapVersion,
		GrantID:               "first-manager-20261010",
		Scope:                 peerConfig.Scope,
		BootstrapIdentityHash: strings.Repeat("a", 64),
		ManagerIdentityHash:   strings.Repeat("b", 64),
		IssuerIdentityHash:    strings.Repeat("c", 64),
		CredentialBindingHash: strings.Repeat("d", 64),
		ReasonHash:            strings.Repeat("e", 64),
		NotBefore:             now.Add(-time.Minute),
		ExpiresAt:             now.Add(time.Hour),
		AuthorizedUntil:       now.Add(30 * time.Minute),
		ReadFence:             true, WriteFence: true, ManageDeployment: true,
	}
	path := filepath.Join(t.TempDir(), "manager-grant.json")
	write := func(raw []byte) string {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	pin := write(raw)
	grant, err := ReadRecoveryManagerBootstrapGrant(path, pin)
	if err != nil || grant == nil || grant.path != path || grant.digest != pin || grant.document != doc {
		t.Fatal("pinned grant rejected", err)
	}
	var missingAudit *recoveryBootstrapNilAuditStub
	serviceWithoutAudit := RecoveryManagerBootstrapService{Scope: doc.Scope, BootstrapIdentityHash: doc.BootstrapIdentityHash,
		GrantPath: path, GrantSHA256: pin, DB: &sql.DB{}, Authenticator: &RecoveryManagerPeerAuthenticator{}, ExternalAudit: missingAudit}
	if err := serviceWithoutAudit.RegisterFirst(context.Background(), &RecoveryManagerPeer{owner: serviceWithoutAudit.Authenticator}, grant); !errors.Is(err, ErrDenied) {
		t.Fatal("typed-nil external audit accepted", err)
	}
	if _, err := ReadRecoveryManagerBootstrapGrant(path, strings.Repeat("0", 64)); !errors.Is(err, ErrDenied) {
		t.Fatal("wrong deployment pin accepted", err)
	}
	if _, err := ReadRecoveryManagerBootstrapGrant(path, "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal("malformed deployment pin accepted", err)
	}
	for name, change := range map[string]func(*recoveryManagerBootstrapDocument){
		"wrong scope":                   func(d *recoveryManagerBootstrapDocument) { d.Scope.Database = "other" },
		"missing management permission": func(d *recoveryManagerBootstrapDocument) { d.ManageDeployment = false },
		"expired authorization":         func(d *recoveryManagerBootstrapDocument) { d.AuthorizedUntil = d.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := doc
			change(&mutated)
			if !validRecoveryManagerBootstrap(mutated) && name == "wrong scope" {
				t.Fatal("scope fixture invalid")
			}
			encoded, err := json.Marshal(mutated)
			if err != nil {
				t.Fatal(err)
			}
			newPin := write(encoded)
			candidate, err := ReadRecoveryManagerBootstrapGrant(path, newPin)
			if name == "wrong scope" {
				if err != nil || candidate.document.Scope == doc.Scope {
					t.Fatal("scope mismatch was not represented", err)
				}
				auth := &RecoveryManagerPeerAuthenticator{}
				service := RecoveryManagerBootstrapService{Scope: doc.Scope, BootstrapIdentityHash: doc.BootstrapIdentityHash,
					GrantPath: path, GrantSHA256: newPin, DB: &sql.DB{}, Authenticator: auth, ExternalAudit: recoveryBootstrapAuditStub{}}
				if err := service.RegisterFirst(context.Background(), &RecoveryManagerPeer{owner: auth}, candidate); !errors.Is(err, ErrDenied) {
					t.Fatal("cross-scope grant accepted", err)
				}
			} else if !errors.Is(err, ErrDenied) {
				t.Fatal("invalid grant accepted", err)
			}
		})
	}
	if got := write(append(raw, []byte("\n{\"extra\":true}")...)); got == pin {
		t.Fatal("fixture failed to change")
	} else if _, err := ReadRecoveryManagerBootstrapGrant(path, got); !errors.Is(err, ErrDenied) {
		t.Fatal("trailing JSON accepted", err)
	}
	if _, err := ReadRecoveryManagerBootstrapGrant(path, pin); !errors.Is(err, ErrDenied) {
		t.Fatal("changed file accepted under old pin", err)
	}
	unknownField := append([]byte(nil), raw[:len(raw)-1]...)
	unknownField = append(unknownField, []byte(`,"unknown":true}`)...)
	if _, err := ReadRecoveryManagerBootstrapGrant(path, write(unknownField)); !errors.Is(err, ErrDenied) {
		t.Fatal("unknown grant field accepted", err)
	}
}
