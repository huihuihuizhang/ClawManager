package systembackupbusinessa

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type enterpriseAuthProofFixture struct {
	calls       int
	wantVersion string
	failure     error
	mutateInput bool
}

func (p *enterpriseAuthProofFixture) VerifyEnterpriseAuthSource(_ context.Context, registry, schema,
	evidence string, sources []EnterpriseAuthRestoreSource) error {
	p.calls++
	if !hashPattern.MatchString(registry) || !hashPattern.MatchString(schema) || evidence != "sev_enterprise_auth" {
		return errors.New("unbound enterprise auth evidence")
	}
	if len(sources) == 1 && sources[0].SecretRefVersion != p.wantVersion {
		return ErrEnterpriseAuthRestore
	}
	if p.mutateInput && len(sources) == 1 {
		sources[0].LDAPHost = "attacker.invalid"
		*sources[0].LDAPAdminGroupDNs = "attacker"
		*sources[0].UpdatedBy = 99
	}
	return p.failure
}

func enterpriseAuthRestoreFixture(t *testing.T) (*CaptureScope, *UserRestoreBatch,
	EnterpriseAuthRestoreSource, EnterpriseAuthRestoreMapping) {
	t.Helper()
	scope, err := pinnedScope(t, registryFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 20, 1, 2, 3, 123456000, time.UTC)
	users, err := NormalizeUsersForRestore([]UserRestoreSource{{
		ID: 7, Username: "source", Email: "source@example.invalid", Role: "admin",
		CreatedAt: created, UpdatedAt: created,
	}}, []UserRestoreMapping{{
		SourceID: 7, TargetID: 107, TargetUsername: "target", TargetEmail: "target@example.invalid",
	}})
	if err != nil {
		t.Fatal(err)
	}
	actor := 7
	groups := "cn=admins,dc=example,dc=invalid\ncn=operators,dc=example,dc=invalid"
	source := EnterpriseAuthRestoreSource{
		ID: 1, Provider: "ldap", Enabled: true, AllowLocalFallback: true, SyncRole: true,
		LDAPHost: "ldap.example.invalid", LDAPPort: 636, LDAPUseTLS: true,
		LDAPTLSCAFile: "/etc/certs/ldap-ca.pem", LDAPTLSServerName: "ldap.example.invalid",
		LDAPBindDN:             "cn=bind,dc=example,dc=invalid",
		BindPasswordSourceKind: EnterpriseAuthBindCiphertextRef, SecretRefVersion: "fixture-version-1",
		LDAPBaseDN: "dc=example,dc=invalid", LDAPUserFilter: "(uid=%s)",
		LDAPUsernameAttribute: "uid", LDAPEmailAttribute: "mail",
		LDAPGroupBaseDN: "ou=groups,dc=example,dc=invalid",
		LDAPGroupFilter: "(member=%s)", LDAPAdminGroupDNs: &groups,
		LDAPDefaultRole: "user", Version: 3, UpdatedBy: &actor,
		CreatedAt: created, UpdatedAt: created.Add(time.Hour),
	}
	return scope, users, source, EnterpriseAuthRestoreMapping{SourceID: 1, TargetID: 101}
}

func TestEnterpriseAuthRestoreCompleteInertRowWithBoundProof(t *testing.T) {
	scope, users, source, mapping := enterpriseAuthRestoreFixture(t)
	proof := &enterpriseAuthProofFixture{wantVersion: source.SecretRefVersion, mutateInput: true}
	rows, err := NormalizeEnterpriseAuthSettingsForRestore(context.Background(), scope, users,
		[]EnterpriseAuthRestoreSource{source}, []EnterpriseAuthRestoreMapping{mapping}, "sev_enterprise_auth", proof)
	if err != nil || proof.calls != 1 || len(rows) != 1 {
		t.Fatalf("incomplete enterprise auth restore: %+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	row := rows[0]
	if row.ID != 101 || row.Provider != "ldap" || row.Enabled || !row.AllowLocalFallback ||
		!row.SyncRole || row.LDAPHost != source.LDAPHost || row.LDAPPort != 636 ||
		!row.LDAPUseTLS || row.LDAPTLSCAFile != source.LDAPTLSCAFile ||
		row.LDAPBindDN != source.LDAPBindDN || row.LDAPBaseDN != source.LDAPBaseDN ||
		row.LDAPUserFilter != source.LDAPUserFilter || row.LDAPDefaultRole != "user" ||
		row.LDAPBindPasswordCiphertext == nil || *row.LDAPBindPasswordCiphertext != "" ||
		row.LDAPAdminGroupDNs == nil || *row.LDAPAdminGroupDNs != *source.LDAPAdminGroupDNs ||
		row.UpdatedBy == nil || *row.UpdatedBy != 107 || row.Version != 3 ||
		!row.CreatedAt.Equal(source.CreatedAt) || !row.UpdatedAt.Equal(source.UpdatedAt) {
		t.Fatalf("enterprise auth row retained a credential or lost SQL fields: %+v", row)
	}
	*source.LDAPAdminGroupDNs = "source mutated"
	*source.UpdatedBy = 8
	if *row.LDAPAdminGroupDNs != "cn=admins,dc=example,dc=invalid\ncn=operators,dc=example,dc=invalid" ||
		*row.UpdatedBy != 107 {
		t.Fatal("restored row aliases mutable source fields")
	}
}

func TestEnterpriseAuthRestoreRequiresProofEvenForEmptyTable(t *testing.T) {
	scope, users, source, mapping := enterpriseAuthRestoreFixture(t)
	proof := &enterpriseAuthProofFixture{}
	rows, err := NormalizeEnterpriseAuthSettingsForRestore(context.Background(), scope, users,
		nil, nil, "sev_enterprise_auth", proof)
	if err != nil || len(rows) != 0 || proof.calls != 1 {
		t.Fatalf("empty source was not proved: rows=%+v, calls=%d, err=%v", rows, proof.calls, err)
	}
	for name, candidate := range map[string]EnterpriseAuthSourceProofVerifier{
		"nil": nil, "typed nil": (*enterpriseAuthProofFixture)(nil),
	} {
		rows, err := NormalizeEnterpriseAuthSettingsForRestore(context.Background(), scope, users,
			[]EnterpriseAuthRestoreSource{source}, []EnterpriseAuthRestoreMapping{mapping},
			"sev_enterprise_auth", candidate)
		if !errors.Is(err, ErrCaptureEvidenceIncomplete) || rows != nil {
			t.Fatalf("%s proof accepted: rows=%+v, err=%v", name, rows, err)
		}
	}
	proof = &enterpriseAuthProofFixture{wantVersion: "fixture-version-1", failure: errors.New("dump unavailable")}
	rows, err = NormalizeEnterpriseAuthSettingsForRestore(context.Background(), scope, users,
		[]EnterpriseAuthRestoreSource{source}, []EnterpriseAuthRestoreMapping{mapping},
		"sev_enterprise_auth", proof)
	if err == nil || rows != nil || proof.calls != 1 {
		t.Fatalf("failed source proof emitted rows: %+v, err=%v", rows, err)
	}
}

func TestEnterpriseAuthRestoreRejectsRefDriftAndInvalidSource(t *testing.T) {
	scope, users, source, mapping := enterpriseAuthRestoreFixture(t)
	proof := &enterpriseAuthProofFixture{wantVersion: "fixture-version-1"}
	badVersion := source
	badVersion.SecretRefVersion = "fixture-version-2"
	rows, err := NormalizeEnterpriseAuthSettingsForRestore(context.Background(), scope, users,
		[]EnterpriseAuthRestoreSource{badVersion}, []EnterpriseAuthRestoreMapping{mapping},
		"sev_enterprise_auth", proof)
	if !errors.Is(err, ErrEnterpriseAuthRestore) || rows != nil || proof.calls != 1 {
		t.Fatalf("secret ref version drift accepted: %+v, err=%v", rows, err)
	}
	for name, mutate := range map[string]func(*EnterpriseAuthRestoreSource, *EnterpriseAuthRestoreMapping){
		"missing actor mapping": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) {
			actor := 8
			s.UpdatedBy = &actor
		},
		"bad target id":         func(_ *EnterpriseAuthRestoreSource, m *EnterpriseAuthRestoreMapping) { m.TargetID = 0 },
		"wrong source id":       func(_ *EnterpriseAuthRestoreSource, m *EnterpriseAuthRestoreMapping) { m.SourceID = 2 },
		"future provider":       func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) { s.Provider = "oidc" },
		"invalid role":          func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) { s.LDAPDefaultRole = "root" },
		"invalid port":          func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) { s.LDAPPort = 0 },
		"invalid version alias": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) { s.SecretRefVersion = "latest" },
		"missing ref":           func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) { s.SecretRefVersion = "" },
		"ref on clear": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) {
			s.BindPasswordSourceKind = EnterpriseAuthBindExplicitClear
		},
		"unknown bind state": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) {
			s.BindPasswordSourceKind = "unknown"
		},
		"invalid text": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) { s.LDAPHost = "ldap\x00host" },
		"oversized text": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) {
			s.LDAPHost = strings.Repeat("a", 256)
		},
		"reversed times": func(s *EnterpriseAuthRestoreSource, _ *EnterpriseAuthRestoreMapping) {
			s.UpdatedAt = s.CreatedAt.Add(-time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			badSource, badMapping := source, mapping
			mutate(&badSource, &badMapping)
			candidate := &enterpriseAuthProofFixture{wantVersion: "fixture-version-1"}
			rows, err := NormalizeEnterpriseAuthSettingsForRestore(context.Background(), scope, users,
				[]EnterpriseAuthRestoreSource{badSource}, []EnterpriseAuthRestoreMapping{badMapping},
				"sev_enterprise_auth", candidate)
			if !errors.Is(err, ErrEnterpriseAuthRestore) || rows != nil || candidate.calls != 0 {
				t.Fatalf("invalid source reached proof or emitted rows: %+v, calls=%d, err=%v", rows, candidate.calls, err)
			}
		})
	}
}

func TestEnterpriseAuthRestoreClearsInheritedEnvironmentPassword(t *testing.T) {
	_, users, source, mapping := enterpriseAuthRestoreFixture(t)
	for _, kind := range []string{EnterpriseAuthBindInherited, EnterpriseAuthBindExplicitClear} {
		source.BindPasswordSourceKind = kind
		source.SecretRefVersion = ""
		row, err := NormalizeEnterpriseAuthSettingForRestore(users, source, mapping)
		if err != nil || row.Enabled || row.LDAPBindPasswordCiphertext == nil ||
			*row.LDAPBindPasswordCiphertext != "" {
			t.Fatalf("%s inherited target environment password: %+v, err=%v", kind, row, err)
		}
	}
}
