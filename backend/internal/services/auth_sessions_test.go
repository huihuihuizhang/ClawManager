package services

import (
	"clawreef/internal/config"
	"clawreef/internal/models"
	"clawreef/internal/repository"
	"clawreef/internal/systembackupsecurity"
	"clawreef/internal/utils"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"
)

type sessionLoginRepo struct {
	*fakeUserRepo
	beforeUpdate               func(*models.User)
	narrowUpdates, fullUpdates int
}

func (r *sessionLoginRepo) Update(u *models.User) error {
	r.fullUpdates++
	return errors.New("full update forbidden")
}
func (r *sessionLoginRepo) UpdateLoginState(s repository.LoginState) error {
	r.narrowUpdates++
	u := r.users[s.UserID]
	if r.beforeUpdate != nil {
		r.beforeUpdate(u)
	}
	if !u.IsActive || u.PasswordHash != s.PasswordHash || u.Role != s.ExpectedRole || u.AuthProvider != s.AuthProvider || !reflect.DeepEqual(u.ExternalID, s.ExternalID) {
		return errors.New("login state conflict")
	}
	u.LastLogin = &s.At
	u.Role = s.Role
	if u.AuthProvider == "" {
		u.AuthProvider = "local"
	}
	return nil
}

type sessionRecorderFunc func(context.Context, systembackupsecurity.LoginSessionPair) error

func (f sessionRecorderFunc) RecordPair(ctx context.Context, p systembackupsecurity.LoginSessionPair) error {
	return f(ctx, p)
}
func authSessionFixture(t *testing.T) (*sessionLoginRepo, *models.User) {
	t.Helper()
	r := &sessionLoginRepo{fakeUserRepo: newFakeUserRepo()}
	hash, err := utils.HashPassword("verified-password")
	if err != nil {
		t.Fatal(err)
	}
	u := &models.User{Username: "alice", PasswordHash: hash, Role: "admin", IsActive: true, AuthProvider: "local"}
	if err := r.Create(u); err != nil {
		t.Fatal(err)
	}
	return r, u
}

func TestAuthSessionLoginAndRefreshCallback(t *testing.T) {
	r, u := authSessionFixture(t)
	var captured []systembackupsecurity.LoginSessionPair
	auth := NewAuthService(r, testJWTConfig(), nil, WithSystemBackupSessions(sessionRecorderFunc(func(ctx context.Context, p systembackupsecurity.LoginSessionPair) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("missing callback timeout")
		}
		captured = append(captured, p)
		return nil
	})))
	pair, err := auth.Login("alice", "verified-password")
	if err != nil {
		t.Fatal(err)
	}
	next, err := auth.RefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 || r.narrowUpdates != 1 || r.fullUpdates != 0 {
		t.Fatal("issuer boundary not used")
	}
	hash := sha256.Sum256([]byte(u.PasswordHash))
	for _, p := range captured {
		if p.UserID != int64(u.ID) || p.CredentialSHA256 != hex.EncodeToString(hash[:]) {
			t.Fatal("callback does not bind verified credential")
		}
	}
	if captured[0].PreviousRefreshToken != "" || captured[1].PreviousRefreshToken != pair.RefreshToken || captured[1].AccessToken != next.AccessToken || captured[0].AccessToken != pair.AccessToken {
		t.Fatal("returned pair differs from registered pair")
	}
}

func TestAuthSessionRejectsBeforeReturningTokens(t *testing.T) {
	for _, failure := range []error{systembackupsecurity.ErrLoginSessionRejected, errors.New("PRIVATE_SQL_PASSWORD_AND_TOKEN")} {
		t.Run(failure.Error(), func(t *testing.T) {
			r, _ := authSessionFixture(t)
			calls := 0
			auth := NewAuthService(r, testJWTConfig(), nil, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error { calls++; return failure })))
			if p, err := auth.Login("alice", "wrong-password"); p != nil || err == nil || calls != 0 {
				t.Fatal("invalid password reached registrar")
			}
			want := systembackupsecurity.ErrLoginSessionUnavailable
			if failure == systembackupsecurity.ErrLoginSessionRejected {
				want = failure
			}
			if p, err := auth.Login("alice", "verified-password"); p != nil || err != want || calls != 1 {
				t.Fatalf("callback error was not closed: %v", err)
			}
		})
	}
}

func TestAuthSessionLoginCannotRestoreStaleUser(t *testing.T) {
	for _, kind := range []string{"password", "disabled", "role", "external identity"} {
		t.Run(kind, func(t *testing.T) {
			r, u := authSessionFixture(t)
			r.beforeUpdate = func(row *models.User) {
				switch kind {
				case "password":
					row.PasswordHash = "new-password-hash"
				case "disabled":
					row.IsActive = false
				case "role":
					row.Role = "user"
				case "external identity":
					row.ExternalID = stringPtr("different")
				}
			}
			calls := 0
			auth := NewAuthService(r, testJWTConfig(), nil, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error { calls++; return nil })))
			if p, err := auth.Login("alice", "verified-password"); p != nil || err == nil || calls != 0 || r.fullUpdates != 0 {
				t.Fatal("stale login snapshot accepted")
			}
			if kind == "password" && r.users[u.ID].PasswordHash != "new-password-hash" {
				t.Fatal("password restored")
			}
			if kind == "disabled" && r.users[u.ID].IsActive {
				t.Fatal("account reactivated")
			}
		})
	}
}

func TestAuthSessionRequiresNarrowRepository(t *testing.T) {
	r, _ := authSessionFixture(t)
	calls := 0
	auth := NewAuthService(r.fakeUserRepo, testJWTConfig(), nil, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error { calls++; return nil })))
	if p, err := auth.Login("alice", "verified-password"); p != nil || err == nil || calls != 0 {
		t.Fatal("unsafe repository enrolled")
	}
}

func TestAuthSessionLDAPUsesVerifiedIdentity(t *testing.T) {
	r, u := authSessionFixture(t)
	row := r.users[u.ID]
	row.PasswordHash = "external:ldap"
	row.AuthProvider = "ldap"
	row.LoginAlias = stringPtr("ldap_alice")
	row.ExternalID = stringPtr("uid=alice,dc=example")
	calls := 0
	auth := NewAuthService(r, testJWTConfig(), fakeEnterpriseAuth{user: &EnterpriseUser{ExternalID: *row.ExternalID, Role: "admin"}}, WithSystemBackupSessions(sessionRecorderFunc(func(_ context.Context, p systembackupsecurity.LoginSessionPair) error {
		calls++
		sum := sha256.Sum256([]byte("external:ldap"))
		if p.CredentialSHA256 != hex.EncodeToString(sum[:]) {
			t.Error("LDAP credential snapshot changed")
		}
		return nil
	})))
	if p, err := auth.Login("alice", "directory-password"); p == nil || err != nil || calls != 1 || r.narrowUpdates != 1 {
		t.Fatalf("LDAP issuance: %v", err)
	}
}

// This adapter deliberately does not pre-validate the returned identity: the
// service under test must reject a misbehaving directory adapter itself.
type sessionDirectoryFunc func(context.Context, string, string) (*EnterpriseUser, error)

func (f sessionDirectoryFunc) AuthenticateByIdentity(ctx context.Context, id, password string) (*EnterpriseUser, error) {
	return f(ctx, id, password)
}

func ldapSessionFixture(t *testing.T) (*sessionLoginRepo, *models.User) {
	t.Helper()
	r := &sessionLoginRepo{fakeUserRepo: newFakeUserRepo()}
	u := &models.User{Username: "alice", PasswordHash: "external:ldap", Role: "admin", IsActive: true,
		AuthProvider: AuthProviderLDAP, LoginAlias: stringPtr("ldap_alice"), ExternalID: stringPtr("uid=alice,dc=example")}
	if err := r.Create(u); err != nil {
		t.Fatal(err)
	}
	return r, u
}

func TestAuthSessionLDAPLegacyAliasCannotIssueTokens(t *testing.T) {
	r, _ := ldapSessionFixture(t)
	auth := NewAuthService(r, testJWTConfig(), sessionDirectoryFunc(func(context.Context, string, string) (*EnterpriseUser, error) {
		t.Fatal("legacy alias reached directory authentication")
		return nil, nil
	}), WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error {
		t.Fatal("legacy alias enrolled a backup session")
		return nil
	})))
	if pair, err := auth.Login("ldap_alice", "directory-password"); pair != nil || err == nil || r.narrowUpdates != 0 || r.fullUpdates != 0 {
		t.Fatal("legacy alias caused issuance or a user update")
	}
}

func TestAuthSessionLocalPrefixedUsernameKeepsLocalProvider(t *testing.T) {
	r, u := authSessionFixture(t)
	r.users[u.ID].Username = "ldap_alice"
	calls := 0
	auth := NewAuthService(r, testJWTConfig(), sessionDirectoryFunc(func(context.Context, string, string) (*EnterpriseUser, error) {
		t.Fatal("local prefixed username reached LDAP")
		return nil, nil
	}), WithSystemBackupSessions(sessionRecorderFunc(func(_ context.Context, pair systembackupsecurity.LoginSessionPair) error {
		calls++
		if pair.UserID != int64(u.ID) {
			t.Fatal("wrong backup session identity")
		}
		return nil
	})))
	if pair, err := auth.Login("ldap_alice", "verified-password"); pair == nil || err != nil || calls != 1 || r.narrowUpdates != 1 || r.fullUpdates != 0 {
		t.Fatalf("local prefixed username failed to enroll safely: %v", err)
	}
}

func TestAuthSessionLDAPRejectsDirectoryFailuresBeforeIssuance(t *testing.T) {
	for _, kind := range []string{"bad_password", "unavailable", "missing_user", "nil_identity", "different_identity", "empty_identity"} {
		t.Run(kind, func(t *testing.T) {
			r, u := ldapSessionFixture(t)
			directoryCalls, recorderCalls := 0, 0
			directory := sessionDirectoryFunc(func(_ context.Context, id, password string) (*EnterpriseUser, error) {
				directoryCalls++
				if id != *u.ExternalID || password != "directory-password" {
					t.Fatal("directory request did not bind provisioned identity and submitted credential")
				}
				switch kind {
				case "bad_password":
					return nil, ErrEnterpriseInvalidCredentials
				case "unavailable":
					return nil, errors.New("private directory endpoint and credential")
				case "missing_user":
					return nil, ErrEnterpriseUserNotFound
				case "nil_identity":
					return nil, nil
				case "different_identity":
					return &EnterpriseUser{ExternalID: "uid=bob,dc=example", Role: "admin"}, nil
				default:
					return &EnterpriseUser{Role: "admin"}, nil
				}
			})
			auth := NewAuthService(r, testJWTConfig(), directory, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error {
				recorderCalls++
				return nil
			})))
			pair, err := auth.Login("alice", "directory-password")
			if pair != nil || err == nil || err.Error() != "invalid username or password" {
				t.Fatal("directory failure returned tokens or exposed adapter details")
			}
			if directoryCalls != 1 || recorderCalls != 0 || r.narrowUpdates != 0 || r.fullUpdates != 0 || r.users[u.ID].LastLogin != nil {
				t.Fatal("rejected identity caused login side effects")
			}
		})
	}
}

func TestAuthSessionLDAPRejectsInvalidLocalBindingBeforeDirectory(t *testing.T) {
	for _, kind := range []string{"disabled", "missing_identity", "blank_identity", "unprovisioned", "missing_adapter"} {
		t.Run(kind, func(t *testing.T) {
			r, u := ldapSessionFixture(t)
			switch kind {
			case "disabled":
				r.users[u.ID].IsActive = false
			case "missing_identity":
				r.users[u.ID].ExternalID = nil
			case "blank_identity":
				r.users[u.ID].ExternalID = stringPtr("  ")
			case "unprovisioned":
				delete(r.users, u.ID)
			}
			var directory EnterpriseAuthenticator = sessionDirectoryFunc(func(context.Context, string, string) (*EnterpriseUser, error) {
				t.Fatal("invalid local binding reached the directory")
				return nil, nil
			})
			if kind == "missing_adapter" {
				directory = nil
			}
			auth := NewAuthService(r, testJWTConfig(), directory, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error {
				t.Fatal("invalid local binding reached the recorder")
				return nil
			})))
			if pair, err := auth.Login("alice", "directory-password"); pair != nil || err == nil || r.narrowUpdates != 0 || r.fullUpdates != 0 {
				t.Fatal("invalid local binding was accepted or updated")
			}
		})
	}
}

func TestAuthSessionLDAPRejectsChangedSnapshot(t *testing.T) {
	for _, kind := range []string{"disabled", "role", "identity", "provider", "credential"} {
		t.Run(kind, func(t *testing.T) {
			r, u := ldapSessionFixture(t)
			var changed models.User
			directoryCalls := 0
			directory := sessionDirectoryFunc(func(_ context.Context, id, _ string) (*EnterpriseUser, error) {
				directoryCalls++
				row := r.users[u.ID]
				switch kind {
				case "disabled":
					row.IsActive = false
				case "role":
					row.Role = "user"
				case "identity":
					row.ExternalID = stringPtr("uid=bob,dc=example")
				case "provider":
					row.AuthProvider = AuthProviderLocal
				case "credential":
					row.PasswordHash = "changed-credential-marker"
				}
				changed = *row
				return &EnterpriseUser{ExternalID: id, Role: "admin"}, nil
			})
			auth := NewAuthService(r, testJWTConfig(), directory, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error {
				t.Fatal("stale LDAP snapshot reached recorder")
				return nil
			})))
			if pair, err := auth.Login("alice", "directory-password"); pair != nil || err == nil || directoryCalls != 1 || r.narrowUpdates != 1 || r.fullUpdates != 0 {
				t.Fatal("stale LDAP snapshot was accepted")
			}
			if !reflect.DeepEqual(*r.users[u.ID], changed) {
				t.Fatal("login overwrote identity changes made during directory authentication")
			}
		})
	}
}

func TestAuthSessionLDAPRecorderFailureHidesTokens(t *testing.T) {
	for _, operation := range []string{"login", "refresh"} {
		for _, rejected := range []bool{false, true} {
			name := operation + "/unavailable"
			if rejected {
				name = operation + "/rejected"
			}
			t.Run(name, func(t *testing.T) {
				r, u := ldapSessionFixture(t)
				directoryCalls, recorderCalls := 0, 0
				directory := sessionDirectoryFunc(func(_ context.Context, id, _ string) (*EnterpriseUser, error) {
					directoryCalls++
					return &EnterpriseUser{ExternalID: id}, nil
				})
				refresh, err := utils.GenerateToken(utils.TokenClaims{UserID: u.ID, TokenType: "refresh"}, testJWTConfig().Secret, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				want := systembackupsecurity.ErrLoginSessionUnavailable
				if rejected {
					want = systembackupsecurity.ErrLoginSessionRejected
				}
				auth := NewAuthService(r, testJWTConfig(), directory, WithSystemBackupSessions(sessionRecorderFunc(func(_ context.Context, p systembackupsecurity.LoginSessionPair) error {
					recorderCalls++
					if operation == "refresh" && p.PreviousRefreshToken != refresh {
						t.Fatal("refresh lost its parent token")
					}
					if rejected {
						return want
					}
					return errors.New("private database credentials")
				})))
				var pair *TokenPair
				if operation == "login" {
					pair, err = auth.Login("alice", "directory-password")
				} else {
					pair, err = auth.RefreshToken(refresh)
				}
				if pair != nil || err != want || recorderCalls != 1 {
					t.Fatal("recorder failure returned tokens or leaked internal error")
				}
				if (operation == "login" && directoryCalls != 1) || (operation == "refresh" && directoryCalls != 0) {
					t.Fatal("unexpected directory authentication boundary")
				}
			})
		}
	}
}

func TestAuthSessionLDAPRoleSyncPrecedesRecorder(t *testing.T) {
	for _, role := range []string{"admin", "user"} {
		t.Run(role, func(t *testing.T) {
			r, u := ldapSessionFixture(t)
			r.users[u.ID].Role = "user"
			if role == "user" {
				r.users[u.ID].Role = "admin"
			}
			calls := 0
			auth := NewAuthService(r, testJWTConfig(), sessionDirectoryFunc(func(_ context.Context, id, _ string) (*EnterpriseUser, error) {
				return &EnterpriseUser{ExternalID: id, Role: role}, nil
			}), WithEnterpriseAuthPolicy(config.EnterpriseAuthConfig{SyncRole: true}), WithSystemBackupSessions(sessionRecorderFunc(func(_ context.Context, p systembackupsecurity.LoginSessionPair) error {
				calls++
				if r.users[u.ID].Role != role || r.narrowUpdates != 1 || p.UserID != int64(u.ID) {
					t.Fatal("recorder observed a stale role")
				}
				return nil
			})))
			if pair, err := auth.Login("alice", "directory-password"); pair == nil || err != nil || calls != 1 || r.fullUpdates != 0 {
				t.Fatal("role synchronization broke issuance")
			}
		})
	}
}

type observedLoginQuotaRepo struct {
	*fakeQuotaRepo
	reads  int
	onRead func()
}

func (r *observedLoginQuotaRepo) GetByUserID(id int) (*models.UserQuota, error) {
	r.reads++
	if r.onRead != nil {
		r.onRead()
	}
	return r.fakeQuotaRepo.GetByUserID(id)
}

func TestAuthSessionLDAPQuotaSyncFollowsConditionalLogin(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "accepted"
		if stale {
			name = "disabled_during_directory_auth"
		}
		t.Run(name, func(t *testing.T) {
			r, u := ldapSessionFixture(t)
			r.users[u.ID].Role = "user"
			quota := &observedLoginQuotaRepo{fakeQuotaRepo: &fakeQuotaRepo{}}
			quota.onRead = func() {
				if r.users[u.ID].Role != "admin" || r.narrowUpdates != 1 {
					t.Fatal("quota synchronized before the conditional login update")
				}
			}
			directory := sessionDirectoryFunc(func(_ context.Context, id, _ string) (*EnterpriseUser, error) {
				if stale {
					r.users[u.ID].IsActive = false
				}
				return &EnterpriseUser{ExternalID: id, Role: "admin"}, nil
			})
			auth := NewAuthService(r, testJWTConfig(), directory, WithEnterpriseAuthPolicy(config.EnterpriseAuthConfig{SyncRole: true}), WithQuotaRepository(quota))
			pair, err := auth.Login("alice", "directory-password")
			if stale {
				if pair != nil || err == nil || quota.reads != 0 || quota.createdFor != 0 {
					t.Fatal("stale directory login changed quota or issued tokens")
				}
			} else if pair == nil || err != nil || quota.reads != 1 || quota.createdFor != u.ID {
				t.Fatal("accepted directory login did not synchronize quota")
			}
		})
	}
}

func TestAuthSessionRequestContextReachesDirectoryAndRecorder(t *testing.T) {
	r, u := ldapSessionFixture(t)
	marker := struct{}{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), marker, "request"), time.Minute)
	defer cancel()
	directoryCalls, recorderCalls := 0, 0
	directory := sessionDirectoryFunc(func(ctx context.Context, id, _ string) (*EnterpriseUser, error) {
		directoryCalls++
		if ctx.Value(marker) != "request" || id != *u.ExternalID {
			t.Fatal("directory did not receive the request context")
		}
		return &EnterpriseUser{ExternalID: id, Role: "admin"}, nil
	})
	auth := NewAuthService(r, testJWTConfig(), directory, WithSystemBackupSessions(sessionRecorderFunc(func(ctx context.Context, _ systembackupsecurity.LoginSessionPair) error {
		recorderCalls++
		deadline, ok := ctx.Deadline()
		parentDeadline, _ := parent.Deadline()
		if ctx.Value(marker) != "request" || !ok || !deadline.Before(parentDeadline) {
			t.Fatal("session recorder did not receive the bounded request context")
		}
		return nil
	}))).(RequestAuthService)
	pair, err := auth.LoginContext(parent, "alice", "directory-password")
	if err != nil || pair == nil || directoryCalls != 1 || recorderCalls != 1 {
		t.Fatal("request-scoped LDAP login failed")
	}
	if next, err := auth.RefreshTokenContext(parent, pair.RefreshToken); err != nil || next == nil || recorderCalls != 2 {
		t.Fatal("request-scoped refresh did not reach the recorder")
	}
}

func TestAuthSessionCanceledDirectoryRequestCannotIssue(t *testing.T) {
	r, _ := ldapSessionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	directory := sessionDirectoryFunc(func(_ context.Context, id, _ string) (*EnterpriseUser, error) {
		cancel()
		return &EnterpriseUser{ExternalID: id, Role: "admin"}, nil
	})
	auth := NewAuthService(r, testJWTConfig(), directory, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error {
		t.Fatal("canceled LDAP request reached session registration")
		return nil
	}))).(RequestAuthService)
	if pair, err := auth.LoginContext(ctx, "alice", "directory-password"); pair != nil || !errors.Is(err, context.Canceled) || r.narrowUpdates != 0 || r.fullUpdates != 0 {
		t.Fatal("canceled LDAP request updated login state or issued tokens")
	}
	if pair, err := auth.RefreshTokenContext(ctx, "ignored"); pair != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled refresh was not rejected before token processing")
	}
}

func TestAuthSessionCanceledRecorderCannotReturnTokens(t *testing.T) {
	r, _ := authSessionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	auth := NewAuthService(r, testJWTConfig(), nil, WithSystemBackupSessions(sessionRecorderFunc(func(context.Context, systembackupsecurity.LoginSessionPair) error {
		cancel()
		return nil
	}))).(RequestAuthService)
	if pair, err := auth.LoginContext(ctx, "alice", "verified-password"); pair != nil || !errors.Is(err, systembackupsecurity.ErrLoginSessionUnavailable) {
		t.Fatal("canceled session registration returned tokens")
	}
}
