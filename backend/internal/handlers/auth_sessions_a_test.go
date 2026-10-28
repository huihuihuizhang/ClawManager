package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/config"
	"clawreef/internal/middleware"
	"clawreef/internal/models"
	"clawreef/internal/repository"
	"clawreef/internal/services"
	"clawreef/internal/systembackupsecurity"
	"clawreef/internal/utils"

	"github.com/gin-gonic/gin"
)

// Exercise the real HTTP handler, auth service, bcrypt and JWT. Repository,
// session persistence and directory transport are models, not SQL/LDAP proof.
type aAuthHTTPRepo struct {
	repository.UserRepository
	user    models.User
	updates int
}

func (r *aAuthHTTPRepo) GetByUsername(name string) (*models.User, error) {
	if name != r.user.Username {
		return nil, nil
	}
	u := r.user
	return &u, nil
}
func (r *aAuthHTTPRepo) GetByID(id int) (*models.User, error) {
	if id != r.user.ID {
		return nil, nil
	}
	u := r.user
	return &u, nil
}
func (r *aAuthHTTPRepo) UpdateLoginState(s repository.LoginState) error {
	if s.UserID != r.user.ID || s.PasswordHash != r.user.PasswordHash || s.ExpectedRole != r.user.Role || s.AuthProvider != r.user.AuthProvider || !reflect.DeepEqual(s.ExternalID, r.user.ExternalID) || !r.user.IsActive {
		return errors.New("login state changed")
	}
	r.updates++
	r.user.LastLogin = &s.At
	r.user.Role = s.Role
	return nil
}
func (r *aAuthHTTPRepo) Update(*models.User) error {
	return errors.New("full user update forbidden in session-enabled login")
}

type aAuthHTTPRecorder func(context.Context, systembackupsecurity.LoginSessionPair) error

func (f aAuthHTTPRecorder) RecordPair(ctx context.Context, p systembackupsecurity.LoginSessionPair) error {
	return f(ctx, p)
}

type aAuthHTTPDirectory func(context.Context, string, string) (*services.EnterpriseUser, error)

func (f aAuthHTTPDirectory) AuthenticateByIdentity(ctx context.Context, id, password string) (*services.EnterpriseUser, error) {
	return f(ctx, id, password)
}

type aAuthHTTPContextKey struct{}

const aAuthHTTPSecret = "synthetic-auth-http-secret-at-least-32-bytes"

func aAuthHTTPFixture(t *testing.T, record aAuthHTTPRecorder, directory services.EnterpriseAuthenticator) (*aAuthHTTPRepo, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	hash, err := utils.HashPassword("verified-http-password")
	if err != nil {
		t.Fatal(err)
	}
	repo := &aAuthHTTPRepo{user: models.User{ID: 45, Username: "alice", Role: "admin", IsActive: true, AuthProvider: "local", PasswordHash: hash}}
	if directory != nil {
		id := "uid=alice,dc=example"
		repo.user.AuthProvider, repo.user.PasswordHash, repo.user.ExternalID = "ldap", "external:ldap", &id
	}
	auth := services.NewAuthService(repo, config.JWTConfig{Secret: aAuthHTTPSecret, AccessExpiry: 5, RefreshExpiry: 1}, directory, services.WithSystemBackupSessions(record))
	handler := NewAuthHandler(auth)
	router := gin.New()
	router.POST("/login", handler.Login)
	router.POST("/refresh", handler.RefreshToken)
	return repo, router
}

func aAuthHTTPPost(router *gin.Engine, ctx context.Context, endpoint, body string, bearer ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://manager.example"+endpoint, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	if len(bearer) == 1 && bearer[0] != "" {
		r.Header.Set("Authorization", "Bearer "+bearer[0])
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func aAuthHTTPToken(t *testing.T, kind string) string {
	t.Helper()
	token, err := utils.GenerateToken(utils.TokenClaims{UserID: 45, TokenType: kind}, aAuthHTTPSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func aAuthHTTPPair(t *testing.T, w *httptest.ResponseRecorder) services.TokenPair {
	t.Helper()
	var result struct {
		Success bool               `json:"success"`
		Data    services.TokenPair `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusOK || !result.Success {
		t.Fatalf("token response status=%d decode=%v", w.Code, err)
	}
	for kind, token := range map[string]string{"access": result.Data.AccessToken, "refresh": result.Data.RefreshToken} {
		claims, err := utils.ValidateToken(token, aAuthHTTPSecret)
		if err != nil || claims.UserID != 45 || claims.TokenType != kind || claims.ID == "" {
			t.Fatalf("invalid returned %s JWT", kind)
		}
	}
	return result.Data
}

func TestAAuthHTTPLoginRefreshBindsRegisteredTokens(t *testing.T) {
	ctx := context.WithValue(context.Background(), aAuthHTTPContextKey{}, "request-bound")
	var registered []systembackupsecurity.LoginSessionPair
	repo, router := aAuthHTTPFixture(t, func(ctx context.Context, p systembackupsecurity.LoginSessionPair) error {
		if ctx.Value(aAuthHTTPContextKey{}) != "request-bound" {
			t.Error("HTTP request context lost before enrollment")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("enrollment lacks bounded context")
		}
		registered = append(registered, p)
		return nil
	}, nil)
	first := aAuthHTTPPair(t, aAuthHTTPPost(router, ctx, "/login", `{"username":"alice","password":"verified-http-password"}`))
	next := aAuthHTTPPair(t, aAuthHTTPPost(router, ctx, "/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`))
	if len(registered) != 2 || repo.updates != 1 || registered[0].PreviousRefreshToken != "" || registered[1].PreviousRefreshToken != first.RefreshToken {
		t.Fatal("HTTP login/refresh did not use the narrow enrollment boundary")
	}
	digest := sha256.Sum256([]byte(repo.user.PasswordHash))
	for i, pair := range []services.TokenPair{first, next} {
		got := registered[i]
		if got.UserID != 45 || got.CredentialSHA256 != hex.EncodeToString(digest[:]) || got.AccessToken != pair.AccessToken || got.RefreshToken != pair.RefreshToken {
			t.Fatal("HTTP returned tokens differ from registered credential-bound pair")
		}
	}
	if first.AccessToken == next.AccessToken || first.RefreshToken == next.RefreshToken {
		t.Fatal("refresh reused token identities")
	}
}

func TestAAuthHTTPEnrollmentFailureWithholdsTokens(t *testing.T) {
	for _, endpoint := range []string{"/login", "/refresh"} {
		for _, failure := range []string{"rejected", "unavailable", "request-cancelled-in-recorder"} {
			t.Run(endpoint+"/"+failure, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				_, router := aAuthHTTPFixture(t, func(context.Context, systembackupsecurity.LoginSessionPair) error {
					calls++
					switch failure {
					case "rejected":
						return systembackupsecurity.ErrLoginSessionRejected
					case "unavailable":
						return errors.New("PRIVATE_DATABASE_DETAIL")
					default:
						cancel()
						return nil
					}
				}, nil)
				body := `{"username":"alice","password":"verified-http-password"}`
				if endpoint == "/refresh" {
					body = `{"refresh_token":"` + aAuthHTTPToken(t, "refresh") + `"}`
				}
				w := aAuthHTTPPost(router, ctx, endpoint, body)
				want := http.StatusServiceUnavailable
				if failure == "rejected" {
					want = http.StatusUnauthorized
				}
				if w.Code != want || calls != 1 || strings.Contains(w.Body.String(), "PRIVATE_DATABASE_DETAIL") || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
					t.Fatalf("enrollment failure not closed: status=%d calls=%d", w.Code, calls)
				}
			})
		}
	}
}

func TestAAuthHTTPInvalidRequestsNeverEnroll(t *testing.T) {
	for _, kind := range []string{"malformed-login", "missing-username", "wrong-password", "disabled-user", "malformed-refresh", "invalid-refresh", "access-as-refresh", "cancelled-login", "cancelled-refresh"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			repo, router := aAuthHTTPFixture(t, func(context.Context, systembackupsecurity.LoginSessionPair) error { calls++; return nil }, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			endpoint, body := "/login", `{"username":"alice","password":"verified-http-password"}`
			switch kind {
			case "malformed-login":
				body = "{"
			case "missing-username":
				body = `{"password":"verified-http-password"}`
			case "wrong-password":
				body = `{"username":"alice","password":"wrong"}`
			case "disabled-user":
				repo.user.IsActive = false
			case "malformed-refresh":
				endpoint, body = "/refresh", "{"
			case "invalid-refresh":
				endpoint, body = "/refresh", `{"refresh_token":"invalid"}`
			case "access-as-refresh":
				endpoint, body = "/refresh", `{"refresh_token":"`+aAuthHTTPToken(t, "access")+`"}`
			case "cancelled-login":
				cancel()
			case "cancelled-refresh":
				endpoint, body = "/refresh", `{"refresh_token":"`+aAuthHTTPToken(t, "refresh")+`"}`
				cancel()
			}
			w := aAuthHTTPPost(router, ctx, endpoint, body)
			if w.Code < 400 || calls != 0 || strings.Contains(w.Body.String(), "access_token") || strings.Contains(w.Body.String(), "refresh_token") {
				t.Fatalf("invalid request enrolled: status=%d calls=%d", w.Code, calls)
			}
		})
	}
}

func TestAAuthHTTPDirectoryUsesRequestAndProvisionedIdentity(t *testing.T) {
	for _, kind := range []string{"accepted", "different-identity", "unavailable", "cancelled-in-directory"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), aAuthHTTPContextKey{}, "directory-request"))
			defer cancel()
			enrollments, directoryCalls := 0, 0
			_, router := aAuthHTTPFixture(t, func(context.Context, systembackupsecurity.LoginSessionPair) error { enrollments++; return nil }, aAuthHTTPDirectory(func(ctx context.Context, id, password string) (*services.EnterpriseUser, error) {
				directoryCalls++
				if ctx.Value(aAuthHTTPContextKey{}) != "directory-request" || id != "uid=alice,dc=example" || password != "verified-http-password" {
					t.Error("directory did not receive actual request and provisioned identity")
				}
				switch kind {
				case "different-identity":
					return &services.EnterpriseUser{ExternalID: "uid=other,dc=example"}, nil
				case "unavailable":
					return nil, services.ErrEnterpriseUnavailable
				case "cancelled-in-directory":
					cancel()
				}
				return &services.EnterpriseUser{ExternalID: id, Role: "admin"}, nil
			}))
			w := aAuthHTTPPost(router, ctx, "/login", `{"username":"alice","password":"verified-http-password"}`)
			if directoryCalls != 1 {
				t.Fatal("directory authentication not invoked exactly once")
			}
			if kind == "accepted" {
				aAuthHTTPPair(t, w)
				if enrollments != 1 {
					t.Fatal("verified directory identity not enrolled")
				}
			} else if w.Code < 400 || enrollments != 0 || strings.Contains(w.Body.String(), "access_token") {
				t.Fatal("directory rejection released tokens")
			}
		})
	}
}

func TestAAuthHTTPLogoutRevokesBeforeSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("JWT_SECRET", aAuthHTTPSecret)
	for _, kind := range []string{"success", "backup-failure", "desktop-failure", "no-token", "invalid-token", "refresh-token"} {
		t.Run(kind, func(t *testing.T) {
			handler := NewAuthHandler(nil)
			var calls []string
			hook := func(name string) func(context.Context, int) error {
				return func(ctx context.Context, id int) error {
					if id != 45 || ctx.Value(aAuthHTTPContextKey{}) != "logout-request" {
						t.Error("revocation lost authenticated user or request context")
					}
					calls = append(calls, name)
					if kind == name+"-failure" {
						return errors.New("PRIVATE_REVOCATION_DETAIL")
					}
					return nil
				}
			}
			handler.SetSystemBackupLogoutHook(hook("backup"))
			handler.SetDesktopLogoutHook(hook("desktop"))
			router := gin.New()
			router.POST("/logout", middleware.Auth(), handler.Logout)
			token := aAuthHTTPToken(t, "access")
			switch kind {
			case "no-token":
				token = ""
			case "invalid-token":
				token = "invalid"
			case "refresh-token":
				token = aAuthHTTPToken(t, "refresh")
			}
			w := aAuthHTTPPost(router, context.WithValue(context.Background(), aAuthHTTPContextKey{}, "logout-request"), "/logout", `{}`, token)
			wantCalls := []string{"backup", "desktop"}
			wantStatus := http.StatusOK
			if kind != "success" {
				wantStatus = http.StatusServiceUnavailable
			}
			if kind == "backup-failure" {
				wantCalls = []string{"backup"}
			}
			if strings.HasSuffix(kind, "token") {
				wantStatus, wantCalls = http.StatusUnauthorized, nil
			}
			if w.Code != wantStatus || !reflect.DeepEqual(calls, wantCalls) || strings.Contains(w.Body.String(), "PRIVATE_REVOCATION_DETAIL") {
				t.Fatalf("logout revocation not closed: status=%d calls=%v", w.Code, calls)
			}
		})
	}
}
