package systembackupsecurity

import (
	"context"
	"database/sql"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"
)

// Deployment construction only. Resource observations are actual original
// owners, never HTTP fields or bootstrap grants. The factory itself supplies
// the real session/registry/strong-auth/nonce/RBAC/capacity/response adapters.
type ConfigMutationProductionConfig struct {
	DB                                *sql.DB
	Database                          DatabaseIdentity
	InstallationID                    string
	SessionSecret                     []byte
	RegistryDirectory, NonceDirectory string
	CapacityReportFile                string
	LargeSmokeBytes                   int64
	Resources                         ConfigMutationResolverSources
}

type ConfigMutationProduction struct {
	service  ConfigMutationService
	handler  *ConfigMutationHTTP
	sessions *SQLLoginSessions
	secret   []byte
}

// Registry bytes are supplied by the fixed real file reader below, so that
// particular callback is not an external dependency. Every owner remains so.
func MissingConfigMutationProductionOwners(s ConfigMutationResolverSources) []string {
	missing := []string{}
	for _, name := range MissingConfigMutationResolverAdapters(s) {
		if name != "registry_bytes" {
			missing = append(missing, name)
		}
	}
	return missing
}

func NewConfigMutationProduction(cfg ConfigMutationProductionConfig) (*ConfigMutationProduction, error) {
	if cfg.DB == nil || !cfg.Database.valid() || !configMutationInstallation.MatchString(cfg.InstallationID) || len(cfg.SessionSecret) < 32 || len(MissingConfigMutationProductionOwners(cfg.Resources)) != 0 {
		return nil, ErrRegistrationUnavailable
	}
	// The SAME actual KEK resolver owner must supply the independently invoked
	// preparation. There is no separate override that can bypass its attempt.
	kekOwner := cfg.Resources.References["kek"]
	kek, ok := kekOwner.(ConfigMutationKEKPreparation)
	if !ok || nilConfigMutationBoundary(kek) || reflect.TypeOf(kekOwner).Kind() != reflect.Pointer {
		return nil, ErrRegistrationUnavailable
	}
	files, err := NewConfigMutationSecurityFiles(cfg.InstallationID, cfg.Database, cfg.RegistryDirectory, cfg.NonceDirectory)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	capacity, err := NewConfigMutationCapacity(cfg.Database, cfg.CapacityReportFile, cfg.LargeSmokeBytes)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	sessions, err := NewSQLLoginSessions(cfg.DB, cfg.Database, cfg.InstallationID, cfg.SessionSecret)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	keep := false
	defer func() {
		if !keep {
			sessions.Close()
		}
	}()
	authority, err := NewPinnedConfigMutationAuthority(cfg.InstallationID, ConfigMutationAuthoritySources{
		CheckSession: sessions.CheckConfigMutationSession, RegistryBytes: files.files.RegistryBytes,
		StrongAuth: files.StrongAuth, ReserveMetadata: capacity.Reserve, RedactReason: redactProductionConfigChangeReason,
	})
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	resources := cfg.Resources
	resources.RegistryBytes = files.files.RegistryBytes
	resolver, err := NewPinnedConfigMutationResolver(cfg.InstallationID, cfg.Database, resources)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	responses, err := NewSQLOperationResponses(cfg.DB, cfg.Database, cfg.InstallationID, sessions, cfg.RegistryDirectory)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	out := &ConfigMutationProduction{sessions: sessions, secret: append([]byte(nil), cfg.SessionSecret...)}
	out.service = ConfigMutationService{DB: cfg.DB, Database: cfg.Database, InstallationID: cfg.InstallationID, Authority: authority, Resolver: resolver, Responses: responses, KEK: kek}
	out.handler, err = NewConfigMutationHTTP(cfg.InstallationID, JWTRegistrationAuthenticator{Secret: out.secret}, &out.service)
	if err != nil {
		wipeSecret(out.secret)
		return nil, ErrRegistrationUnavailable
	}
	keep = true
	return out, nil
}

// Preserve only the presence of an optional free-text reason in the audit.
// Exact request hashing still binds the submitted body; no submitted secret or
// caller text is echoed to response/evidence/audit by this production adapter.
func redactProductionConfigChangeReason(ctx context.Context, reason *string) (*string, error) {
	if ctx == nil || ctx.Err() != nil || reason != nil && (!utf8.ValidString(*reason) || len(*reason) > 512) {
		return nil, ErrRegistrationUnavailable
	}
	if reason == nil || strings.TrimSpace(*reason) == "" {
		return nil, nil
	}
	redacted := "[redacted]"
	return &redacted, nil
}

func (p *ConfigMutationProduction) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p == nil || p.handler == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	p.handler.ServeHTTP(w, r)
}

// Register this SAME recorder with the existing verified login/refresh issuer.
// This getter does not create/enroll/refresh a session or authenticate an actor.
func (p *ConfigMutationProduction) LoginSessions() *SQLLoginSessions {
	if p == nil {
		return nil
	}
	return p.sessions
}

// Drain HTTP/login users first. Caller retains ownership of the actual DB.
func (p *ConfigMutationProduction) Close() {
	if p == nil {
		return
	}
	p.handler = nil
	if p.sessions != nil {
		p.sessions.Close()
	}
	wipeSecret(p.secret)
	p.secret = nil
}

var _ http.Handler = (*ConfigMutationProduction)(nil)
