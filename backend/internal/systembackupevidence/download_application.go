package systembackupevidence

import (
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// All inputs are deployment-owned. Sessions, materials and physical capacity
// must describe the same installation/database; their production readers
// recheck these identities on the borrowed transaction. No owner adapter,
// arbitrary audit callback or legacy private-download proof can be supplied.
type DownloadApplicationConfig struct {
	Authority                                         DownloadAuthorityConfig
	S3                                                S3STSConfig
	Transit                                           []DownloadTransitConfig
	Sessions                                          *sec.SQLLoginSessions
	Materials                                         *sec.ConfigMutationSecurityFiles
	Capacity                                          *sec.ConfigMutationCapacity
	ProofIssuer                                       string
	AdmissionReservationBytes, ResultReservationBytes int
	MaterialsUntil, AuditMinimumRetainUntil           time.Time
	JournalPath                                       string
	JournalMaxBytes                                   int64
}

type DownloadApplication struct {
	Runtime      *DownloadRuntime
	ProofTargets *PinnedSensitiveDownloadProofTargets
	admission    *DownloadAdmissionService
}

func NewDownloadApplication(c DownloadApplicationConfig) (*DownloadApplication, error) {
	base := c.Authority.Registry
	if base.Policy != nil || !nilSystemAdapter(c.Authority.SensitiveStepUp) {
		return nil, ErrDownloadAdmissionNotReady
	}
	owners, err := NewSQLDownloadOwners(SQLDownloadOwnersConfig{Registry: base, Sessions: c.Sessions, RegistryDirectory: c.Authority.RegistryDirectory, Root: c.Authority.Root})
	if err != nil {
		return nil, err
	}
	registry := owners.Registry()
	environment, err := NewPinnedDownloadAdmissionEnvironment(PinnedDownloadAdmissionConfig{Installation: registry.Installation, Sessions: c.Sessions, Materials: c.Materials,
		RegistryDirectory: c.Authority.RegistryDirectory, Issuer: c.ProofIssuer, Owners: owners, Capacity: c.Capacity,
		MeasuredReservationBytes: c.AdmissionReservationBytes, MaterialsUntil: c.MaterialsUntil, AuditMinimumRetainUntil: c.AuditMinimumRetainUntil})
	if err != nil {
		return nil, err
	}
	app := &DownloadApplication{}
	app.admission, err = NewDownloadAdmissionService(registry, c.Authority.JWTSecret, environment)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*DownloadApplication, error) { app.Close(); return nil, err }
	results, err := NewSQLDownloadResults(SQLDownloadResultsConfig{Registry: registry, Owners: owners, Capacity: c.Capacity, MeasuredReservationBytes: c.ResultReservationBytes})
	if err != nil {
		return fail(err)
	}
	app.ProofTargets, err = NewPinnedSensitiveDownloadProofTargets(registry, environment)
	if err != nil {
		return fail(err)
	}
	c.Authority.Registry = registry
	app.Runtime, err = NewJournaledDownloadRuntime(DownloadRuntimeConfig{Authority: c.Authority, S3: c.S3, Transit: c.Transit, Admission: app.admission, Results: results},
		DownloadFailureJournalConfig{Path: c.JournalPath, MaxBytes: c.JournalMaxBytes, Installation: registry.Installation, ServerUUID: registry.ServerUUID, Database: registry.Database})
	if err != nil {
		return fail(err)
	}
	return app, nil
}

// The HTTPS host must drain requests before closing owned keys and journal.
func (a *DownloadApplication) Close() {
	if a == nil {
		return
	}
	a.Runtime.Close()
	if a.admission != nil {
		wipe(a.admission.secret)
	}
}
