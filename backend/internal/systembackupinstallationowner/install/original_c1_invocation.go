package install

import (
	"clawreef/internal/mysqltls"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"github.com/go-sql-driver/mysql"
	"path/filepath"
	"strings"
	"time"
)

// OriginalC1SigningInvocation contains pinned source selections, never an
// authorization JSON. Authentication still requires real original admin bytes,
// current Kubernetes enrollment, original issuer and actual native sources.
type OriginalC1ReferenceGroups struct {
	Six, MinIO, StatusRelay, Nonce, EvidenceCA, BackupKEK, CatalogCheckpoint                                                                                                          BootstrapSourceFilePin
	SixOutputDirectory, MinIOOutputDirectory, StatusRelayOutputDirectory, NonceOutputDirectory, EvidenceCAOutputDirectory, BackupKEKOutputDirectory, CatalogCheckpointOutputDirectory string
}
type OriginalC1SigningInvocation struct {
	PreColdHead1Directory string
	Groups                *OriginalC1ReferenceGroups
	Version               string
	Domain                OriginalC1DomainInputs
	Channel               OriginalC1ChannelInputs
	Signing               OriginalC1SigningPipelineInputs
	CapacityDSN           BootstrapSourceFilePin
	CapacityTLS           mysqltls.Material
}

func DecodeOriginalC1SigningInvocation(raw []byte, digest string) (OriginalC1SigningInvocation, error) {
	var in OriginalC1SigningInvocation
	if hash(raw) != digest || decodeExact(raw, &in) != nil || (in.Version != "original-c1-signing-invocation.v1" && in.Version != "original-c1-current-references-invocation.v2") || in.CapacityTLS.Validate() != nil || !in.CapacityTLS.Selected() || in.Signing.Capacity.Validate() != nil {
		return in, ErrInstall
	}
	if in.Version == "original-c1-current-references-invocation.v2" {
		if in.Groups == nil || !bootstrapSourcePinValid(in.Groups.Six) || !bootstrapSourcePinValid(in.Groups.MinIO) || !bootstrapSourcePinValid(in.Groups.StatusRelay) || !bootstrapSourcePinValid(in.Groups.Nonce) || !bootstrapSourcePinValid(in.Groups.EvidenceCA) || !bootstrapSourcePinValid(in.Groups.BackupKEK) || !bootstrapSourcePinValid(in.Groups.CatalogCheckpoint) || privateDirectory(in.Groups.SixOutputDirectory) != nil || privateDirectory(in.Groups.MinIOOutputDirectory) != nil || privateDirectory(in.Groups.StatusRelayOutputDirectory) != nil || privateDirectory(in.Groups.NonceOutputDirectory) != nil || privateDirectory(in.Groups.EvidenceCAOutputDirectory) != nil || privateDirectory(in.Groups.BackupKEKOutputDirectory) != nil || privateDirectory(in.Groups.CatalogCheckpointOutputDirectory) != nil {
			return in, ErrInstall
		}
	} else if in.Groups != nil {
		return in, ErrInstall
	}
	return in, nil
}

// Capacity uses its own exact SELECT-only principal beside the actual MySQL
// volume. The collector itself checks native server_uuid/datadir/auto.cnf,
// own-account grants, complete pinned tables, DB bytes and actual statfs.
func (i *Installer) openOriginalC1Capacity(in OriginalC1SigningInvocation) (*sql.DB, error) {
	raw, err := readBootstrapSourcePin(in.CapacityDSN, 16384)
	if err != nil {
		return nil, ErrInstall
	}
	defer clear(raw)
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || cfg.Net != "tcp" || cfg.DBName != i.plan.Target.Database || cfg.User != in.Signing.Capacity.User || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext || cfg.TLSConfig != "" || cfg.TLS != nil || in.CapacityTLS.Apply(cfg) != nil {
		return nil, ErrInstall
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, ErrInstall
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// RunOriginalC1SigningProduction is called by the real CLI and can be called
// directly by the complete Go adoption invocation. Never call the CLI between
// this and adoption: retain its returned opaque source and SAME ctx in-process.
func (i *Installer) RunOriginalC1SigningProduction(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalC1SigningInvocation, issuerPrivate []byte) (*OriginalC1SigningProduction, error) {
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	capacityDB, err := i.openOriginalC1Capacity(in)
	if err != nil {
		return nil, err
	}
	defer capacityDB.Close()
	report, err := sec.CollectPinnedRegistrationCapacity(ctx, capacityDB, in.Signing.Capacity)
	if err != nil {
		return nil, ErrInstall
	}
	raw, err := canonical(report)
	if err != nil || writeNewFiles(in.Domain.OutputDirectory, map[string][]byte{"c1-capacity.before-domain.json": raw}) != nil {
		return nil, ErrInstall
	}
	in.Domain.CapacityReport = BootstrapSourceFilePin{File: filepath.Join(in.Domain.OutputDirectory, "c1-capacity.before-domain.json"), SHA256: hash(raw)}
	production, _, err := i.BeginOriginalC1Production(ctx, password, enrollment, in.Domain, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first, err := production.ProduceOriginalC1SigningWithNativeChannel(ctx, capacityDB, in.Channel, in.Signing, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	if in.Groups == nil {
		return first, nil
	}
	ok := false
	defer func() {
		if !ok {
			first.Close()
		}
	}()
	common := in.Signing
	// All groups use the SAME real channel/token pair and original producer;
	// no opaque handle/Prepared/claim crosses a JSON/process boundary.
	common.STSJWT = first.run.stsJWT
	common.AuthenticationJWT = first.run.authenticationJWT
	common.AuthenticationAudience = first.run.authenticationAudience
	common.OutputDirectory = in.Groups.SixOutputDirectory
	six, err := production.ProduceOriginalC1SixReferences(ctx, capacityDB, first.channel, common, in.Groups.Six, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, six)
	common.OutputDirectory = in.Groups.MinIOOutputDirectory
	five, err := production.ProduceOriginalC1MinIOReferences(ctx, capacityDB, first.channel, common, in.Groups.MinIO, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, five)
	common.OutputDirectory = in.Groups.StatusRelayOutputDirectory
	relay, err := production.ProduceOriginalC1StatusRelay(ctx, capacityDB, first.channel, common, in.Groups.StatusRelay, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, relay)
	common.OutputDirectory = in.Groups.NonceOutputDirectory
	nonceBatch, err := production.ProduceOriginalC1Nonce(ctx, capacityDB, first.channel, common, in.Groups.Nonce, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, nonceBatch)
	common.OutputDirectory = in.Groups.EvidenceCAOutputDirectory
	caBatch, err := production.ProduceOriginalC1EvidenceCA(ctx, capacityDB, first.channel, common, in.Groups.EvidenceCA, in.Groups.Six, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, caBatch)
	common.OutputDirectory = in.Groups.BackupKEKOutputDirectory
	kekBatch, err := production.ProduceOriginalC1BackupKEK(ctx, capacityDB, first.channel, common, in.Groups.BackupKEK, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, kekBatch)
	common.OutputDirectory = in.Groups.CatalogCheckpointOutputDirectory
	catalogBatch, err := production.ProduceOriginalC1CatalogCheckpoint(ctx, capacityDB, first.channel, common, in.Groups.CatalogCheckpoint, in.Groups.MinIO, password, issuerPrivate)
	if err != nil {
		return nil, err
	}
	first.children = append(first.children, catalogBatch)
	if _, err = first.CompleteOriginalSources(ctx); err != nil {
		return nil, err
	}
	if in.PreColdHead1Directory != "" {
		head1, err := first.ImportOriginalPreColdHead1(ctx, password, issuerPrivate, in.PreColdHead1Directory)
		if err != nil {
			return nil, err
		}
		first.head1 = &head1
	}
	ok = true
	return first, nil
}

type OriginalC1GroupTiming struct {
	Purposes                                        []string
	RunID                                           pd.ID
	EvidenceID                                      pd.EvidenceID
	NativeStartedAt, NativeUntil, ResultCommittedAt pd.Timestamp
}
type OriginalC1SigningStageReceipt struct {
	PreColdHead1                             *OriginalC1Head1Receipt
	GroupTiming                              []OriginalC1GroupTiming
	ReceiptSQLClock, MinimumObservationUntil pd.Timestamp
	ObservationsStillFreshAtReceipt          bool
	Version, State                           string
	Mapping, Signature                       BootstrapSourceFilePin
	ReferenceCount                           int
	Complete20, AdoptionCommitted, Enabled   bool
}

func (p *OriginalC1SigningProduction) StageReceipt(ctx context.Context) (OriginalC1SigningStageReceipt, error) {
	var zero OriginalC1SigningStageReceipt
	if _, err := p.OriginalSources(ctx); err != nil {
		return zero, err
	}
	count := len(p.selections)
	for _, child := range p.children {
		count += len(child.selections)
	}
	var server, database string
	var clock time.Time
	if p.run.parent.operator.installer.db.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &clock) != nil || server != string(p.run.parent.domain.Scope.ServerUUID) || database != string(p.run.parent.domain.Scope.Database) {
		return zero, ErrInstall
	}
	receipt := OriginalC1SigningStageReceipt{PreColdHead1: p.head1, Version: "original-c1-current-reference-stage-receipt.v2", State: "actual-native-reference-results-committed", Mapping: p.mapping, Signature: p.signature, ReferenceCount: count, Complete20: count == 20, ReceiptSQLClock: c1stamp(clock)}
	var minimum time.Time
	for _, batch := range append([]*OriginalC1SigningProduction{p}, p.children...) {
		r := batch.run
		timing := OriginalC1GroupTiming{RunID: r.command.Next.RunID, EvidenceID: r.command.Next.EvidenceID, NativeStartedAt: c1stamp(r.native.started), NativeUntil: r.observation.ExpiresAt, ResultCommittedAt: batch.committedAt}
		for _, ref := range r.native.references {
			timing.Purposes = append(timing.Purposes, ref.Purpose)
		}
		receipt.GroupTiming = append(receipt.GroupTiming, timing)
		until, err := r.observation.ExpiresAt.Time()
		if err != nil {
			return zero, ErrInstall
		}
		if minimum.IsZero() || until.Before(minimum) {
			minimum = until
		}
	}
	receipt.MinimumObservationUntil = c1stamp(minimum)
	receipt.ObservationsStillFreshAtReceipt = clock.Before(minimum)
	// Reporting only: no current bootstrap authentication/consumption is skipped
	// based on this bool. Its actual SQL transaction must check its own clock.
	return receipt, nil
}
