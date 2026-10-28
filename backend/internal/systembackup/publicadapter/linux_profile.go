package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	d "clawreef/internal/systembackupdispatch"
)

type InstanceIdentity = domain.SourceInstance
type SourceInventory struct {
	Database, ServerUUID string
	Users                []int
	Instances            []InstanceIdentity
}

func cloneSourceInventory(in SourceInventory) SourceInventory {
	in.Users = append([]int(nil), in.Users...)
	in.Instances = append([]InstanceIdentity(nil), in.Instances...)
	return in
}

type AgentKind struct{ Type, Mode, Variant, OS string }

// LinuxProfile uses only an existing SELECT-only source connection and concrete
// writer/Job builders. A supplies the connection identity; D supplies the
// admitted mapping. Builders assemble handles/specs, never dispatch resources.
// Runtime Agent, kubernetes/dynamic clients and CRI/NFS Proof clients belong to
// these explicit builders; no private Driver, SQLStore or Vault is accepted.
type LinuxProfileConfig struct {
	// RecoveryOnly binds the original frozen plan without source discovery.
	// It cannot produce a fresh source inventory or authorize another capture.
	RecoveryOnly         bool
	Source               *sql.DB
	Database, ServerUUID string
	Supported            map[AgentKind]bool
	HoldLimit            time.Duration
	BuildWriters         func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error)
	BuildParts           func(d.Input, SourceInventory, time.Time) ([]JobPart, error)
}
type LinuxProfile struct{ cfg LinuxProfileConfig }

func NewLinuxProfile(cfg LinuxProfileConfig) (*LinuxProfile, error) {
	if (cfg.Source == nil && !cfg.RecoveryOnly) || cfg.Database == "" || cfg.ServerUUID == "" || len(cfg.Supported) == 0 || cfg.HoldLimit <= 0 || cfg.HoldLimit > time.Hour || cfg.BuildWriters == nil || cfg.BuildParts == nil {
		return nil, d.ErrNotReady
	}
	copyKinds := map[AgentKind]bool{}
	for k, v := range cfg.Supported {
		if !strings.EqualFold(k.OS, "linux") || strings.EqualFold(k.Variant, "windows") || k.Type == "" || k.Mode == "" {
			return nil, d.ErrNotReady
		}
		copyKinds[k] = v
	}
	cfg.Supported = copyKinds
	return &LinuxProfile{cfg}, nil
}

func (p *LinuxProfile) inventory(ctx context.Context) (SourceInventory, error) {
	var out SourceInventory
	if p.cfg.RecoveryOnly || p.cfg.Source == nil {
		return out, d.ErrNotReady
	}
	tx, err := p.cfg.Source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return out, d.ErrNotReady
	}
	defer tx.Rollback()
	if tx.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&out.Database, &out.ServerUUID) != nil || out.Database != p.cfg.Database || out.ServerUUID != p.cfg.ServerUUID {
		return out, d.ErrNotReady
	}
	rows, err := tx.QueryContext(ctx, "SELECT id FROM users ORDER BY id")
	if err != nil {
		return out, d.ErrNotReady
	}
	users := map[int]bool{}
	for rows.Next() {
		var id int
		if rows.Scan(&id) != nil || id <= 0 || users[id] || len(users) >= 100000 {
			rows.Close()
			return out, d.ErrNotReady
		}
		users[id] = true
		out.Users = append(out.Users, id)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil || len(users) == 0 {
		return out, d.ErrNotReady
	}
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return out, d.ErrNotReady
	}
	seen := map[int]bool{}
	for _, i := range instances {
		if i.ID <= 0 || seen[i.ID] || !users[i.UserID] || len(seen) >= 9998 || !p.cfg.Supported[AgentKind{i.Type, i.Mode, i.Variant, i.OS}] {
			return out, d.ErrNotReady
		}
		seen[i.ID] = true
		out.Instances = append(out.Instances, i)
	}
	if ctx.Err() != nil {
		return out, d.ErrNotReady
	}
	// Read-only rollback ends the snapshot; this component never runs source DDL
	// or commits a control transaction, nor does it read password/secret columns.
	return out, nil
}

func (p *LinuxProfile) Discover(ctx context.Context, in d.Input) (Discovery, error) {
	var out Discovery
	inv, err := p.inventory(ctx)
	if err != nil {
		return out, err
	}
	encoded, err := json.Marshal(inv)
	if err != nil {
		return out, d.ErrNotReady
	}
	out.Source = encoded
	out.SourceSHA256 = digest(encoded)
	out.HoldUntil = time.Now().UTC().Add(p.cfg.HoldLimit)
	if out.HoldUntil.After(in.Authority.DeadlineAt) {
		out.HoldUntil = in.Authority.DeadlineAt.UTC()
	}
	out.Parts, err = p.cfg.BuildParts(cloneInput(in), cloneSourceInventory(inv), out.HoldUntil)
	if err != nil {
		return Discovery{}, classify(err)
	}
	out.Writers = []FrozenWriter{}
	if in.Authority.TaskType == "backup" {
		writers, err := p.cfg.BuildWriters(ctx, cloneInput(in), cloneSourceInventory(inv), nil)
		if err != nil {
			return Discovery{}, classify(err)
		}
		for _, w := range writers {
			if nilValue(w) {
				return Discovery{}, d.ErrNotReady
			}
			s, err := w.Observe(ctx)
			if err != nil {
				return Discovery{}, classify(err)
			}
			out.Writers = append(out.Writers, FrozenWriter{w.ID(), s})
		}
	}
	return out, nil
}

func (p *LinuxProfile) BindWriters(ctx context.Context, in d.Input, x Discovery) ([]flow.Writer, error) {
	var inv SourceInventory
	if digest(x.Source) != x.SourceSHA256 || decodeStrict(x.Source, &inv) != nil || inv.Database != p.cfg.Database || inv.ServerUUID != p.cfg.ServerUUID {
		return nil, d.ErrNotReady
	}
	// Bind uses ONLY frozen source data. No SQL discovery or new UID allocation.
	return p.cfg.BuildWriters(ctx, cloneInput(in), cloneSourceInventory(inv), append([]FrozenWriter(nil), x.Writers...))
}

func (p *LinuxProfile) Preflight(ctx context.Context, in d.Input, x Discovery) ([]d.ModuleResult, error) {
	if err := p.CheckSource(ctx, in, x); err != nil {
		return nil, err
	}
	var current SourceInventory
	if decodeStrict(x.Source, &current) != nil {
		return nil, d.ErrNotReady
	}
	out := make([]d.ModuleResult, 0, len(x.Parts))
	for _, part := range x.Parts {
		checkpoint, _ := json.Marshal(map[string]string{"schema_version": "system-backup-b-source-preflight.v1", "inventory_sha256": x.SourceSHA256})
		out = append(out, d.ModuleResult{SchemaVersion: "system-backup-part-result.v1", Part: part.Part, Category: part.Category, Status: "completed", Checkpoint: checkpoint, Statistics: map[string]uint64{"users": uint64(len(current.Users)), "instances": uint64(len(current.Instances))}, Warnings: []d.Warning{}, EvidenceIDs: []string{}, FailureCategory: "none"})
	}
	return out, nil
}

func (p *LinuxProfile) CheckSource(ctx context.Context, _ d.Input, x Discovery) error {
	current, err := p.inventory(ctx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(current)
	if err != nil || digest(raw) != x.SourceSHA256 {
		return &Failure{"coordination_invalid"}
	}
	return nil
}
