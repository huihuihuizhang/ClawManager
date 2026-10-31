package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

type InstanceIdentity = domain.SourceInstance
type SourceInventory struct {
	Database, ServerUUID string
	Users                []int
	Instances            []InstanceIdentity
	Teams                *team.Inventory `json:"Teams,omitempty"`
}

func cloneSourceInventory(in SourceInventory) SourceInventory {
	in.Users = append([]int(nil), in.Users...)
	in.Instances = append([]InstanceIdentity(nil), in.Instances...)
	in.Teams = team.CloneInventory(in.Teams)
	return in
}

type AgentKind struct{ Type, Mode, Variant, OS string }

// LinuxProfile uses only an existing SELECT-only source connection and concrete
// writer/Job builders. A supplies the connection identity; D supplies the
// admitted mapping. Builders assemble handles/specs, never dispatch resources.
// Runtime Agent, kubernetes/dynamic clients and CRI/NFS Proof clients belong to
// these explicit builders; no private Driver, SQLStore or Vault is accepted.
type LinuxProfileConfig struct {
	// VerifySource checks the actual discovery transaction before and after
	// reading inventory. It must not commit or roll back the transaction.
	VerifySource func(context.Context, *sql.Tx) error
	// Optional C reader shares this exact authenticated SQL snapshot. A nil
	// reader preserves historical user/instance plans and cannot enable Teams.
	ReadTeams func(context.Context, *sql.Tx, SourceInventory) (*team.Inventory, error)
	// RecoveryOnly binds the original frozen plan without source discovery.
	// It cannot produce a fresh source inventory or authorize another capture.
	RecoveryOnly         bool
	Source               *sql.DB
	Database, ServerUUID string
	Supported            map[AgentKind]bool
	HoldLimit            time.Duration
	BuildWriters         func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error)
	BuildParts           func(d.Input, SourceInventory, time.Time) ([]JobPart, error)
	// Optional original-writer-aware factory. Discover takes and validates ONE
	// writer snapshot before calling it; invocation/header and plan share it.
	BuildPartsWithWriters func(d.Input, SourceInventory, time.Time, []FrozenWriter) ([]JobPart, error)
}
type LinuxProfile struct{ cfg LinuxProfileConfig }

func NewLinuxProfile(cfg LinuxProfileConfig) (*LinuxProfile, error) {
	if (cfg.Source == nil && !cfg.RecoveryOnly) || cfg.Database == "" || cfg.ServerUUID == "" || len(cfg.Supported) == 0 || cfg.HoldLimit <= 0 || cfg.HoldLimit > time.Hour || cfg.BuildWriters == nil || (cfg.BuildParts == nil && cfg.BuildPartsWithWriters == nil) {
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
	if p.cfg.VerifySource != nil && p.cfg.VerifySource(ctx, tx) != nil {
		return SourceInventory{}, d.ErrNotReady
	}
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
	if p.cfg.ReadTeams != nil {
		out.Teams, err = p.cfg.ReadTeams(ctx, tx, cloneSourceInventory(out))
		owners := map[int]int{}
		for _, instance := range out.Instances {
			owners[instance.ID] = instance.UserID
		}
		if err != nil || out.Teams == nil || out.Teams.Validate(users, owners) != nil {
			return SourceInventory{}, d.ErrNotReady
		}
		out.Teams = team.CloneInventory(out.Teams)
	}
	if ctx.Err() != nil || (p.cfg.VerifySource != nil && p.cfg.VerifySource(ctx, tx) != nil) {
		return SourceInventory{}, d.ErrNotReady
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
	if p.cfg.BuildPartsWithWriters == nil {
		out.Parts, err = p.cfg.BuildParts(cloneInput(in), cloneSourceInventory(inv), out.HoldUntil)
		if err != nil {
			return Discovery{}, classify(err)
		}
	}
	out.Writers = []FrozenWriter{}
	seen := map[string]bool{}
	if in.Authority.TaskType == "backup" {
		writers, err := p.cfg.BuildWriters(ctx, cloneInput(in), cloneSourceInventory(inv), nil)
		if err != nil {
			return Discovery{}, classify(err)
		}
		for _, w := range writers {
			if nilValue(w) {
				return Discovery{}, d.ErrNotReady
			}
			if w.ID() == "" || seen[w.ID()] || len(out.Writers) >= 10000 {
				return Discovery{}, d.ErrNotReady
			}
			s, err := w.Observe(ctx)
			if err != nil {
				return Discovery{}, classify(err)
			}
			if s.UID == "" || s.Generation <= 0 {
				return Discovery{}, d.ErrNotReady
			}
			seen[w.ID()] = true
			out.Writers = append(out.Writers, FrozenWriter{w.ID(), s})
		}
	}
	if p.cfg.BuildPartsWithWriters != nil {
		out.Parts, err = p.cfg.BuildPartsWithWriters(cloneInput(in), cloneSourceInventory(inv), out.HoldUntil, append([]FrozenWriter{}, out.Writers...))
		if err != nil {
			return Discovery{}, classify(err)
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
