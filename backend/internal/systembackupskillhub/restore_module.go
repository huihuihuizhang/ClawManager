package systembackupskillhub

import (
	"context"
	"errors"
	"reflect"
	"regexp"
)

// RestoreBinding identifies a sealed source and isolated target. Hash syntax
// checks do NOT authenticate these claims; the mandatory authority adapters
// must bind them to trusted deployment state and the complete source/mapping.
type RestoreBinding struct {
	RegistrySHA256       string
	SchemaSHA256         string
	CheckpointSHA256     string
	CaptureContextSHA256 string
	ArtifactSHA256       string
	TargetIdentitySHA256 string
	EvidenceRef          string
}

// ReadLimits bounds total rows and total string payload bytes across all eight
// tables. Fixed-width model memory is additionally bounded by MaxRows.
// Mapping counts/strings are bounded separately before cloning. These limits
// must come from the frozen task configuration, not a browser request.
type ReadLimits struct {
	MaxRows           int64
	MaxPayloadBytes   int64
	MaxMappingEntries int64
	MaxMappingBytes   int64
}

// RestoreRequest is a local data-module input, not a public Runner wire DTO.
type RestoreRequest struct {
	Binding RestoreBinding
	Source  Rows
	Mapping RestoreMapping
	Limits  ReadLimits
}

// NormalizationAuthority is supplied by the restore coordinator. Verify must
// authenticate source completeness (including empty tables), frozen registry,
// sealed artifact/checkpoint, the exact mapping/limits and target isolation/startup
// fence/write authority. Recheck validates that SAME authority again. The SQL
// writer must separately fence its own transaction at commit; candidate rows
// from Normalize never confer SQL authority.
type NormalizationAuthority interface {
	VerifyNormalization(context.Context, RestoreRequest) error
	RecheckNormalization(context.Context, RestoreRequest) error
}
type Normalizer struct{ Authority NormalizationAuthority }

var (
	ErrRestoreAuthority = errors.New("skill hub restore authority unavailable")
	ErrTargetRead       = errors.New("skill hub restore target read failed")
)
var evidenceIDPattern = regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`)

// Normalize freezes the caller's inputs before invoking any external adapter.
// Adapters receive private copies; their mutations cannot change expectations.
func (n Normalizer) Normalize(ctx context.Context, request RestoreRequest) (Rows, error) {
	var empty Rows
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if nilObjectAdapter(n.Authority) {
		return empty, ErrRestoreAuthority
	}
	frozen, err := freezeRestoreRequest(ctx, request)
	if err != nil {
		return empty, err
	}
	if err := n.Authority.VerifyNormalization(ctx, cloneRestoreRequest(frozen)); err != nil {
		return empty, restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	rows, err := PrepareRestoreRows(ctx, frozen.Source, frozen.Mapping)
	if err != nil {
		return empty, err
	}
	if err := checkRowsCapacity(ctx, rows, frozen.Limits); err != nil {
		return empty, err
	}
	if err := n.Authority.RecheckNormalization(ctx, cloneRestoreRequest(frozen)); err != nil {
		return empty, restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return rows, nil
}
func freezeRestoreRequest(ctx context.Context, r RestoreRequest) (RestoreRequest, error) {
	b := r.Binding
	for _, hash := range []string{b.RegistrySHA256, b.SchemaSHA256, b.CheckpointSHA256, b.CaptureContextSHA256, b.ArtifactSHA256, b.TargetIdentitySHA256} {
		if !validSHA256(hash) {
			return RestoreRequest{}, ErrRestoreAuthority
		}
	}
	if len(b.EvidenceRef) > 256 || !evidenceIDPattern.MatchString(b.EvidenceRef) {
		return RestoreRequest{}, ErrRestoreAuthority
	}
	if r.Limits.MaxRows <= 0 || r.Limits.MaxPayloadBytes < 0 || r.Limits.MaxMappingEntries < 0 || r.Limits.MaxMappingBytes < 0 {
		return RestoreRequest{}, ErrCapacity
	}
	if err := checkRowsCapacity(ctx, r.Source, r.Limits); err != nil {
		return RestoreRequest{}, err
	}
	if err := checkMappingCapacity(ctx, r.Mapping, r.Limits); err != nil {
		return RestoreRequest{}, err
	}
	if err := ValidateRows(ctx, r.Source); err != nil {
		return RestoreRequest{}, err
	}
	if err := validateMapping(ctx, r.Source, r.Mapping); err != nil {
		return RestoreRequest{}, err
	}
	return cloneRestoreRequest(r), nil
}
func cloneRestoreRequest(in RestoreRequest) RestoreRequest {
	out := in
	out.Source = cloneRows(in.Source)
	out.Mapping.IDs = make(map[string]map[int]int, len(in.Mapping.IDs))
	for table, ids := range in.Mapping.IDs {
		copyIDs := make(map[int]int, len(ids))
		for a, b := range ids {
			copyIDs[a] = b
		}
		out.Mapping.IDs[table] = copyIDs
	}
	out.Mapping.ObjectKeys = make(map[string]string, len(in.Mapping.ObjectKeys))
	for a, b := range in.Mapping.ObjectKeys {
		out.Mapping.ObjectKeys[a] = b
	}
	out.Mapping.BindingPaths = make(map[int]BindingPaths, len(in.Mapping.BindingPaths))
	for id, p := range in.Mapping.BindingPaths {
		out.Mapping.BindingPaths[id] = BindingPaths{InstallPath: cloneString(p.InstallPath), WorkspaceDir: cloneString(p.WorkspaceDir)}
	}
	out.Mapping.JobWorkspaceDirs = make(map[int]string, len(in.Mapping.JobWorkspaceDirs))
	for id, p := range in.Mapping.JobWorkspaceDirs {
		out.Mapping.JobWorkspaceDirs[id] = p
	}
	return out
}
func checkRowsCapacity(ctx context.Context, r Rows, limit ReadLimits) error {
	var count, bytes int64
	for _, table := range tables(r) {
		n := int64(table.rows.Len())
		if n > limit.MaxRows-count {
			return ErrCapacity
		}
		count += n
		for i := 0; i < table.rows.Len(); i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			row := table.rows.Index(i)
			for j := 0; j < row.NumField(); j++ {
				field := row.Field(j)
				if field.Kind() == reflect.Pointer {
					if field.IsNil() {
						continue
					}
					field = field.Elem()
				}
				if field.Kind() == reflect.String {
					n := int64(len(field.String()))
					if n > limit.MaxPayloadBytes-bytes {
						return ErrCapacity
					}
					bytes += n
				}
			}
		}
	}
	return ctx.Err()
}
func checkMappingCapacity(ctx context.Context, m RestoreMapping, limit ReadLimits) error {
	var entries, payload int64
	add := func(n int, bytes int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if int64(n) > limit.MaxMappingEntries-entries || bytes > limit.MaxMappingBytes-payload {
			return ErrCapacity
		}
		entries += int64(n)
		payload += bytes
		return nil
	}
	// Closed table names are checked before copying; unknown names never reach SQL.
	if len(m.IDs) != 10 {
		return ErrMapping
	}
	for name, ids := range m.IDs {
		if knownTable(name) == "unknown_table" {
			return ErrMapping
		}
		if err := add(len(ids), 0); err != nil {
			return err
		}
	}
	for key, value := range m.ObjectKeys {
		if err := add(1, int64(len(key))+int64(len(value))); err != nil {
			return err
		}
	}
	for _, p := range m.BindingPaths {
		var bytes int64
		if p.InstallPath != nil {
			bytes += int64(len(*p.InstallPath))
		}
		if p.WorkspaceDir != nil {
			bytes += int64(len(*p.WorkspaceDir))
		}
		if err := add(1, bytes); err != nil {
			return err
		}
	}
	for _, p := range m.JobWorkspaceDirs {
		if err := add(1, int64(len(p))); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func restoreFailure(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// SQL/proof errors can contain credentials, connection strings and row data.
	return fallback
}
