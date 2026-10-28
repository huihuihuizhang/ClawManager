package systembackupbusinessa

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"
)

// GatewayAliasRestoreSource covers all migration-038 SQL columns. A keeps the
// historical SHA-256 token hash for audit, but never receives a plaintext token.
type GatewayAliasRestoreSource struct {
	ID         int64
	InstanceID int
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
}

type GatewayAliasRestoreMapping struct {
	SourceID int64
	TargetID int64
}

// GatewayAliasInstanceMapping comes from B's independently approved instances
// restore. A cannot infer target IDs from its own alias table.
type GatewayAliasInstanceMapping struct {
	SourceID int
	TargetID int
}

type NormalizedGatewayAlias struct {
	ID         int64
	InstanceID int
	TokenHash  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
	LastUsedAt *time.Time
}

// GatewayAliasRestoreProofVerifier belongs to B. It must authenticate the
// source dump, both ID mappings, target DB UTC clock, registered evidence and
// the B-owned target instances.access_token clear before A returns alias rows.
// The proof must cover an empty alias table as well.
type GatewayAliasRestoreProofVerifier interface {
	VerifyGatewayAliasRestore(context.Context, string, string, string,
		[]GatewayAliasRestoreSource, []GatewayAliasRestoreMapping,
		[]GatewayAliasInstanceMapping, time.Time) error
}

var ErrGatewayAliasRestore = errors.New("A gateway token alias restore normalization failed")

// NormalizeGatewayAliasesForRestore expires every alias before the target DB
// clock and remaps its B-owned instance FK. B still owns the actual SQL write,
// target uniqueness and direct-token revocation in instances.access_token.
func NormalizeGatewayAliasesForRestore(ctx context.Context, scope *CaptureScope,
	sources []GatewayAliasRestoreSource, mappings []GatewayAliasRestoreMapping,
	instances []GatewayAliasInstanceMapping, targetNow time.Time, evidenceRef string,
	proof GatewayAliasRestoreProofVerifier) ([]NormalizedGatewayAlias, error) {
	cutoff := targetNow.UTC().Truncate(time.Second).Add(-time.Second)
	if ctx == nil || ctx.Err() != nil || scope == nil || len(scope.tables) != len(tables) ||
		!hashPattern.MatchString(scope.registrySHA) || !hashPattern.MatchString(scope.schemaSHA) ||
		!evidencePattern.MatchString(evidenceRef) || len(sources) != len(mappings) ||
		!validMySQLDateTime(cutoff) {
		return nil, ErrGatewayAliasRestore
	}
	if nilGatewayAliasProof(proof) {
		return nil, ErrCaptureEvidenceIncomplete
	}
	projection := cloneGatewayAliasSources(sources)
	instanceBySource := make(map[int]int, len(instances))
	seenTargetInstances := make(map[int]struct{}, len(instances))
	for _, mapping := range instances {
		if mapping.SourceID <= 0 || mapping.SourceID > math.MaxInt32 ||
			mapping.TargetID <= 0 || mapping.TargetID > math.MaxInt32 {
			return nil, ErrGatewayAliasRestore
		}
		if _, duplicate := instanceBySource[mapping.SourceID]; duplicate {
			return nil, ErrGatewayAliasRestore
		}
		if _, duplicate := seenTargetInstances[mapping.TargetID]; duplicate {
			return nil, ErrGatewayAliasRestore
		}
		instanceBySource[mapping.SourceID] = mapping.TargetID
		seenTargetInstances[mapping.TargetID] = struct{}{}
	}
	aliasBySource := make(map[int64]GatewayAliasRestoreMapping, len(mappings))
	seenTargetAliases := make(map[int64]struct{}, len(mappings))
	for _, mapping := range mappings {
		if mapping.SourceID <= 0 || mapping.TargetID <= 0 {
			return nil, ErrGatewayAliasRestore
		}
		if _, duplicate := aliasBySource[mapping.SourceID]; duplicate {
			return nil, ErrGatewayAliasRestore
		}
		if _, duplicate := seenTargetAliases[mapping.TargetID]; duplicate {
			return nil, ErrGatewayAliasRestore
		}
		aliasBySource[mapping.SourceID] = mapping
		seenTargetAliases[mapping.TargetID] = struct{}{}
	}
	rows := make([]NormalizedGatewayAlias, 0, len(projection))
	seenSources := make(map[int64]struct{}, len(projection))
	seenHashes := make(map[string]struct{}, len(projection))
	for _, source := range projection {
		mapping, found := aliasBySource[source.ID]
		targetInstance, instanceFound := instanceBySource[source.InstanceID]
		if !found || !instanceFound {
			return nil, ErrGatewayAliasRestore
		}
		if _, duplicate := seenSources[source.ID]; duplicate {
			return nil, ErrGatewayAliasRestore
		}
		if _, duplicate := seenHashes[source.TokenHash]; duplicate {
			return nil, ErrGatewayAliasRestore
		}
		row, err := NormalizeGatewayAliasForRestore(source, mapping, targetInstance, targetNow)
		if err != nil {
			return nil, err
		}
		seenSources[source.ID] = struct{}{}
		seenHashes[source.TokenHash] = struct{}{}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	if err := proof.VerifyGatewayAliasRestore(ctx, scope.registrySHA, scope.schemaSHA,
		evidenceRef, cloneGatewayAliasSources(projection),
		append([]GatewayAliasRestoreMapping(nil), mappings...),
		append([]GatewayAliasInstanceMapping(nil), instances...), targetNow); err != nil {
		return nil, fmt.Errorf("A gateway token alias source proof: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

// NormalizeGatewayAliasForRestore is only a pure row transform. A production
// batch uses the proof-gated entry above, not an unauthenticated single row.
func NormalizeGatewayAliasForRestore(source GatewayAliasRestoreSource,
	mapping GatewayAliasRestoreMapping, targetInstance int,
	targetNow time.Time) (NormalizedGatewayAlias, error) {
	cutoff := targetNow.UTC().Truncate(time.Second).Add(-time.Second)
	created := source.CreatedAt.UTC().Truncate(time.Second)
	updated := source.UpdatedAt.UTC().Truncate(time.Second)
	if source.ID <= 0 || source.InstanceID <= 0 || source.InstanceID > math.MaxInt32 ||
		mapping.SourceID != source.ID || mapping.TargetID <= 0 ||
		targetInstance <= 0 || targetInstance > math.MaxInt32 ||
		!lowerHexSHA256(source.TokenHash) || !validMySQLDateTime(source.ExpiresAt.UTC()) ||
		!validMySQLDateTime(created) || !validMySQLDateTime(updated) ||
		!validMySQLDateTime(cutoff) || updated.Before(created) {
		return NormalizedGatewayAlias{}, ErrGatewayAliasRestore
	}
	var lastUsed *time.Time
	if source.LastUsedAt != nil {
		value := source.LastUsedAt.UTC().Truncate(time.Second)
		if !validMySQLDateTime(value) || value.After(updated) {
			return NormalizedGatewayAlias{}, ErrGatewayAliasRestore
		}
		lastUsed = &value
	}
	return NormalizedGatewayAlias{
		ID: mapping.TargetID, InstanceID: targetInstance,
		TokenHash: source.TokenHash, ExpiresAt: cutoff,
		CreatedAt: created, UpdatedAt: updated, LastUsedAt: lastUsed,
	}, nil
}

func cloneGatewayAliasSources(sources []GatewayAliasRestoreSource) []GatewayAliasRestoreSource {
	result := append([]GatewayAliasRestoreSource(nil), sources...)
	for i := range result {
		if result[i].LastUsedAt != nil {
			value := *result[i].LastUsedAt
			result[i].LastUsedAt = &value
		}
	}
	return result
}

func nilGatewayAliasProof(proof GatewayAliasRestoreProofVerifier) bool {
	if proof == nil {
		return true
	}
	value := reflect.ValueOf(proof)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
