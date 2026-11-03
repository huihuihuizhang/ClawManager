package systembackupkekadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	reg "clawreef/internal/systembackupkekregistry"
)

var ErrOriginalHistoryNeedsClassification = errors.New("original history nonempty, unknown or changed; original classification required")

// These are original deployment-owner scanners, not page JSON or a new index.
// D must bind this complete scope set (including Additional original sources)
// to its actual retained writer fence. This collector cannot establish that
// global protection or substitute for all16 witnesses/independent adoption.
type OriginalEmptyHistoryScopes struct {
	Artifact, Staging, Catalog *S3CoverageCensus
	Additional                 []*S3CoverageCensus
}
type UnadmittedEmptyOriginalHistory struct {
	sql      SQLCoverageCensusFacts
	external []S3CoverageCensusFacts
}

func (*UnadmittedEmptyOriginalHistory) MarshalJSON() ([]byte, error) {
	return nil, ErrOriginalHistoryNeedsClassification
}

func emptyOriginalSources(sql SQLCoverageCensusFacts, external []S3CoverageCensusFacts) error {
	if len(sql.Tables) == 0 || len(external) < 3 {
		return ErrOriginalHistoryNeedsClassification
	}
	for _, table := range sql.Tables {
		if table.Table == "" || table.Rows != 0 || table.Bytes != 0 {
			return ErrOriginalHistoryNeedsClassification
		}
	}
	seen := map[string]bool{}
	for _, source := range external {
		identity, _ := json.Marshal(source.Scope)
		if seen[string(identity)] || !authoritySource(source.Source) || source.ObservedAt.IsZero() || len(source.Members) != 0 {
			return ErrOriginalHistoryNeedsClassification
		}
		seen[string(identity)] = true
		members, _ := json.Marshal([]S3CoverageMember{})
		if source.MembersSHA256 != emptyHistoryBytesSHA(members) {
			return ErrOriginalHistoryNeedsClassification
		}
		ended := map[string]bool{}
		next := map[string][2]string{}
		for _, page := range source.Pages {
			if (page.Kind != "versions" && page.Kind != "uploads") || ended[page.Kind] || page.Entries != 0 || !authorityHash.MatchString(page.PayloadSHA256) || next[page.Kind] != [2]string{page.KeyMarker, page.TokenMarker} {
				return ErrOriginalHistoryNeedsClassification
			}
			if page.Truncated {
				return ErrOriginalHistoryNeedsClassification
			} // empty truncated page is not EOF
			if page.NextKeyMarker != "" || page.NextTokenMarker != "" {
				return ErrOriginalHistoryNeedsClassification
			}
			ended[page.Kind] = true
		}
		if !ended["versions"] || !ended["uploads"] {
			return ErrOriginalHistoryNeedsClassification
		}
	}
	return nil
}

// CollectEmptyOriginalHistory executes FULL original SQL and every configured
// native versions/delete-marker/MPU census twice. It has a legal zero branch:
// no historical body/sample/legacy decoder is requested when those scans prove
// no members. Nonempty/unknown/partial/changed sources never become released.
// Result is deliberately UNADMITTED: same retained global cut, other native
// source universes and issuer authentication remain D/A original responsibilities.
func CollectEmptyOriginalHistory(ctx context.Context, sql *SQLCoverageCensus, scopes OriginalEmptyHistoryScopes) (*UnadmittedEmptyOriginalHistory, error) {
	if ctx == nil || sql == nil || scopes.Artifact == nil || scopes.Staging == nil || scopes.Catalog == nil {
		return nil, ErrOriginalHistoryNeedsClassification
	}
	scanners := append([]*S3CoverageCensus{scopes.Artifact, scopes.Staging, scopes.Catalog}, scopes.Additional...)
	first, err := sql.Observe(ctx)
	if err != nil {
		return nil, err
	}
	external := make([]S3CoverageCensusFacts, 0, len(scanners))
	for _, scanner := range scanners {
		if scanner == nil {
			return nil, ErrOriginalHistoryNeedsClassification
		}
		observed, e := scanner.Observe(ctx)
		if e != nil {
			return nil, e
		}
		external = append(external, observed.Facts())
	}
	if err = emptyOriginalSources(first.Facts(), external); err != nil {
		return nil, err
	}
	// Recheck source drift, not a claim that double scans themselves are a fence.
	second, err := sql.Observe(ctx)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(first.Facts().Tables, second.Facts().Tables) {
		return nil, ErrOriginalHistoryNeedsClassification
	}
	for index, scanner := range scanners {
		observed, e := scanner.Observe(ctx)
		if e != nil {
			return nil, e
		}
		actual := observed.Facts()
		prior := external[index]
		if !reflect.DeepEqual(actual.Scope, prior.Scope) || actual.Source != prior.Source || actual.MembersSHA256 != prior.MembersSHA256 || !reflect.DeepEqual(actual.Pages, prior.Pages) {
			return nil, ErrOriginalHistoryNeedsClassification
		}
		external[index] = actual
	}
	if err = emptyOriginalSources(second.Facts(), external); err != nil {
		return nil, err
	}
	return &UnadmittedEmptyOriginalHistory{sql: second.Facts(), external: external}, nil
}

// EmptyReferences returns DATA, never PreparedCoverage/backfill permission.
// Nil/failed collectors cannot supply a purported empty reference set.
func (o *UnadmittedEmptyOriginalHistory) EmptyReferences() ([]reg.Reference, error) {
	if o == nil || emptyOriginalSources(o.sql, o.external) != nil {
		return nil, ErrOriginalHistoryNeedsClassification
	}
	return []reg.Reference{}, nil
}

func emptyHistoryBytesSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
