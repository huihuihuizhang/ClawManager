package domain

import (
	"clawreef/internal/systembackup/schemaobjects"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
)

type BusinessCaptureSchema struct {
	Version                    string `json:"schema_version"`
	PolicySHA256, SchemaSHA256 string
	Tables                     []string
}

const BusinessCaptureSchemaVersion = "reviewed-business-capture-schema.v1"

func BusinessCapturePolicySHA256() string {
	raw, _ := json.Marshal(struct {
		Rules  any
		Census string
	}{rules(), SchemaCensusPolicySHA256()})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func (s BusinessCaptureSchema) Validate() error {
	if s.Version != BusinessCaptureSchemaVersion || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(s.PolicySHA256) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(s.SchemaSHA256) || len(s.Tables) < 1 || len(s.Tables) > 1000 {
		return ErrSchema
	}
	allowed := map[string]bool{}
	for _, n := range BusinessCaptureTables() {
		allowed[n] = true
	}
	for i, n := range s.Tables {
		if !allowed[n] || (i > 0 && s.Tables[i-1] >= n) {
			return ErrSchema
		}
	}
	optional := map[string]bool{}
	for _, n := range schemaobjects.OptionalBusinessTables() {
		optional[n] = true
	}
	selected := map[string]bool{}
	for _, n := range s.Tables {
		selected[n] = true
	}
	for name := range allowed {
		if !optional[name] && !selected[name] {
			return ErrSchema
		}
	}
	return nil
}

// This projection contains no rows. The actual original Invocation/plan/context
// freezes this independently observed full-census/schema identity for readback.
func ObserveBusinessCaptureSchema(ctx context.Context, q schemaCensusReader, spec SchemaCensusSpec) (BusinessCaptureSchema, error) {
	if CheckBusinessSchemaCensus(ctx, q, spec) != nil {
		return BusinessCaptureSchema{}, ErrSchema
	}
	tables, err := Catalog(ctx, q)
	if err != nil {
		return BusinessCaptureSchema{}, err
	}
	schema, err := BusinessCaptureSchemaForTables(tables)
	if err != nil {
		return BusinessCaptureSchema{}, err
	}
	if CheckBusinessSchemaCensus(ctx, q, spec) != nil {
		return BusinessCaptureSchema{}, ErrSchema
	}
	return schema, nil
}

func BusinessCaptureSchemaForTables(tables []Table) (BusinessCaptureSchema, error) {
	frozen := append([]Table{}, tables...)
	sort.Slice(frozen, func(i, j int) bool { return frozen[i].Name < frozen[j].Name })
	allowed := map[string]bool{}
	for _, n := range BusinessCaptureTables() {
		allowed[n] = true
	}
	s := BusinessCaptureSchema{Version: BusinessCaptureSchemaVersion, PolicySHA256: BusinessCapturePolicySHA256(), Tables: []string{}}
	for i := range frozen {
		if !allowed[frozen[i].Name] || (i > 0 && frozen[i-1].Name == frozen[i].Name) {
			return BusinessCaptureSchema{}, ErrSchema
		}
		s.Tables = append(s.Tables, frozen[i].Name)
		frozen[i].Rows = nil
	}
	raw, err := json.Marshal(frozen)
	if err != nil || len(raw) > 8<<20 {
		return BusinessCaptureSchema{}, ErrCapacity
	}
	h := sha256.Sum256(raw)
	s.SchemaSHA256 = hex.EncodeToString(h[:])
	return s, s.Validate()
}

func VerifyBusinessCapturedSnapshot(snapshot Snapshot, expected BusinessCaptureSchema) error {
	if expected.Validate() != nil || validateSnapshot(snapshot) != nil {
		return ErrSchema
	}
	actual, err := BusinessCaptureSchemaForTables(snapshot.Tables)
	if err != nil || actual.PolicySHA256 != expected.PolicySHA256 || actual.SchemaSHA256 != expected.SchemaSHA256 || len(actual.Tables) != len(expected.Tables) {
		return ErrSchema
	}
	for i := range actual.Tables {
		if actual.Tables[i] != expected.Tables[i] {
			return ErrSchema
		}
	}
	return nil
}
