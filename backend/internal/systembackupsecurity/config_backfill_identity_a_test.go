package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type backfillIdentityVector struct {
	Kind, Name, OriginalCanonical, Canonical, SHA256 string
	Facts                                            json.RawMessage
}

func backfillIdentityVectors(t *testing.T) []backfillIdentityVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/config_backfill_identity_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Profile string
		Vectors []struct {
			Kind, Name, Canonical, SHA256 string
			Original                      string `json:"original_canonical"`
			Facts                         json.RawMessage
		}
	}
	if json.Unmarshal(raw, &file) != nil || file.Profile != "a-config-canonical-backfill-identities.v1" || len(file.Vectors) != 7 {
		t.Fatal("invalid independent identity vectors")
	}
	var out []backfillIdentityVector
	for _, v := range file.Vectors {
		out = append(out, backfillIdentityVector{v.Kind, v.Name, v.Original, v.Canonical, v.SHA256, v.Facts})
	}
	return out
}

func backfillIdentityRowFixture(t *testing.T) (ConfigBackfillRowFacts, []byte) {
	t.Helper()
	v := backfillIdentityVectors(t)[0]
	var f ConfigBackfillRowFacts
	if json.Unmarshal(v.Facts, &f) != nil {
		t.Fatal("row vector facts")
	}
	return f, []byte(v.OriginalCanonical)
}

func TestConfigBackfillIdentityIndependentVectors(t *testing.T) {
	for _, v := range backfillIdentityVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			var raw []byte
			var digest string
			var err error
			if v.Kind == "row" {
				var f ConfigBackfillRowFacts
				if json.Unmarshal(v.Facts, &f) != nil {
					t.Fatal("row facts")
				}
				raw, digest, err = CanonicalConfigBackfillRowIdentity(f, []byte(v.OriginalCanonical))
			} else {
				var f ConfigBackfillProvenanceFacts
				if json.Unmarshal(v.Facts, &f) != nil {
					t.Fatal("provenance facts")
				}
				raw, digest, err = CanonicalConfigBackfillProvenance(f)
			}
			if err != nil || string(raw) != v.Canonical || digest != v.SHA256 {
				t.Fatal("independent Node/Go identity parity", err, digest)
			}
		})
	}
}

func TestConfigBackfillIdentityEveryMaterializedColumnMustMatch(t *testing.T) {
	f, original := backfillIdentityRowFixture(t)
	for column := range f.Materialized {
		t.Run(column, func(t *testing.T) {
			changed, source := backfillIdentityRowFixture(t)
			changed.Materialized[column] += "!"
			if out, digest, err := CanonicalConfigBackfillRowIdentity(changed, source); out != nil || digest != "" || err != ErrConfigMutation {
				t.Fatal("source overrode actual SQL column drift", column, err)
			}
			delete(changed.Materialized, column)
			if out, digest, err := CanonicalConfigBackfillRowIdentity(changed, source); out != nil || digest != "" || err != ErrConfigMutation {
				t.Fatal("missing locked SQL column accepted", column, err)
			}
		})
	}
	f.Materialized["unexpected_column"] = "value"
	if out, digest, err := CanonicalConfigBackfillRowIdentity(f, original); out != nil || digest != "" || err != ErrConfigMutation {
		t.Fatal("unreviewed column silently ignored", err)
	}
}

func TestConfigBackfillIdentityRequiresExactSQLDecimalScale(t *testing.T) {
	for _, v := range backfillIdentityVectors(t)[4:] {
		t.Run(v.Name, func(t *testing.T) {
			var f ConfigBackfillRowFacts
			if json.Unmarshal(v.Facts, &f) != nil {
				t.Fatal("decimal vector facts")
			}
			f.Materialized["source_size_safety_factor"] = strings.TrimRight(strings.TrimRight(f.Materialized["source_size_safety_factor"], "0"), ".")
			if out, digest, err := CanonicalConfigBackfillRowIdentity(f, []byte(v.OriginalCanonical)); out != nil || digest != "" || err != ErrConfigMutation {
				t.Fatal("non-SQL decimal scale accepted", err)
			}
		})
	}
}

func TestConfigBackfillIdentityBindsImmutableRowMetadata(t *testing.T) {
	changes := map[string]func(*ConfigBackfillRowFacts){
		"server":       func(f *ConfigBackfillRowFacts) { f.TargetServerUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
		"database":     func(f *ConfigBackfillRowFacts) { f.TargetDatabase = strings.ToLower(f.TargetDatabase) },
		"installation": func(f *ConfigBackfillRowFacts) { f.InstallationID = "installation_other" },
		"surrogate-id": func(f *ConfigBackfillRowFacts) { f.RowID = "2" },
		"version":      func(f *ConfigBackfillRowFacts) { f.Version++ },
		"copied-from":  func(f *ConfigBackfillRowFacts) { v := int64(1); f.CopiedFromVersion = &v },
		"creator":      func(f *ConfigBackfillRowFacts) { f.CreatedBy += " " },
		"reason":       func(f *ConfigBackfillRowFacts) { v := "合成原因"; f.ChangeReason = &v },
		"created-at":   func(f *ConfigBackfillRowFacts) { f.CreatedAt = f.CreatedAt.Add(time.Microsecond) },
	}
	base := backfillIdentityVectors(t)[0]
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f, original := backfillIdentityRowFixture(t)
			change(&f)
			out, digest, err := CanonicalConfigBackfillRowIdentity(f, original)
			if err != nil || len(out) == 0 || digest == base.SHA256 {
				t.Fatal("immutable row change did not change identity", err)
			}
		})
	}
}

func TestConfigBackfillIdentityRejectsInvalidRowsAndNonOriginalBytes(t *testing.T) {
	for name, change := range map[string]func(*ConfigBackfillRowFacts, *[]byte){
		"no-source":       func(_ *ConfigBackfillRowFacts, source *[]byte) { *source = nil },
		"pretty-source":   func(_ *ConfigBackfillRowFacts, source *[]byte) { *source = append([]byte(" "), (*source)...) },
		"bad-source-utf8": func(_ *ConfigBackfillRowFacts, source *[]byte) { (*source)[1] = 255 },
		"hash":            func(f *ConfigBackfillRowFacts, _ *[]byte) { f.ConfigSHA256 = strings.Repeat("f", 64) },
		"size":            func(f *ConfigBackfillRowFacts, _ *[]byte) { f.ConfigSizeBytes++ },
		"leading-id-zero": func(f *ConfigBackfillRowFacts, _ *[]byte) { f.RowID = "01" },
		"overflow-id":     func(f *ConfigBackfillRowFacts, _ *[]byte) { f.RowID = "18446744073709551616" },
		"zero-id":         func(f *ConfigBackfillRowFacts, _ *[]byte) { f.RowID = "0" },
		"changed-schema":  func(f *ConfigBackfillRowFacts, _ *[]byte) { f.SchemaVersion = "other.v1" },
		"changed-row-ver": func(f *ConfigBackfillRowFacts, _ *[]byte) { f.RowVersion = 2 },
		"unsafe-version":  func(f *ConfigBackfillRowFacts, _ *[]byte) { f.Version = 9007199254740992 },
		"copy-self":       func(f *ConfigBackfillRowFacts, _ *[]byte) { f.CopiedFromVersion = &f.Version },
		"copy-zero":       func(f *ConfigBackfillRowFacts, _ *[]byte) { v := int64(0); f.CopiedFromVersion = &v },
		"missing-columns": func(f *ConfigBackfillRowFacts, _ *[]byte) { f.Materialized = nil },
		"submicrosecond":  func(f *ConfigBackfillRowFacts, _ *[]byte) { f.CreatedAt = f.CreatedAt.Add(time.Nanosecond) },
		"non-utc": func(f *ConfigBackfillRowFacts, _ *[]byte) {
			f.CreatedAt = f.CreatedAt.In(time.FixedZone("offset", 3600))
		},
		"pre-mysql-year": func(f *ConfigBackfillRowFacts, _ *[]byte) { f.CreatedAt = time.Date(999, 1, 1, 0, 0, 0, 0, time.UTC) },
		"creator-budget": func(f *ConfigBackfillRowFacts, _ *[]byte) { f.CreatedBy = strings.Repeat("界", 43) },
		"creator-utf8":   func(f *ConfigBackfillRowFacts, _ *[]byte) { f.CreatedBy = string([]byte{255}) },
		"reason-budget":  func(f *ConfigBackfillRowFacts, _ *[]byte) { v := strings.Repeat("界", 171); f.ChangeReason = &v },
		"empty-reason":   func(f *ConfigBackfillRowFacts, _ *[]byte) { v := ""; f.ChangeReason = &v },
		"reason-utf8":    func(f *ConfigBackfillRowFacts, _ *[]byte) { v := string([]byte{255}); f.ChangeReason = &v },
	} {
		t.Run(name, func(t *testing.T) {
			f, original := backfillIdentityRowFixture(t)
			change(&f, &original)
			if out, digest, err := CanonicalConfigBackfillRowIdentity(f, original); out != nil || digest != "" || err != ErrConfigMutation {
				t.Fatal("invalid target/row/source produced identity", err)
			}
		})
	}
}

func TestConfigBackfillIdentityPreservesLegalSQLByteBudgets(t *testing.T) {
	for _, name := range []string{"creator-128-ascii", "creator-128-utf8-bytes", "reason-512-ascii", "reason-512-utf8-bytes"} {
		t.Run(name, func(t *testing.T) {
			f, original := backfillIdentityRowFixture(t)
			if name == "creator-128-ascii" {
				f.CreatedBy = strings.Repeat("a", 128)
			} else if name == "creator-128-utf8-bytes" {
				f.CreatedBy = strings.Repeat("界", 42) + "ab"
			} else {
				reason := strings.Repeat("a", 512)
				if name == "reason-512-utf8-bytes" {
					reason = strings.Repeat("界", 170) + "ab"
				}
				f.ChangeReason = &reason
			}
			raw, _, err := CanonicalConfigBackfillRowIdentity(f, original)
			if err != nil {
				t.Fatal("legal SQL byte budget was rejected", err)
			}
			var decoded map[string]json.RawMessage
			if json.Unmarshal(raw, &decoded) != nil {
				t.Fatal("row identity JSON")
			}
			var text string
			field, expected := "created_by", f.CreatedBy
			if f.ChangeReason != nil {
				field, expected = "change_reason", *f.ChangeReason
			}
			if json.Unmarshal(decoded[field], &text) != nil || text != expected {
				t.Fatal("historical metadata was truncated or normalized")
			}
		})
	}
}

func TestConfigBackfillIdentityRejectsSQLByteBudgetOverflow(t *testing.T) {
	for _, name := range []string{"creator-129-utf8-bytes", "reason-513-utf8-bytes"} {
		t.Run(name, func(t *testing.T) {
			f, original := backfillIdentityRowFixture(t)
			if name == "creator-129-utf8-bytes" {
				f.CreatedBy = strings.Repeat("界", 43)
			} else {
				reason := strings.Repeat("界", 171)
				f.ChangeReason = &reason
			}
			if out, digest, err := CanonicalConfigBackfillRowIdentity(f, original); out != nil || digest != "" || err != ErrConfigMutation {
				t.Fatal("SQL OCTET_LENGTH overflow accepted as character count", err)
			}
		})
	}
}

func TestConfigBackfillIdentityProvenanceBindsEverySourceFact(t *testing.T) {
	base := backfillIdentityVectors(t)[2]
	for name, change := range map[string]func(*ConfigBackfillProvenanceFacts){
		"server":      func(f *ConfigBackfillProvenanceFacts) { f.TargetServerUUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" },
		"database":    func(f *ConfigBackfillProvenanceFacts) { f.TargetDatabase = strings.ToLower(f.TargetDatabase) },
		"install":     func(f *ConfigBackfillProvenanceFacts) { f.InstallationID += "x" },
		"version":     func(f *ConfigBackfillProvenanceFacts) { f.Version++ },
		"hash":        func(f *ConfigBackfillProvenanceFacts) { f.ConfigSHA256 = strings.Repeat("b", 64) },
		"size":        func(f *ConfigBackfillProvenanceFacts) { f.ConfigSizeBytes++ },
		"issuer":      func(f *ConfigBackfillProvenanceFacts) { f.SourceIssuer += " " },
		"archive-id":  func(f *ConfigBackfillProvenanceFacts) { f.SourceID += " " },
		"archive-ver": func(f *ConfigBackfillProvenanceFacts) { f.SourceVersion = "immutable-v2" },
		"attestation": func(f *ConfigBackfillProvenanceFacts) { f.AttestationSHA256 = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var f ConfigBackfillProvenanceFacts
			if json.Unmarshal(base.Facts, &f) != nil {
				t.Fatal("source facts")
			}
			change(&f)
			out, digest, err := CanonicalConfigBackfillProvenance(f)
			if err != nil || len(out) == 0 || digest == base.SHA256 || bytes.Equal(out, []byte(base.Canonical)) {
				t.Fatal("changed source provenance reused identity", err)
			}
		})
	}
}

func TestConfigBackfillIdentityProvenanceRejectsInvalidShape(t *testing.T) {
	base := backfillIdentityVectors(t)[2]
	for name, change := range map[string]func(*ConfigBackfillProvenanceFacts){
		"untrusted-server-case": func(f *ConfigBackfillProvenanceFacts) { f.TargetServerUUID = strings.ToUpper(f.TargetServerUUID) },
		"bad-database":          func(f *ConfigBackfillProvenanceFacts) { f.TargetDatabase = "../other" },
		"zero-version":          func(f *ConfigBackfillProvenanceFacts) { f.Version = 0 },
		"empty-issuer":          func(f *ConfigBackfillProvenanceFacts) { f.SourceIssuer = " " },
		"issuer-utf8":           func(f *ConfigBackfillProvenanceFacts) { f.SourceIssuer = string([]byte{255}) },
		"empty-record":          func(f *ConfigBackfillProvenanceFacts) { f.SourceID = "\n" },
		"record-budget":         func(f *ConfigBackfillProvenanceFacts) { f.SourceID = strings.Repeat("界", 683) },
		"empty-record-version":  func(f *ConfigBackfillProvenanceFacts) { f.SourceVersion = "" },
		"attestation-case":      func(f *ConfigBackfillProvenanceFacts) { f.AttestationSHA256 = strings.Repeat("A", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var f ConfigBackfillProvenanceFacts
			if json.Unmarshal(base.Facts, &f) != nil {
				t.Fatal("source facts")
			}
			change(&f)
			if out, digest, err := CanonicalConfigBackfillProvenance(f); out != nil || digest != "" || err != ErrConfigMutation {
				t.Fatal("malformed provenance representation accepted", err)
			}
		})
	}
}
