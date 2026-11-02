package systembackupkekregistry

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "clawreef/internal/systembackupwire"
)

func bindingReadFixture() Binding {
	pin := ReferencePin{IdentityHash: strings.Repeat("a", 64), Version: "original-v1"}
	return Binding{
		InstallationID: "installation_binding_read",
		ConfigRef:      pin,
		Key: wire.KeyBinding{Provider: "external-kms", IdentityHash: pin.IdentityHash,
			RegistryVersion: pin.Version, ProviderKeyID: "original-key", ProviderVersion: "1"},
		Provider: ProviderBinding{Endpoint: "https://kms.invalid", KeyName: "original-key",
			ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), CAPEMSHA256: strings.Repeat("d", 64),
			CASource: SourceRecord{SourceID: "original-ca", RecordID: "ca", RecordVersion: "v1", ContentSHA256: strings.Repeat("d", 64)}},
		GenerateRef: testTypedReference(`{"purpose":"data_key_generation","description_redacted":"original"}`),
		UnwrapRef:   testTypedReference(`{"purpose":"kek_unwrap","description_redacted":"original"}`),
	}
}

func bindingReadRevocation(purpose RevocationPurpose) Revocation {
	return Revocation{Purpose: purpose, Source: SourceRecord{SourceID: "independent-owner", RecordID: "revocation",
		RecordVersion: "v1", ContentSHA256: strings.Repeat("e", 64)}, SourceRevision: "original-revision",
		ObservedAt: time.Date(2026, 11, 2, 0, 0, 0, 123456000, time.UTC)}
}

type bindingReadTestRow struct {
	values []any
	err    error
}

func (r bindingReadTestRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("test row width mismatch")
	}
	for i, value := range r.values {
		target := reflect.ValueOf(dest[i]).Elem()
		if value == nil {
			target.SetZero()
		} else if raw := reflect.ValueOf(value); raw.Type().AssignableTo(target.Type()) {
			target.Set(raw)
		} else {
			return errors.New("test row type mismatch")
		}
	}
	return nil
}

func bindingReadFixtureRow(t *testing.T) bindingReadTestRow {
	t.Helper()
	b := bindingReadFixture()
	raw, _, err := hashJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	core, err := semanticCoreHash(b)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := BindingFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	return bindingReadTestRow{values: []any{b.ConfigRef.IdentityHash, b.ConfigRef.Version, fingerprint, core, raw, uint64(7), []byte(nil), []byte(nil)}}
}

func TestReadBindingSharedScannerRetainsCurrentIndependentRevocations(t *testing.T) {
	row := bindingReadFixtureRow(t)
	b := bindingReadFixture()
	got, err := scanBindingRow(row, b.InstallationID)
	if err != nil || got.RowVersion != 7 || !reflect.DeepEqual(got.Binding, b) || got.GenerateRevoked != nil || got.UnwrapRevoked != nil {
		t.Fatal("original binding rejected", err)
	}
	for _, purpose := range []RevocationPurpose{GenerateRevocation, UnwrapRevocation} {
		rev := bindingReadRevocation(purpose)
		raw, _, e := hashJSON(rev)
		if e != nil {
			t.Fatal(e)
		}
		index := 6
		if purpose == UnwrapRevocation {
			index = 7
		}
		row.values[index] = raw
		got, err = scanBindingRow(row, b.InstallationID)
		if err != nil || !SameSecurityBinding(got.Binding, b) {
			t.Fatal("persisted revocation must remain visible typed facts, not an implicit permission", err)
		}
		if purpose == GenerateRevocation && (got.GenerateRevoked == nil || got.UnwrapRevoked != nil || !reflect.DeepEqual(*got.GenerateRevoked, rev)) {
			t.Fatal("generation and independent unwrap revocation conflated")
		}
		if purpose == UnwrapRevocation && (got.GenerateRevoked == nil || got.UnwrapRevoked == nil || !reflect.DeepEqual(*got.UnwrapRevoked, rev)) {
			t.Fatal("current unwrap invalidation lost")
		}
	}
}

func TestReadBindingSharedScannerRejectsInvalidOriginalRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*bindingReadTestRow)
	}{
		{"scan", func(r *bindingReadTestRow) { r.err = errors.New("private driver error") }},
		{"identity", func(r *bindingReadTestRow) { r.values[0] = strings.Repeat("b", 64) }},
		{"version", func(r *bindingReadTestRow) { r.values[1] = "different" }},
		{"fingerprint", func(r *bindingReadTestRow) { r.values[2] = strings.Repeat("0", 64) }},
		{"core-hash", func(r *bindingReadTestRow) { r.values[3] = strings.Repeat("0", 64) }},
		{"invalid-json", func(r *bindingReadTestRow) { r.values[4] = []byte(`{`) }},
		{"noncanonical-core", func(r *bindingReadTestRow) { r.values[4] = append([]byte(" "), r.values[4].([]byte)...) }},
		{"empty-core", func(r *bindingReadTestRow) { r.values[4] = []byte(nil) }},
		{"zero-rv", func(r *bindingReadTestRow) { r.values[5] = uint64(0) }},
		{"generate-json", func(r *bindingReadTestRow) { r.values[6] = []byte(`{`) }},
		{"unwrap-json", func(r *bindingReadTestRow) { r.values[7] = []byte(`{`) }},
		{"generate-purpose", func(r *bindingReadTestRow) { r.values[6] = []byte(`{"Purpose":"unwrap"}`) }},
		{"unwrap-purpose", func(r *bindingReadTestRow) { r.values[7] = []byte(`{"Purpose":"generate"}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := bindingReadFixtureRow(t)
			tc.change(&row)
			if _, err := scanBindingRow(row, bindingReadFixture().InstallationID); !errors.Is(err, ErrKEKFacts) {
				t.Fatal("invalid binding accepted", err)
			}
		})
	}
	if _, err := scanBindingRow(bindingReadFixtureRow(t), "other-installation"); !errors.Is(err, ErrKEKFacts) {
		t.Fatal("installation substitution accepted", err)
	}
	row := bindingReadFixtureRow(t)
	bad := bindingReadFixture()
	bad.GenerateRef.SHA256 = strings.Repeat("0", 64)
	raw, _, err := hashJSON(bad)
	if err != nil {
		t.Fatal(err)
	}
	row.values[4] = raw
	if _, err := scanBindingRow(row, bad.InstallationID); !errors.Is(err, ErrKEKFacts) {
		t.Fatal("invalid original typed-reference bytes/hash accepted", err)
	}
}

type bindingReadNoQueries struct{ t *testing.T }

func (v *bindingReadNoQueries) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	v.t.Fatal("invalid input must not reach SQL")
	return nil, ErrKEKFacts
}

func (v *bindingReadNoQueries) QueryRowContext(context.Context, string, ...any) *sql.Row {
	v.t.Fatal("invalid input must not reach SQL")
	return nil
}

func TestReadBindingTxInvalidInputsNeverReachSQL(t *testing.T) {
	ctx := context.Background()
	store := &SQLStore{}
	view := &bindingReadNoQueries{t: t}
	b := bindingReadFixture()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	var typedNil *bindingReadNoQueries
	for _, tc := range []struct {
		name         string
		store        *SQLStore
		ctx          context.Context
		view         SQLReadView
		installation string
		pin          ReferencePin
	}{
		{"nil-store", nil, ctx, view, b.InstallationID, b.ConfigRef},
		{"nil-context", store, nil, view, b.InstallationID, b.ConfigRef},
		{"canceled", store, canceled, view, b.InstallationID, b.ConfigRef},
		{"nil-view", store, ctx, nil, b.InstallationID, b.ConfigRef},
		{"typed-nil-view", store, ctx, typedNil, b.InstallationID, b.ConfigRef},
		{"empty-installation", store, ctx, view, "", b.ConfigRef},
		{"long-installation", store, ctx, view, strings.Repeat("i", 129), b.ConfigRef},
		{"invalid-pin", store, ctx, view, b.InstallationID, ReferencePin{IdentityHash: "invalid", Version: "v1"}},
		{"empty-version", store, ctx, view, b.InstallationID, ReferencePin{IdentityHash: b.ConfigRef.IdentityHash}},
		{"long-version", store, ctx, view, b.InstallationID, ReferencePin{IdentityHash: b.ConfigRef.IdentityHash, Version: strings.Repeat("v", 129)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.store.ReadBindingTx(tc.ctx, tc.view, tc.installation, tc.pin); !errors.Is(err, ErrKEKFacts) {
				t.Fatal("invalid original transaction input accepted", err)
			}
		})
	}
}
