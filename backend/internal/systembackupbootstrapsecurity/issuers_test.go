package systembackupbootstrapsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

var issuerNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

type issuerFixture struct {
	fixture
	v                *Issuers
	provider, strong map[string]any
	paths            map[string]string
}

func newIssuerFixture(t *testing.T, mutate func(map[string]any, map[string]any), wire func(string, []byte) []byte) issuerFixture {
	t.Helper()
	f := newFixture(t, nil, nil)
	public := func(value byte) []byte {
		return []byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	}
	key := func(value byte, purpose string) map[string]any {
		return map[string]any{"issuer": purpose + "-test", "key_id": "key-test", "key_version": "1", "purpose": purpose,
			"public_key_base64": public(value), "not_before": issuerNow.Add(-time.Hour).Format(time.RFC3339Nano), "not_after": issuerNow.Add(time.Hour).Format(time.RFC3339Nano), "revoked": false}
	}
	p, s := key(1, "provider_proof_issuer"), key(2, "strong_auth_issuer")
	p["target_types"] = []string{"external_action", "backup_staging", "restore_resource"}
	p["proof_types"] = []string{"provider_presence", "provider_absence", "ownership"}
	s["policy"] = map[string]any{"methods": []string{"totp"}, "acr": []string{}, "amr": []string{"otp"}}
	provider := map[string]any{"schema_version": "system-backup-provider-issuers.draft.v1", "version": "provider-v1", "scope": map[string]any{"installation_id": f.grant.InstallationID, "audience": "provider-test"}, "keys": []any{p}}
	strong := map[string]any{"schema_version": "system-backup-strong-auth-issuers.draft.v1", "version": "strong-v1", "audience": "strong-test", "keys": []any{s}}
	if mutate != nil {
		mutate(provider, strong)
	}
	var config map[string]any
	if err := json.Unmarshal(f.config.CanonicalJSON(), &config); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for kind, registry := range map[string]map[string]any{"provider_proof_issuers": provider, "strong_auth_issuers": strong} {
		raw, err := json.Marshal(registry)
		if err != nil {
			t.Fatal(err)
		}
		if wire != nil {
			raw = wire(kind, raw)
		}
		version := "provider-v1"
		if kind == "strong_auth_issuers" {
			version = "strong-v1"
		}
		path := filepath.Join(f.validator.directory, kind, version, sha(raw)+".json")
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		paths[kind] = path
		for _, value := range config["registries"].([]any) {
			pin := value.(map[string]any)
			if pin["registry_kind"] == kind {
				pin["version"], pin["sha256"] = version, sha(raw)
			}
		}
	}
	raw, _ := json.Marshal(config)
	var err error
	f.config, err = sec.DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.grant.ConfigSHA256 = f.config.SHA256()
	v := NewIssuers(f.validator.directory)
	v.now = func() time.Time { return issuerNow }
	return issuerFixture{f, v, provider, strong, paths}
}

func firstKey(r map[string]any) map[string]any { return r["keys"].([]any)[0].(map[string]any) }
func policy(r map[string]any) map[string]any   { return firstKey(r)["policy"].(map[string]any) }

func TestIssuersPrepareAndBorrowedTransaction(t *testing.T) {
	f := newIssuerFixture(t, func(p, s map[string]any) {
		policy(s)["methods"] = []string{"totp", "webauthn", "oidc_mfa"}
		policy(s)["acr"] = []string{"urn:test:mfa"}
		policy(s)["amr"] = []string{"otp", "webauthn", "mfa"}
		// Keep rotated historical versions; they must not substitute for an
		// active version but must still participate in purpose separation.
		for _, r := range []map[string]any{p, s} {
			old := map[string]any{}
			for k, value := range firstKey(r) {
				old[k] = value
			}
			old["key_version"], old["revoked"] = "historical", true
			old["not_after"] = issuerNow.Add(-time.Minute).Format(time.RFC3339Nano)
			if old["purpose"] == "strong_auth_issuer" {
				old["policy"] = map[string]any{"methods": []string{"totp"}, "acr": []string{}, "amr": []string{"otp"}}
			}
			r["keys"] = append(r["keys"].([]any), old)
		}
	}, nil)
	check, err := f.v.Prepare(context.Background(), f.grant, f.config)
	if err != nil {
		t.Fatal(err)
	}
	s := &dbState{server: f.grant.ServerUUID, database: f.grant.Database}
	if err = check.Recheck(context.Background(), begin(t, s), issuerNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s.queries != 1 || s.writes != 0 || s.commits != 0 {
		t.Fatal("transaction ownership changed")
	}
	if _, err = json.Marshal(check); err == nil || fmt.Sprintf("%#v", check) != "BootstrapIssuerCheck" {
		t.Fatal("private check serialized")
	}
}

func TestIssuersRejectInvalidTrustAndUnusableCurrentKeys(t *testing.T) {
	cases := map[string]func(map[string]any, map[string]any){
		"wrong_installation":      func(p, s map[string]any) { p["scope"].(map[string]any)["installation_id"] = "installation_other" },
		"provider_schema":         func(p, s map[string]any) { p["schema_version"] = "other" },
		"provider_version":        func(p, s map[string]any) { p["version"] = "other" },
		"provider_unknown_target": func(p, s map[string]any) { firstKey(p)["target_types"] = []string{"other"} },
		"provider_unknown_proof":  func(p, s map[string]any) { firstKey(p)["proof_types"] = []string{"other"} },
		"provider_duplicate_target": func(p, s map[string]any) {
			firstKey(p)["target_types"] = []string{"external_action", "external_action"}
		},
		"provider_incompatible_capabilities": func(p, s map[string]any) { firstKey(p)["proof_types"] = []string{"ownership"} },
		"provider_wrong_purpose":             func(p, s map[string]any) { firstKey(p)["purpose"] = "strong_auth_issuer" },
		"strong_schema":                      func(p, s map[string]any) { s["schema_version"] = "other" },
		"strong_version":                     func(p, s map[string]any) { s["version"] = "other" },
		"strong_blank_audience":              func(p, s map[string]any) { s["audience"] = " " },
		"strong_blank_issuer":                func(p, s map[string]any) { firstKey(s)["issuer"] = " " },
		"strong_wrong_purpose":               func(p, s map[string]any) { firstKey(s)["purpose"] = "capture_signing" },
		"strong_bad_key":                     func(p, s map[string]any) { firstKey(s)["public_key_base64"] = []byte{1} },
		"strong_bad_interval":                func(p, s map[string]any) { firstKey(s)["not_after"] = firstKey(s)["not_before"] },
		"strong_duplicate_version":           func(p, s map[string]any) { s["keys"] = append(s["keys"].([]any), firstKey(s)) },
		"unknown_method":                     func(p, s map[string]any) { policy(s)["methods"] = []string{"password"} },
		"duplicate_method":                   func(p, s map[string]any) { policy(s)["methods"] = []string{"totp", "totp"} },
		"duplicate_amr":                      func(p, s map[string]any) { policy(s)["amr"] = []string{"otp", "otp"} },
		"blank_acr":                          func(p, s map[string]any) { policy(s)["acr"] = []string{" "} },
		"webauthn_without_amr":               func(p, s map[string]any) { policy(s)["methods"] = []string{"totp", "webauthn"} },
		"oidc_without_acr":                   func(p, s map[string]any) { policy(s)["methods"] = []string{"totp", "oidc_mfa"} },
		"totp_without_otp":                   func(p, s map[string]any) { policy(s)["amr"] = []string{} },
		"shared_public_key":                  func(p, s map[string]any) { firstKey(s)["public_key_base64"] = firstKey(p)["public_key_base64"] },
		"conflicting_active_policy": func(p, s map[string]any) {
			other := map[string]any{}
			for k, value := range firstKey(s) {
				other[k] = value
			}
			other["key_version"] = "2"
			other["policy"] = map[string]any{"methods": []string{"totp"}, "acr": []string{}, "amr": []string{"otp", "mfa"}}
			s["keys"] = append(s["keys"].([]any), other)
		},
	}
	for _, kind := range []string{"provider", "strong"} {
		for _, state := range []string{"revoked", "expired", "future", "insufficient_runway"} {
			kind, state := kind, state
			cases[kind+"_"+state] = func(p, s map[string]any) {
				r := p
				if kind == "strong" {
					r = s
				}
				k := firstKey(r)
				switch state {
				case "revoked":
					k["revoked"] = true
				case "expired":
					k["not_after"] = issuerNow.Format(time.RFC3339Nano)
				case "future":
					k["not_before"] = issuerNow.Add(time.Minute).Format(time.RFC3339Nano)
				case "insufficient_runway":
					k["not_after"] = issuerNow.Add(5 * time.Minute).Format(time.RFC3339Nano)
				}
			}
		}
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newIssuerFixture(t, mutate, nil)
			if check, err := f.v.Prepare(context.Background(), f.grant, f.config); err == nil || check != nil {
				t.Fatal("invalid issuer trust admitted")
			}
		})
	}
}

func TestIssuersRejectMalformedPinnedWire(t *testing.T) {
	for _, kind := range []string{"strong_auth_issuers", "provider_proof_issuers"} {
		for _, mutation := range []string{"unknown", "null", "alias", "duplicate", "missing"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				f := newIssuerFixture(t, nil, func(current string, raw []byte) []byte {
					if current != kind {
						return raw
					}
					replace := map[string]string{"unknown": `"approved":true,"revoked":false`, "null": `"revoked":null`, "alias": `"Revoked":false`, "duplicate": `"revoked":true,"revoked":false`, "missing": `"remove_me":false`}[mutation]
					return []byte(strings.Replace(string(raw), `"revoked":false`, replace, 1))
				})
				if check, err := f.v.Prepare(context.Background(), f.grant, f.config); err == nil || check != nil {
					t.Fatal("malformed pinned JSON admitted")
				}
			})
		}
	}
}

func TestIssuersRecheckDriftExpiryIdentityAndCancellation(t *testing.T) {
	for _, name := range []string{"provider_file_changed", "strong_file_removed", "clock_expired", "wrong_server", "wrong_database", "query_error", "canceled_during_query", "nil_transaction", "zero_clock"} {
		t.Run(name, func(t *testing.T) {
			f := newIssuerFixture(t, nil, nil)
			check, err := f.v.Prepare(context.Background(), f.grant, f.config)
			if err != nil {
				t.Fatal(err)
			}
			s := &dbState{server: f.grant.ServerUUID, database: f.grant.Database}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := issuerNow
			switch name {
			case "provider_file_changed":
				if err = os.WriteFile(f.paths["provider_proof_issuers"], []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "strong_file_removed":
				if err = os.Remove(f.paths["strong_auth_issuers"]); err != nil {
					t.Fatal(err)
				}
			case "clock_expired":
				now = now.Add(time.Hour)
			case "wrong_server":
				s.server = "other"
			case "wrong_database":
				s.database = "other"
			case "query_error":
				s.queryError = true
			case "canceled_during_query":
				s.cancel = cancel
			case "zero_clock":
				now = time.Time{}
			}
			tx := begin(t, s)
			if name == "nil_transaction" {
				tx = nil
			}
			if err = check.Recheck(ctx, tx, now); err == nil {
				t.Fatal("stale issuer trust admitted")
			}
			if s.writes != 0 || s.commits != 0 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("transaction effect or raw error escaped")
			}
		})
	}
}

func TestIssuersInvalidInputAndContext(t *testing.T) {
	for _, name := range []string{"grant_hash", "directory", "nil_validator", "nil_clock", "zero_clock", "missing_file", "nil_context", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f := newIssuerFixture(t, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "grant_hash":
				f.grant.ConfigSHA256 = strings.Repeat("0", 64)
			case "directory":
				f.v.directory = "relative"
			case "nil_validator":
				f.v = nil
			case "nil_clock":
				f.v.now = nil
			case "zero_clock":
				f.v.now = func() time.Time { return time.Time{} }
			case "missing_file":
				if err := os.Remove(f.paths["provider_proof_issuers"]); err != nil {
					t.Fatal(err)
				}
			case "nil_context":
				ctx = nil
			case "canceled":
				cancel()
			}
			if check, err := f.v.Prepare(ctx, f.grant, f.config); err == nil || check != nil {
				t.Fatal("invalid issuer input admitted")
			}
		})
	}
}

func TestIssuersRecheckRejectsNewlyActiveConflictingPolicy(t *testing.T) {
	f := newIssuerFixture(t, func(p, s map[string]any) {
		future := map[string]any{}
		for key, value := range firstKey(s) {
			future[key] = value
		}
		future["key_version"] = "future"
		future["not_before"] = issuerNow.Add(time.Minute).Format(time.RFC3339Nano)
		future["policy"] = map[string]any{"methods": []string{"totp"}, "acr": []string{}, "amr": []string{"otp", "mfa"}}
		s["keys"] = append(s["keys"].([]any), future)
	}, nil)
	check, err := f.v.Prepare(context.Background(), f.grant, f.config)
	if err != nil {
		t.Fatal(err)
	}
	s := &dbState{server: f.grant.ServerUUID, database: f.grant.Database}
	if err = check.Recheck(context.Background(), begin(t, s), issuerNow.Add(2*time.Minute)); err == nil {
		t.Fatal("policy activation during preparation was missed")
	}
}

func TestIssuersHistoricalKeysStillRequirePurposeSeparation(t *testing.T) {
	f := newIssuerFixture(t, func(p, s map[string]any) {
		old := map[string]any{}
		for key, value := range firstKey(s) {
			old[key] = value
		}
		old["key_version"], old["revoked"] = "historical", true
		old["public_key_base64"] = firstKey(p)["public_key_base64"]
		s["keys"] = append(s["keys"].([]any), old)
	}, nil)
	if check, err := f.v.Prepare(context.Background(), f.grant, f.config); err == nil || check != nil {
		t.Fatal("revoked public key reused across purposes")
	}
}
