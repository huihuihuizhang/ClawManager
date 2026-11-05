package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	wire "clawreef/internal/systembackupwire"
)

// Complete historical SQL ROW MODEL plus real original-owner signatures,
// actual production SQL signing/staging/Transit TLS code. Not native MySQL,
// real KEK admission, full normal-enable lineage or deployed Task2 success.
type enabledSigningModel struct {
	base                                *signingSQLTestState
	old, current                        ConfigValues
	policy                              ConfigOperationResponsePolicy
	response, core, observation         []byte
	coreSHA, bindingSHA, observationSHA string
	expires                             time.Time
	mode                                string
	lineageReads                        int
}
type enabledSigningConnector struct{ m *enabledSigningModel }

func (c enabledSigningConnector) Driver() driver.Driver { return proofDriver{} }
func (c enabledSigningConnector) Connect(context.Context) (driver.Conn, error) {
	return &enabledSigningConn{signingSQLConn: &signingSQLConn{s: c.m.base}, m: c.m}, nil
}

type enabledSigningConn struct {
	*signingSQLConn
	m *enabledSigningModel
}

func (c *enabledSigningConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	m := c.m
	switch {
	case q == "SELECT UTC_TIMESTAMP(6)":
		return registrationRow(m.base.now), nil
	case strings.HasPrefix(q, "SELECT active_config_version FROM system_backup_v2_installation_state"):
		m.lineageReads++
		return registrationRow(int64(2)), nil
	case strings.HasPrefix(q, "SELECT active_config_version,last_effective_enabled,row_version"):
		m.lineageReads++
		active := int64(2)
		if m.mode == "wrong-active" {
			active = 1
		}
		return registrationRow(active, true, int64(2)), nil
	case strings.Contains(q, "FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?"):
		if len(args) != 2 || args[0].Value != m.policy.InstallationID {
			return nil, errors.New("wrong original config view/key")
		}
		values := m.old
		version := fmt.Sprint(args[1].Value)
		if version == "2" {
			values = m.current
		} else if version != "1" {
			return nil, errors.New("unplanned config version")
		}
		columns, all, e := values.sqlValues(m.policy.InstallationID, "unused", "unused", int64(1))
		if e != nil {
			return nil, e
		}
		cells := map[string]driver.Value{}
		for n, k := range columns {
			switch v := all[n].(type) {
			case []byte:
				cells[k] = v
			case bool:
				cells[k] = v
			default:
				cells[k] = fmt.Sprint(v)
			}
		}
		cells["schema_version"], cells["row_version"] = "system-backup-config.v1", int64(1)
		if m.mode == "wrong-flat" && version == "2" {
			cells["kek_identity_hash"] = strings.Repeat("0", 64)
		}
		selected := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ",")
		out := []driver.Value{}
		for _, k := range selected {
			v, ok := cells[k]
			if !ok {
				return nil, fmt.Errorf("unplanned config field %s", k)
			}
			out = append(out, v)
		}
		return registrationRow(out...), nil
	case strings.HasPrefix(q, "SELECT id,public_id,actor_id,idempotency_key,request_hash,row_version,redacted_response_evidence_id"):
		if m.mode == "missing-enable" {
			return &registrationTestRows{width: 15}, nil
		}
		v := m.policy
		return registrationRow(int64(51), v.OperationPublicID, fmt.Sprint(v.ActorID), v.IdempotencyKey, v.RequestHash, v.RowVersion, int64(71), registrationHash(string(m.response)), v.CreatedAt, v.StartedAt, v.FinishedAt, v.UpdatedAt, v.DeadlineAt), nil
	case strings.HasPrefix(q, "SELECT inline_payload,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE id=?"):
		return registrationRow(m.response, int64(len(m.response)), m.expires), nil
	case strings.HasPrefix(q, "SELECT schema_version,public_id,evidence_failure_code,redaction_classification,row_version,created_at FROM system_backup_v2_evidence"):
		return registrationRow("system-backup-evidence.v1", "sev_12345678-1234-1234-1234-123456789abc", "none", "internal", int64(1), m.policy.FinishedAt), nil
	case strings.HasPrefix(q, "SELECT storage_provider_role,"):
		return registrationRow(make([]driver.Value, 14)...), nil
	case strings.HasPrefix(q, "SELECT chunk_index FROM system_backup_v2_evidence_chunks"):
		if m.mode == "unexpected-chunk" {
			return registrationRow(int64(0)), nil
		}
		return &registrationTestRows{width: 1}, nil
	case strings.Contains(q, "FROM system_backup_v2_kek_admissions a"):
		sha := m.current.SHA256()
		if m.mode == "wrong-admission" {
			sha = strings.Repeat("0", 64)
		}
		return registrationRow(m.core, m.coreSHA, m.bindingSHA, m.observation, m.observationSHA, strings.Repeat("b", 64), "synthetic-v1", sha), nil
	case strings.HasPrefix(q, "SELECT e.expires_at FROM system_backup_v2_operations o JOIN system_backup_v2_evidence e"):
		if len(args) != 3 || args[0].Value != m.policy.InstallationID || args[1].Value != m.policy.OperationPublicID || args[2].Value != m.policy.InstallationID {
			return nil, errors.New("wrong original response expiry join")
		}
		return registrationRow(m.expires), nil
	default:
		return c.signingSQLConn.QueryContext(ctx, q, args)
	}
}
func enabledSigningFixture(t *testing.T) (*installationSigningFixture, *enabledSigningModel, *sql.DB, *SQLInstallationArtifactSigners) {
	t.Helper()
	f, state, _, first := newSigningSQLFixture(t)
	first.Close()
	old, e := DecodeConfigValues(bootstrapFixture(t))
	if e != nil {
		t.Fatal(e)
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(old.CanonicalJSON()))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil {
		t.Fatal("config fixture")
	}
	object["enabled"] = true
	raw, e := json.Marshal(object)
	if e != nil {
		t.Fatal(e)
	}
	current, e := DecodeConfigValues(raw)
	if e != nil {
		t.Fatal(e)
	}
	if ValidateEnableOnlyConfigMutation(ConfigMutationResourceInput{current: old, proposed: current}) != nil {
		t.Fatal("fixture is not exact enabled-only transition")
	}
	oldGrant := state.grant
	oldGrant.ConfigVersion, oldGrant.ConfigSHA256 = 1, old.SHA256()
	for n := range f.record.Permissions {
		copy := oldGrant
		f.record.Permissions[n].SQLOwner = &copy
	}
	f.writeRecord(true)
	state.grant = oldGrant
	state.grant.ConfigVersion, state.grant.ConfigSHA256 = 2, current.SHA256()
	state.now = state.now.UTC().Truncate(time.Microsecond)
	now := state.now
	policy := ConfigOperationResponsePolicy{InstallationID: f.pin.InstallationID, OperationPublicID: "sop_12345678-1234-1234-1234-123456789abc", Endpoint: ConfigUpdateEndpoint, IdempotencyKey: "original-enable-only-operation", RequestHash: strings.Repeat("a", 64), ActorID: 41, Version: 2, RowVersion: 3, CreatedAt: now.Add(-3 * time.Second), StartedAt: now.Add(-2 * time.Second), FinishedAt: now.Add(-time.Second), UpdatedAt: now.Add(-time.Second), DeadlineAt: now.Add(time.Minute)}
	response, e := CanonicalConfigOperationResponse(policy)
	if e != nil {
		t.Fatal(e)
	}
	digest := func(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
	typed := reg.TypedReference{RawJSON: []byte("{}"), SHA256: digest([]byte("{}"))}
	binding := reg.Binding{InstallationID: f.pin.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: strings.Repeat("b", 64), Version: "synthetic-v1"}, Key: wire.KeyBinding{Provider: "vault-transit", IdentityHash: strings.Repeat("b", 64), RegistryVersion: "synthetic-v1", ProviderKeyID: "original-key", ProviderVersion: "1"}, GenerateRef: typed, UnwrapRef: typed}
	core, e := json.Marshal(binding)
	if e != nil {
		t.Fatal(e)
	}
	semantic := binding
	semantic.GenerateRef.SHA256 = ""
	semantic.UnwrapRef.SHA256 = ""
	semanticRaw, e := json.Marshal(semantic)
	if e != nil {
		t.Fatal(e)
	}
	bindingSHA, e := reg.BindingFingerprint(binding)
	if e != nil {
		t.Fatal(e)
	}
	observation := reg.AdmissionObservation{InstallationID: f.pin.InstallationID, ConfigSHA256: current.SHA256(), SourceRevision: "synthetic-original-enable", NotBefore: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute)}
	observed, e := json.Marshal(struct {
		Observation            reg.AdmissionObservation
		GenerateRef, UnwrapRef reg.TypedReference
	}{observation, typed, typed})
	if e != nil {
		t.Fatal(e)
	}
	model := &enabledSigningModel{base: state, old: old, current: current, policy: policy, response: response, core: core, coreSHA: digest(semanticRaw), bindingSHA: bindingSHA, observation: observed, observationSHA: digest(observed), expires: now.Add(20 * time.Minute)}
	db := sql.OpenDB(enabledSigningConnector{model})
	t.Cleanup(func() { _ = db.Close() })
	signers, e := NewSQLInstallationArtifactSigners(context.Background(), db, f.reader, f.pin, f.mounts, f.task, state.claim)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(signers.Close)
	return f, model, db, signers
}
func TestSQLSigningEnabledOnlyActualStageAndTLSRemainOriginalOwner(t *testing.T) {
	f, m, db, s := enabledSigningFixture(t)
	for _, mount := range f.mounts {
		input := signingSQLInput(t, f.task, mount.Binding)
		stageSigningSQLFixture(t, db, s, mount.Binding.Purpose, input, false)
		if len(m.base.evidence) != 0 {
			t.Fatal("rollback left a frozen signing fragment")
		}
		stageSigningSQLFixture(t, db, s, mount.Binding.Purpose, input, true)
		signer, e := s.Signer(mount.Binding.Purpose)
		if e != nil {
			t.Fatal(e)
		}
		signature, e := signer.Sign(context.Background(), input)
		if e != nil {
			t.Fatal(e)
		}
		history, e := s.History(context.Background())
		if e != nil || !ed25519.Verify(history.PurposeKeys(mount.Binding.Purpose)[0].PublicKey, input, signature) {
			t.Fatal("not the original signed owner/key", e)
		}
		m.base.evidence = map[string][]driver.Value{}
	}
	if m.lineageReads < 3 || f.login != 3 || f.signed != 3 || f.authorized != 0 {
		t.Fatal("actual same-view lineage or production TLS path skipped")
	}
}
func TestSQLSigningEnabledOnlyRejectsUnprovedActualTask2BeforeWriteOrProvider(t *testing.T) {
	for _, mode := range []string{"missing-enable", "wrong-active", "wrong-flat", "unexpected-chunk", "wrong-admission", "expired-response", "wrong-task-hash", "other-task-version"} {
		t.Run(mode, func(t *testing.T) {
			f, m, db, s := enabledSigningFixture(t)
			m.mode = mode
			switch mode {
			case "expired-response":
				m.expires = m.base.now.Add(-time.Second)
			case "wrong-task-hash":
				m.base.grant.ConfigSHA256 = strings.Repeat("0", 64)
			case "other-task-version":
				m.base.grant.ConfigVersion = 3
			}
			tx, e := db.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			input := signingSQLInput(t, f.task, f.mounts[0].Binding)
			if s.StageSigningInput(context.Background(), tx, f.mounts[0].Binding.Purpose, input) == nil {
				t.Fatal("Task2 inherited scope without original complete proof")
			}
			if m.base.writes != 0 || f.login != 0 || f.signed != 0 {
				t.Fatal("unproved scope reached write/provider")
			}
		})
	}
}
func TestSQLSigningEnabledOnlyProofAndExpiryCannotCrossViews(t *testing.T) {
	_, m, db, _ := enabledSigningFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	proof, e := ReadOriginalEnabledOnlyLineage(ctx, tx, m.policy.InstallationID, m.old.SHA256(), 2, m.current.SHA256())
	if e != nil {
		t.Fatal(e)
	}
	if until, e := proof.OriginalDiagnosticUntil(ctx, tx); e != nil || !until.Equal(m.expires) {
		t.Fatal("actual original expiry not used", e)
	}
	other, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Rollback()
	if _, e = proof.OriginalDiagnosticUntil(ctx, other); e == nil {
		t.Fatal("foreign transaction accepted")
	}
	foreign, stop := context.WithCancel(ctx)
	defer stop()
	if _, e = proof.OriginalDiagnosticUntil(foreign, tx); e == nil {
		t.Fatal("foreign context accepted")
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if _, e = proof.OriginalDiagnosticUntil(ctx, tx); e == nil {
		t.Fatal("closed proof view accepted")
	}
}
