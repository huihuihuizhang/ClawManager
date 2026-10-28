package systembackupevidence

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sqlTaskOwnerFixture(t *testing.T, kind string) (*admissionTxFixture, *SQLDownloadAuthority, *SQLTaskDownloadOwners, *sqlTaskOwnerModel) {
	t.Helper()
	prefix := map[string]string{"backup": "sbk_", "drill": "sdr_", "preflight": "spf_", "artifact_verify": "sav_"}[kind]
	f, a := uncommittedConfiguredFixture(t, func(f *admissionTxFixture) {
		f.initial.Manifest.Identity.OwnerType = kind
		f.initial.Manifest.Identity.OwnerID = prefix + "11111111-2222-4333-8444-555555555555"
	})
	s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: f.service.registry, Sessions: f.env.sessions, RegistryDirectory: a.c.RegistryDirectory})
	if err != nil {
		t.Fatal(err)
	}
	f.service.registry = s.Registry()
	a.c.Registry = s.Registry()
	m := newSQLTaskOwnerModel(t, f, kind)
	return f, a, s, m
}

func TestSQLTaskDownloadPreviewActualRowsPermissionsAndNoLocks(t *testing.T) {
	for _, kind := range []string{"backup", "drill", "preflight", "artifact_verify"} {
		t.Run(kind, func(t *testing.T) {
			f, _, s, m := sqlTaskOwnerFixture(t, kind)
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			r, err := s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
			if err != nil || !reflect.DeepEqual(r.Manifest, f.initial.Manifest) || !r.OwnerDeadline.Equal(m.deadline) || m.ownerReads < 2 || m.chunkReads != 1 || len(m.lockedStages) != 0 || f.db.ownerLocked || f.db.opKeyLocked {
				t.Fatal("preview did not use authorized nonlocking actual owner/Manifest", err, m.ownerReads, m.chunkReads, m.lockedStages)
			}
			if f.db.inserts != 0 || len(f.db.nonce) != 0 || f.db.reserved != 0 {
				t.Fatal("preview performed admission effects")
			}
		})
	}
}

func TestSQLTaskDownloadPreviewClassifiesAllFourStoredClasses(t *testing.T) {
	for _, classification := range []string{"public", "internal", "confidential", "sensitive"} {
		t.Run(classification, func(t *testing.T) {
			f, a := uncommittedConfiguredFixture(t, func(f *admissionTxFixture) {
				f.initial.Manifest.Identity.Classification = classification
			})
			s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: f.service.registry, Sessions: f.env.sessions, RegistryDirectory: a.c.RegistryDirectory})
			if err != nil {
				t.Fatal(err)
			}
			m := newSQLTaskOwnerModel(t, f, "backup")
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			r, err := s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
			if err != nil || r.Manifest.Identity.Classification != classification || m.chunkReads != 1 {
				t.Fatal("actual classification could not be inspected", classification, err)
			}
			if oneOf(classification, "public", "internal") {
				if _, err = s.Registry().PreviewDownloadEvidence(context.Background(), tx, f.initial.Manifest.Identity.ID, func(context.Context, *sql.Tx, Identity) (time.Time, error) { return m.deadline, nil }); err == nil {
					t.Fatal("MFA-only preview accepted nonprivate evidence")
				}
			}
		})
	}
}

func TestSQLTaskDownloadCurrentRBACRejectsPrivateBeforeChunks(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "config_admin", "security_admin"} {
		for _, classification := range []string{"public", "internal", "confidential", "sensitive"} {
			t.Run(role+"/"+classification, func(t *testing.T) {
				f, a := uncommittedConfiguredFixture(t, func(f *admissionTxFixture) {
					f.initial.Manifest.Identity.Classification = classification
				})
				raw := []byte(strings.ReplaceAll(string(f.env.rbac), "security_admin", role))
				digest := hash(raw)
				f.db.config, f.db.configCells = admissionConfigFixture(t, digest)
				writeAdmissionPinnedFile(t, filepath.Join(a.c.RegistryDirectory, "rbac_bindings", "v1", digest+".json"), raw)
				s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: f.service.registry, Sessions: f.env.sessions, RegistryDirectory: a.c.RegistryDirectory})
				if err != nil {
					t.Fatal(err)
				}
				m := newSQLTaskOwnerModel(t, f, "backup")
				tx, _, err := s.Registry().begin(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				_, err = s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
				allowed := classification == "public" || classification == "internal" || role == "security_admin" || classification == "confidential" && role == "operator"
				if (err == nil) != allowed || !allowed && (m.ownerReads != 0 || m.chunkReads != 0) || allowed && m.chunkReads != 1 {
					t.Fatal("current pinned RBAC classification boundary", role, classification, err, m.ownerReads, m.chunkReads)
				}
			})
		}
	}
}

func TestSQLTaskDownloadUnknownSchemaOwnerAndAuthorityFailBeforeChunks(t *testing.T) {
	for _, mode := range []string{"missing_owner", "foreign_owner", "wrong_kind", "bad_schema", "bad_deadline", "bad_created", "bad_version", "null_evidence_origin", "foreign_evidence_origin", "metadata_missing", "metadata_unknown", "metadata_type", "metadata_partial_producer", "session_revoked", "password", "rbac", "wrong_installation"} {
		t.Run(mode, func(t *testing.T) {
			f, a, s, m := sqlTaskOwnerFixture(t, "backup")
			installation := s.c.Registry.Installation
			switch mode {
			case "missing_owner":
				m.fault = "owner_missing"
			case "foreign_owner":
				m.origin = "installation_other"
			case "wrong_kind":
				m.taskType = "drill"
			case "bad_schema":
				m.schema = "future_unreviewed_schema"
			case "bad_deadline":
				m.deadline = m.created
			case "bad_created":
				m.created = f.initial.CreatedAt.Add(time.Minute)
			case "bad_version":
				m.version = 0
			case "null_evidence_origin":
				s := ""
				f.db.committedOrigin = &s
			case "foreign_evidence_origin":
				s := "installation_other"
				f.db.committedOrigin = &s
			case "metadata_missing":
				delete(m.metadata, "system_backup_v2_events.detail_evidence_public_id")
			case "metadata_unknown":
				m.metadata["system_unreviewed_table.evidence_id"] = "bigint"
			case "metadata_type":
				m.metadata["system_backup_v2_log_chunks.redacted_evidence_id"] = "varchar"
			case "metadata_partial_producer":
				m.metadata["system_backup_producer_runs.evidence_id"] = "varchar"
			case "session_revoked":
				f.db.sessionRevoked = true
			case "password":
				f.db.password = "changed"
			case "rbac":
				if err := os.WriteFile(filepath.Join(a.c.RegistryDirectory, "rbac_bindings", "v1", a.c.RBACSHA256+".json"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong_installation":
				installation = "installation_other"
			}
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if r, err := s.Preview(context.Background(), tx, installation, f.env.actor, f.initial.Manifest.Identity.ID); err == nil || r.Manifest.Identity.ID != "" {
				t.Fatal("untrusted owner/schema returned metadata")
			}
			if m.chunkReads != 0 || len(m.lockedStages) != 0 || f.db.inserts != 0 {
				t.Fatal("failure passed preview boundary", m.chunkReads, m.lockedStages)
			}
		})
	}
}

func TestSQLTaskDownloadLocksReferencesInOrderAndRejectsOverflow(t *testing.T) {
	for _, mode := range []string{"normal", "unsorted", "overflow", "producer_reference", "owner_changed", "classification_changed"} {
		t.Run(mode, func(t *testing.T) {
			f, _, s, m := sqlTaskOwnerFixture(t, "backup")
			switch mode {
			case "normal":
				m.refs["system_backup_v2_check_results"] = []int64{4, 8}
			case "unsorted":
				m.refs["system_backup_v2_check_results"] = []int64{8, 4}
			case "overflow":
				for n := 1; n <= maxTaskDownloadReferences+1; n++ {
					m.refs["system_backup_v2_check_results"] = append(m.refs["system_backup_v2_check_results"], int64(n))
				}
			case "producer_reference":
				for _, table := range taskDownloadSystemProducerTables {
					m.metadata[table+".evidence_id"] = "varchar"
				}
				m.producerMatch = true
			case "owner_changed":
				m.deadline = m.deadline.Add(time.Microsecond)
			case "classification_changed":
				f.db.record.Manifest.Identity.Classification = "internal"
			}
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = s.LockOwnerReferences(context.Background(), tx, f.initial)
			if (err == nil) != (mode == "normal") {
				t.Fatal("reference prefix", mode, err)
			}
			if mode == "normal" {
				if len(m.lockedStages) < 3 || m.lockedStages[0] != 3 || m.lockedStages[len(m.lockedStages)-1] != 5 {
					t.Fatal("missing lock layers", m.lockedStages)
				}
				previous := 0
				for _, stage := range m.lockedStages {
					if stage < previous {
						t.Fatal("backward reference locks", m.lockedStages)
					}
					previous = stage
				}
			}
		})
	}
}

func TestSQLTaskDownloadPolicyRequiresAuthenticatedContextAndCannotWrite(t *testing.T) {
	f, a, s, m := sqlTaskOwnerFixture(t, "backup")
	tx, _, err := s.Registry().begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	before := len(f.db.queries)
	if s.LockScope(context.Background(), tx, s.c.Registry.Installation, f.initial.Manifest.Identity) == nil || s.Authorize(context.Background(), tx, downloadActor(f.env.actor), f.initial, permissions("sensitive")) == nil || len(f.db.queries) != before {
		t.Fatal("caller-supplied actor granted scope")
	}
	ctx, actor, err := a.AuthenticateContext(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.LockScope(ctx, tx, s.c.Registry.Installation, f.initial.Manifest.Identity); err != nil {
		t.Fatal(err)
	}
	locked := len(m.lockedStages)
	if err = s.Authorize(ctx, tx, actor, f.initial, permissions("sensitive")); err != nil {
		t.Fatal(err)
	}
	if len(m.lockedStages) != locked {
		t.Fatal("final authorization acquired new L3+ locks")
	}
	if s.Admit(ctx, tx, f.initial, f.db.now) != ErrDenied || s.Deletable(ctx, tx, f.initial, f.db.now) != ErrDenied || s.Audit(ctx, tx, Audit{}) != ErrDenied {
		t.Fatal("download policy supplied write/GC/audit authority")
	}
}

func TestSQLTaskDownloadRetainedEvidenceKeepsPastOriginalOwnerDeadline(t *testing.T) {
	f, _, s, m := sqlTaskOwnerFixture(t, "backup")
	m.deadline = f.db.now.Add(-time.Minute)
	tx, _, err := s.Registry().begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	r, err := s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, f.initial.Manifest.Identity.ID)
	if err != nil || !r.OwnerDeadline.Equal(m.deadline) || !r.OwnerDeadline.Before(f.db.now) {
		t.Fatal("retained download refreshed/rejected original owner deadline", err)
	}
}

func TestSQLTaskDownloadRealPinnedAdmissionAndPostCommitPolicy(t *testing.T) {
	p := newAdmissionPinnedFixture(t)
	f := p.admissionTxFixture
	r := f.initial
	r.Ref.Identity = f.db.configCells["evidence_store_identity_hash"].(string)
	r.Ref.Version = f.db.configCells["evidence_store_ref_version"].(string)
	var err error
	r.Ref.RelativeKey, err = keyFor("evidence", r.Manifest.Identity)
	if err != nil {
		t.Fatal(err)
	}
	f.initial, f.db.record, f.env.hint, f.db.m.f.Record = r, r, r, r
	s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: f.service.registry, Sessions: p.configuration.Sessions, RegistryDirectory: p.configuration.RegistryDirectory})
	if err != nil {
		t.Fatal(err)
	}
	m := newSQLTaskOwnerModel(t, f, "backup")
	p.configuration.Owners = s
	p.environment, err = NewPinnedDownloadAdmissionEnvironment(p.configuration)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = NewDownloadAdmissionService(s.Registry(), f.secret, p.environment)
	if err != nil {
		t.Fatal(err)
	}
	// File/registry setup precedes admission. Sample the synthetic SQL clock
	// and capacity observation here, as a real fresh report would be sampled;
	// preserve the same signed proof and every original material limit. No
	// report or returned deadline is refreshed after admission starts.
	if err = sampleAAdmissionProofTime(f, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		t.Fatal("original signed proof at admission", err)
	}
	p.report.ObservedAt = f.db.now
	p.writeReport(t)
	c, err := f.service.Admit(f.request)
	if err != nil || c == nil {
		t.Fatal("real pinned owner composition", err, f.db.calls)
	}
	a, err := NewSQLDownloadAuthority(DownloadAuthorityConfig{Registry: s.Registry(), JWTSecret: f.secret, ConfigVersion: 1, ConfigSHA256: f.db.config.SHA256(), RBACVersion: "v1", RBACSHA256: f.env.rbacHash, RegistryDirectory: p.configuration.RegistryDirectory, Root: "evidence", Store: KeyRef{r.Ref.Identity, r.Ref.Version}, Read: KeyRef{f.db.configCells["evidence_read_identity_hash"].(string), f.db.configCells["evidence_read_ref_version"].(string)}, Issuer: "https://issuer.local", Audience: "download-provider", Subject: "system:download", TokenFile: filepath.Join(t.TempDir(), "token"), ExpiresAt: f.db.now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := bindCommittedFixture(t, a, c)
	if err = a.CheckCommittedDownload(ctx, c); err != nil {
		t.Fatal("post-commit real task policy", err)
	}
	if f.db.inserts != 1 || len(f.db.nonce) != 16 || f.db.commits != 2 || m.ownerReads < 3 || !strings.Contains(strings.Join(f.db.calls, ","), "real-task-owner") {
		t.Fatal("new owner source was bypassed", f.db.calls)
	}
}

func TestSQLTaskDownloadOtherOwnerTypesHaveNoTaskFallback(t *testing.T) {
	for _, kind := range []string{"system", "promotion", "catalog_record", "backup_staging"} {
		t.Run(kind, func(t *testing.T) {
			f, _, s, m := sqlTaskOwnerFixture(t, "backup")
			i := f.db.record.Manifest.Identity
			i.OwnerType = kind
			switch kind {
			case "system":
				i.OwnerID = i.Installation
			case "promotion":
				i.OwnerID = "spm_11111111-2222-4333-8444-555555555555"
			case "catalog_record":
				i.OwnerID = "scr_11111111-2222-4333-8444-555555555555"
			case "backup_staging":
				i.OwnerID = "sbs_11111111-2222-4333-8444-555555555555"
			}
			f.db.record.Manifest.Identity = i
			tx, _, err := s.Registry().begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = s.Preview(context.Background(), tx, s.c.Registry.Installation, f.env.actor, i.ID); err == nil || m.ownerReads != 0 || m.chunkReads != 0 {
				t.Fatal("other owner borrowed task deadline", kind, err)
			}
		})
	}
}

func TestSQLTaskDownloadResultLocksActualOwnerAfterRevocation(t *testing.T) {
	for _, mode := range []string{"revoked", "past_owner_deadline", "owner_changed", "owner_created_changed", "reference_overflow"} {
		t.Run(mode, func(t *testing.T) {
			f, _, c := committedFixture(t)
			results := resultFixture(t, f)
			s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: f.service.registry, Sessions: f.env.sessions, RegistryDirectory: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			m := newSQLTaskOwnerModel(t, f, "backup")
			results.c.Registry, results.c.Owners = s.Registry(), s
			f.db.ownerLocked = false // The admission transaction has committed.
			f.db.sessionRevoked, f.db.userActive = true, false
			c.fail()
			switch mode {
			case "past_owner_deadline":
				// The immutable deadline can precede result time. Never refresh it.
				f.db.now = m.deadline.Add(time.Second)
				results = resultFixture(t, f)
				results.c.Registry, results.c.Owners = s.Registry(), s
			case "owner_changed":
				m.deadline = m.deadline.Add(time.Microsecond)
			case "owner_created_changed":
				m.created = c.record.CreatedAt.Add(time.Microsecond)
			case "reference_overflow":
				for n := 1; n <= maxTaskDownloadReferences+1; n++ {
					m.refs["system_backup_v2_check_results"] = append(m.refs["system_backup_v2_check_results"], int64(n))
				}
			}
			queries := len(f.db.queries)
			err = results.Finish(context.Background(), c, DownloadResultObservation{Outcome: "interrupted", BytesWritten: 3})
			wantSuccess := mode == "revoked" || mode == "past_owner_deadline"
			if (err == nil) != wantSuccess {
				t.Fatal("independent result owner source", mode, err, f.db.calls)
			}
			if wantSuccess && (f.db.resultInserts != 1 || f.db.commits != 2 || f.db.record.Claim != "") {
				t.Fatal("revocation prevented recording/release")
			}
			if !wantSuccess && (f.db.resultInserts != 0 || f.db.commits != 1 || f.db.record.Claim != c.record.Claim) {
				t.Fatal("invalid owner/reference left partial result")
			}
			for _, q := range f.db.queries[queries:] {
				if strings.Contains(q, "FROM system_backup_login_") || strings.Contains(q, "FROM system_backup_user_security") {
					t.Fatal("result tried to reauthorize revoked session", q)
				}
			}
			if m.ownerReads == 0 || len(m.lockedStages) == 0 {
				t.Fatal("result bypassed concrete owner/reference locks")
			}
		})
	}
}
