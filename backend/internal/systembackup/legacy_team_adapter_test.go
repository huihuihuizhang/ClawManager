package systembackup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/team"
	"github.com/minio/minio-go/v7"
)

type historicalTeamAuthorityFixture struct {
	ref     LegacyTeamReference
	keys    HistoricalTeamKeys
	revoked bool
	calls   int
}

type legacyStagingAuthorityFunc func(context.Context, LegacyStagingAccess) error

func (f legacyStagingAuthorityFunc) AuthorizeLegacyStaging(ctx context.Context, access LegacyStagingAccess) error {
	return f(ctx, access)
}

func (a *historicalTeamAuthorityFixture) AuthorizeHistoricalTeam(_ context.Context, r LegacyTeamAccess) error {
	a.calls++
	if a.revoked || r.Reference != a.ref {
		return errors.New("permission_denied")
	}
	return nil
}
func (a *historicalTeamAuthorityFixture) ResolveHistoricalTeam(_ context.Context, r LegacyTeamAccess) (HistoricalTeamKeys, error) {
	if a.revoked || r.Reference != a.ref || r.SigningVersion != "v1" {
		return HistoricalTeamKeys{}, errors.New("signing_key_unavailable")
	}
	return a.keys, nil
}

func TestHistoricalTeamArtifactUsesExactVersionAndHistoricalAuthority(t *testing.T) {
	store := testObjectStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	artifact := teamDataPublishedMetadataFixture(t, store, "historical-origin", key)
	ref := LegacyTeamReference{Origin: "historical-origin", BackupID: artifact.Manifest.Payload.BackupID, Commit: artifact.CommitReference}
	a := &historicalTeamAuthorityFixture{ref: ref, keys: HistoricalTeamKeys{PublicKey: pub, SigningVersion: "v1", Wrapper: AESKeyWrapper{Reference: SecretRef{"kubernetes", "fixture-key", "v1", "encryption"}, Key: make([]byte, 32)}}}
	op := "sop_11111111-1111-4111-8111-111111111111"
	if _, err := OpenHistoricalTeamArtifact(ctx, store, ref, op, "verify", nil); err == nil {
		t.Fatal("missing authority accepted")
	}
	wrong := *a
	wrong.keys.SigningVersion = "current-v2"
	if _, err := OpenHistoricalTeamArtifact(ctx, store, ref, op, "verify", &wrong); err == nil {
		t.Fatal("current key substituted for historical key")
	}
	h, err := OpenHistoricalTeamArtifact(ctx, store, ref, op, "verify", a)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.Verify(ctx, 2<<20); err != nil {
		t.Fatal(err)
	}
	d, err := h.Descriptor()
	if err != nil || d.Manifest.Payload.Purpose != "team_data" || d.Manifest.Payload.Consistency != "best_effort" {
		t.Fatal("legacy artifact upgraded", err)
	}
	d.Manifest.Payload.BackupID = "mutated"
	if again, _ := h.Descriptor(); again.Manifest.Payload.BackupID != ref.BackupID {
		t.Fatal("descriptor mutated live artifact")
	}
	// Simulate a changed current pointer, bypassing the immutable writer only in
	// this isolated object-store test. Historical recovery must retain its version.
	name, _ := store.key(ref.Commit.Key)
	if _, err = store.Client.PutObject(ctx, store.Bucket, name, bytes.NewReader([]byte("untrusted current pointer")), 25, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenHistoricalTeamArtifact(ctx, store, ref, op, "verify", a); err != nil {
		t.Fatal("followed latest instead of original version", err)
	}
	download, err := OpenHistoricalTeamArtifact(ctx, store, ref, op, "download", a)
	if err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if err = download.Consume(ctx, "mysql", 2<<20, func(r io.Reader) error { _, err := io.Copy(&data, r); return err }); err != nil || data.String() != "metadata-fixture-only" {
		t.Fatal("original part changed", err)
	}
	// Exercise the same encrypted handoff that public database workers consume.
	// No plaintext file or independently scheduled legacy restore is produced.
	restore, err := OpenHistoricalTeamArtifact(ctx, store, ref, "sdr_11111111-1111-4111-8111-111111111111", "restore", a)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	stageKey := bytes.Repeat([]byte{23}, 32)
	binding := staging.Binding{BackupID: ref.BackupID, Attempt: "original-attempt", Path: "mysql/legacy", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "public-task-grant"}
	grant := legacyStagingAuthorityFunc(func(_ context.Context, access LegacyStagingAccess) error {
		if access.Source.PublicOperationID != restore.access.PublicOperationID || access.Binding != binding || access.Name != "legacy.enc" || access.Part != "mysql" {
			return errors.New("permission_denied")
		}
		return nil
	})
	if _, err = restore.Stage(ctx, "mysql", 2<<20, root, "wrong.enc", stageKey, binding, grant); err == nil {
		t.Fatal("unbound staging name accepted")
	}
	receipt, err := restore.Stage(ctx, "mysql", 2<<20, root, "legacy.enc", stageKey, binding, grant)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := root.ReadFile(receipt.Name)
	if err != nil || bytes.Contains(ciphertext, data.Bytes()) {
		t.Fatal("plaintext handoff", err)
	}
	f, err := staging.OpenFile(ctx, root, receipt)
	if err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	err = staging.ConsumeCompressed(ctx, f, stageKey, binding, 2<<20, 2<<20, func(r io.Reader) error { _, e := io.Copy(&restored, r); return e })
	f.Close()
	if err != nil || !bytes.Equal(data.Bytes(), restored.Bytes()) {
		t.Fatal("encrypted handoff changed original data", err)
	}
	if _, err = restore.Stage(ctx, "mysql", 2<<20, root, "legacy.enc", stageKey, binding, grant); err == nil {
		t.Fatal("existing handoff overwritten")
	}
	if after, _ := root.ReadFile(receipt.Name); !bytes.Equal(after, ciphertext) {
		t.Fatal("existing handoff changed")
	}
	a.revoked = true
	if err = h.Verify(ctx, 2<<20); err == nil {
		t.Fatal("revoked original accepted")
	}
	if err = download.Consume(ctx, "mysql", 2<<20, func(io.Reader) error { t.Fatal("revoked data delivered"); return nil }); err == nil {
		t.Fatal("revoked consume accepted")
	}
	if _, err = json.Marshal(a.keys); err == nil || fmt.Sprintf("%+v", a.keys) != "HistoricalTeamKeys" {
		t.Fatal("keys serializable")
	}
}

func legacyTeamSQLFormatFixture(t *testing.T, omit string) []byte {
	t.Helper()
	tables, err := BuiltinSchema()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	write := func(v SQLRecord) {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	write(SQLRecord{Kind: "mysql_rows_v1"})
	for _, table := range tables {
		if table.Name == omit {
			continue
		}
		write(SQLRecord{Kind: "table", Table: &table})
		sum := sha256.New()
		count := int64(0)
		if table.Name == "team_work_items" {
			row := SQLRecord{Kind: "row"}
			for _, c := range table.Columns {
				v := team.Value("")
				switch c.Name {
				case "id", "team_id", "root_task_id":
					v = team.Value("1")
				case "status":
					v = team.Value("awaiting_review")
				case "result_json":
					v = team.Value("\x00\xff中断前产物")
				case "artifact_refs_json":
					v = team.Value(`["results/report.md"]`)
				default:
					if c.Nullable == "YES" {
						v = team.Null()
					}
				}
				row.Cells = append(row.Cells, v)
			}
			raw, _ := json.Marshal(row)
			sum.Write(append(raw, '\n'))
			write(row)
			count++
		}
		write(SQLRecord{Kind: "end_table", Count: count, SHA256: hex.EncodeToString(sum.Sum(nil))})
	}
	write(SQLRecord{Kind: "end"})
	return b.Bytes()
}

func TestLegacyTeamSQLBridgePreservesCompleteScopeAndBinaryData(t *testing.T) {
	raw := legacyTeamSQLFormatFixture(t, "")
	limits := domain.Limits{MaxRows: 100, MaxBytes: 8 << 20}
	s, err := DecodeLegacyTeamSQL(context.Background(), bytes.NewReader(raw), limits)
	if err != nil {
		t.Fatal(err)
	}
	known, _ := BuiltinSchema()
	if len(s.Tables) != len(known) {
		t.Fatal("scope dropped")
	}
	for _, table := range s.Tables {
		if table.Name == "team_work_items" {
			row := table.Rows[0]
			if row["status"].String() != "awaiting_review" || !bytes.Equal(row["result_json"].Bytes, []byte("\x00\xff中断前产物")) || row["artifact_refs_json"].Null {
				t.Fatal("source state or artifact changed")
			}
		}
	}
	for _, broken := range [][]byte{raw[:len(raw)-8], append(append([]byte(nil), raw...), []byte(`{"kind":"end"}`)...), legacyTeamSQLFormatFixture(t, "custom_team_templates")} {
		if _, err = DecodeLegacyTeamSQL(context.Background(), bytes.NewReader(broken), limits); err == nil {
			t.Fatal("incomplete or malformed scope accepted")
		}
	}
	if _, err = DecodeLegacyTeamSQL(context.Background(), bytes.NewReader(raw), domain.Limits{MaxRows: 100, MaxBytes: 64}); err == nil {
		t.Fatal("size limit ignored")
	}
}
