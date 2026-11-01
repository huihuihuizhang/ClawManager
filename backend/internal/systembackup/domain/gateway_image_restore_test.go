package domain

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
)

func imageFixtureTable(s *Snapshot, name string) *Table {
	for n := range s.Tables {
		if s.Tables[n].Name == name {
			return &s.Tables[n]
		}
	}
	return nil
}

func imageTestCipher(row Row, plain, aad []byte) []byte {
	block, _ := aes.NewCipher(row["encryption_key"].Bytes)
	gcm, _ := cipher.NewGCM(block)
	nonce := []byte("twelve-bytes")
	return gcm.Seal(append([]byte(nil), nonce...), nonce, plain, aad)
}

// Independent migration072/073/074 projection. Native SQL tests must separately
// execute those trusted SQL files; this is not a production schema observation.
func imageRestoreFixture() (Snapshot, []byte) {
	s, _, _ := gatewayRestoreFixture()
	binaryKey := make([]byte, 32)
	for n := range binaryKey {
		binaryKey[n] = byte(n * 17)
	}
	artifact := Row{"id": Text("img_" + strings.Repeat("c", 32)), "user_id": Text("4"), "instance_id": {Null: true}, "gateway_key_id": Text("9223372036854775806"), "model_id": Text("3"), "request_id": Text("image-original"), "media_type": Text("image/png"), "byte_size": Text("4"), "encryption_key": {Bytes: binaryKey}, "ready": Text("1"), "created_at": Text("2025-01-01 00:00:00"), "expires_at": Text("2025-01-08 00:00:00")}
	job := Row{"request_id": Text("image-original"), "scope_hash": Text(strings.Repeat("d", 64)), "idempotency_hash": Text(strings.Repeat("e", 64)), "request_hash": Text(strings.Repeat("f", 64)), "user_id": artifact["user_id"], "instance_id": artifact["instance_id"], "gateway_key_id": artifact["gateway_key_id"], "model_id": artifact["model_id"], "state": Text("running"), "reservation_id": Text("reserved-expired"), "estimate": Text("9999999999.99999999"), "charge": Text("0.00000000"), "settled": Text("0"), "result_metadata": {Null: true}, "error_code": Text(""), "deadline_at": Text("2025-01-01 00:01:00"), "created_at": Text("2025-01-01 00:00:00"), "updated_at": Text("2025-01-01 00:00:00"), "analytics_context": {Null: true}, "analytics_outcome": {Null: true}, "analytics_recorded": Text("0")}
	types := map[string]string{"id": "varchar(64)", "request_id": "varchar(64)", "scope_hash": "char(64)", "idempotency_hash": "char(64)", "request_hash": "char(64)", "user_id": "int", "instance_id": "int", "gateway_key_id": "bigint", "model_id": "int", "state": "varchar(16)", "reservation_id": "varchar(64)", "estimate": "decimal(18,8)", "charge": "decimal(18,8)", "settled": "tinyint(1)", "result_metadata": "longtext", "error_code": "varchar(64)", "deadline_at": "datetime", "created_at": "datetime", "updated_at": "datetime", "analytics_context": "longtext", "analytics_outcome": "longtext", "analytics_recorded": "tinyint(1)", "media_type": "varchar(32)", "byte_size": "bigint", "encryption_key": "varbinary(32)", "ready": "tinyint(1)", "expires_at": "datetime"}
	for _, entry := range []struct {
		name string
		row  Row
		pk   string
	}{{"gateway_image_artifacts", artifact, "id"}, {"gateway_image_jobs", job, "request_id"}} {
		table := Table{Name: entry.name, Engine: "InnoDB", PrimaryKey: []string{entry.pk}, Rows: []Row{entry.row}}
		if entry.name == "gateway_image_jobs" {
			table.UniqueKeys = []UniqueKey{{Name: "idx_image_job_idempotency", Columns: []string{"scope_hash", "idempotency_hash"}}}
		}
		for _, name := range sortedKeys(entry.row) {
			kind := types[name]
			if name == "request_id" && entry.name == "gateway_image_artifacts" {
				kind = "varchar(100)"
			}
			nullable := name == "instance_id" || name == "gateway_key_id" || name == "reservation_id" || name == "result_metadata" || name == "analytics_context" || name == "analytics_outcome"
			table.Columns = append(table.Columns, Column{Name: name, Type: kind, Nullable: nullable})
		}
		s.Tables = append(s.Tables, table)
	}
	find(s, "gateway_key_budget_reservations").Rows[0]["settlement_status"] = Text("image_pending")
	raw := imageTestCipher(artifact, []byte("PNG!"), artifact["id"].Bytes)
	return s, raw
}

func TestGatewayImageOwnerShapeClosureAndInertProjection(t *testing.T) {
	s, _ := imageRestoreFixture()
	if e := validateImageRows(context.Background(), s, false); e != nil {
		t.Fatal(e)
	}
	before, _ := Digest(s)
	first, e := imageProjection(s, "2026-11-01T00:00:00Z")
	if e != nil {
		t.Fatal(e)
	}
	for _, table := range s.Tables {
		if isGatewayImageTable(table.Name) {
			for _, row := range table.Rows {
				if e := normalizeGatewayImageRow(table.Name, row, "2026-11-01T00:00:00Z"); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	if validateImageRows(context.Background(), s, true) != nil {
		t.Fatal("normalized image rows rejected")
	}
	second, _ := imageProjection(s, "2026-11-01T00:00:00Z")
	if first != second {
		t.Fatal("projection is not deterministic/idempotent")
	}
	job := find(s, "gateway_image_jobs").Rows[0]
	if job["state"].String() != "unknown" || job["charge"].String() != "0.00000000" || job["settled"].String() != "1" || job["analytics_recorded"].String() != "1" || find(s, "gateway_key_budget_reservations").Rows[0]["settlement_status"].String() != "image_pending" {
		t.Fatal("quarantine changed charge/hold or left replay enabled")
	}
	after, _ := Digest(s)
	if before == after {
		t.Fatal("fixture did not exercise normalization")
	}
}

func TestGatewayImageRejectsUnknownShapeOrUnclosedHold(t *testing.T) {
	for _, mode := range []string{"unknown-column", "unknown-state", "orphan-hold", "duplicate-job-hold", "wrong-key", "wrong-owner", "wrong-estimate", "missing-reservation", "future-result-json", "missing-artifact", "wrong-artifact-owner", "bad-key-length"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := imageRestoreFixture()
			job := find(s, "gateway_image_jobs").Rows[0]
			artifact := find(s, "gateway_image_artifacts").Rows[0]
			switch mode {
			case "unknown-column":
				table := imageFixtureTable(&s, "gateway_image_jobs")
				table.Columns = append(table.Columns, Column{Name: "future_provider_token", Type: "text"})
				table.Rows[0]["future_provider_token"] = Text("secret")
			case "unknown-state":
				job["state"] = Text("retry")
			case "orphan-hold":
				job["reservation_id"] = Cell{Null: true}
				job["gateway_key_id"] = Cell{Null: true}
			case "duplicate-job-hold":
				table := imageFixtureTable(&s, "gateway_image_jobs")
				row := cloneRow(job)
				row["request_id"] = Text("second-job")
				row["idempotency_hash"] = Text(strings.Repeat("1", 64))
				table.Rows = append(table.Rows, row)
			case "wrong-key":
				job["gateway_key_id"] = Text("105")
			case "wrong-owner":
				job["user_id"] = Text("8")
			case "wrong-estimate":
				job["estimate"] = Text("0.00000001")
			case "missing-reservation":
				job["reservation_id"] = Text("absent")
			case "future-result-json":
				job["result_metadata"] = Text(`{"new_dispatch_field":true}`)
			case "missing-artifact":
				job["result_metadata"] = Text(`{"artifact_ids":["img_absent"]}`)
			case "wrong-artifact-owner":
				artifact["user_id"] = Text("5")
			case "bad-key-length":
				artifact["encryption_key"] = Text("short")
			}
			if validateImageRows(context.Background(), s, false) == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}

func TestGatewayImageEmptyTablesStillRejectOrphanHoldInNormalize(t *testing.T) {
	s, _ := imageRestoreFixture()
	for n := range s.Tables {
		if isGatewayImageTable(s.Tables[n].Name) {
			s.Tables[n].Rows = nil
		}
	}
	p := imageTestPolicy(s)
	if validateImageRows(context.Background(), s, false) == nil {
		t.Fatal("empty images hid image_pending orphan hold")
	}
	if _, e := Normalize(context.Background(), s, s.Tables, p); e == nil {
		t.Fatal("common Normalize accepted empty images plus orphan hold")
	}
	find(s, "gateway_key_budget_reservations").Rows[0]["settlement_status"] = Text("reserved")
	if _, e := Normalize(context.Background(), s, s.Tables, p); e != nil {
		t.Fatal("legitimate empty images without image_pending rejected", e)
	}
}
