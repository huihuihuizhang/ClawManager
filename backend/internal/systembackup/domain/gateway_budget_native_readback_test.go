package domain_test

import (
	"bytes"
	"database/sql"
	"errors"
	"testing"

	"clawreef/internal/repository"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	mysql "github.com/go-sql-driver/mysql"
)

func validateNativeGatewayHistory(t *testing.T, f *gatewayNative, reader *sql.DB, name, user, keyToken, aliasToken string, original domain.Snapshot) {
	t.Helper()
	actual, err := domain.CaptureSource(f.ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, name, f.uuid)
	if err != nil {
		t.Fatal("independent actual gateway snapshot")
	}
	validateNativeGatewayAttributionHistory(t, original, actual)
	for _, table := range []string{"gateway_key_budget_reservations", "gateway_key_budget_ledger"} {
		expected, got := nativeGatewayTable(original, table), nativeGatewayTable(actual, table)
		if len(got.Rows) != len(expected.Rows) {
			t.Fatal("native unsettled/ledger row loss", table)
		}
		for n, row := range expected.Rows {
			for column, value := range row {
				cell := got.Rows[n][column]
				if cell.Null != value.Null || !bytes.Equal(cell.Bytes, value.Bytes) {
					t.Fatal("native raw budget amount/NULL/id/time/status changed", table, column)
				}
			}
		}
	}
	for n, row := range nativeGatewayTable(original, "gateway_keys").Rows {
		got := nativeGatewayTable(actual, "gateway_keys").Rows[n]
		if got["status"].String() != "revoked" {
			t.Fatal("target key remains usable")
		}
		for column, value := range row {
			if row["status"].String() != "revoked" && (column == "status" || column == "revoked_at" || column == "revoked_by_user_id" || column == "revocation_reason" || column == "updated_at") {
				continue
			}
			cell := got[column]
			if cell.Null != value.Null || !bytes.Equal(cell.Bytes, value.Bytes) {
				t.Fatal("native HMAC/actor/expired/null/definition/history changed", column)
			}
		}
	}
	if len(nativeGatewayTable(actual, "instance_gateway_token_aliases").Rows) != 0 {
		t.Fatal("legacy aliases restored")
	}
	before, _ := domain.Digest(actual)
	session := f.upper(name, user, f.nonce)
	keys := repository.NewGatewayKeyRepository(session)
	instances := repository.NewInstanceRepository(session)
	// HMAC still matches the old token; real authentication refuses on status.
	if key, err := keys.GetByToken(keyToken); err != nil || key == nil || key.Status != "revoked" {
		t.Fatal("retained HMAC positive lookup control")
	}
	if key, err := services.NewGatewayKeyService(keys, instances, nil).Resolve(keyToken); err != nil || key != nil {
		t.Fatal("old key token became usable")
	}
	for _, token := range []string{"source-token", aliasToken} {
		if instance, err := instances.GetByAccessToken(token); err != nil || instance != nil {
			t.Fatal("old instance token or alias became usable")
		}
	}
	t.Log("real target authentication: retained HMAC lookup matches revoked key; old gateway key, instance token and alias all refused PASS")
	if _, err := keys.GetBudgetUsage(f.ctx, 9223372036854775806); err == nil {
		t.Fatal("write-side getter unexpectedly succeeded with SELECT-only reader")
	}
	t.Log("actual SELECT-only repository GetBudgetUsage write attempt refused PASS")
	session.Close()
	for _, statement := range []string{
		"UPDATE gateway_keys SET budget_spent=budget_spent WHERE 1=0",
		"DELETE FROM gateway_key_budget_reservations WHERE 1=0",
		"INSERT INTO gateway_key_budget_ledger(reservation_id,gateway_key_id,actual_cost,recorded_at) SELECT 'unused',0,0,CURRENT_TIMESTAMP() WHERE FALSE",
	} {
		_, err := reader.ExecContext(f.ctx, statement)
		var denied *mysql.MySQLError
		if !errors.As(err, &denied) || denied.Number != 1142 {
			t.Fatal("expected actual zero-row DML privilege denial1142")
		}
		t.Logf("actual independent reader MySQL 1142 denial PASS: %s", statement)
	}
	after, err := domain.CaptureSource(f.ctx, reader, domain.Limits{MaxRows: 1000, MaxBytes: 8 << 20}, name, f.uuid)
	if err != nil {
		t.Fatal("post-auth/getter independent capture")
	}
	if hash, _ := domain.Digest(after); hash != before {
		t.Fatal("SELECT-only auth/negative getter changed history")
	}
	t.Log("independent raw-cell readback: DECIMAL/NULL/IDs/HMAC/actors/old reset/review/history preserved; SELECT-only auth and denial probes leave digest unchanged PASS")
}
