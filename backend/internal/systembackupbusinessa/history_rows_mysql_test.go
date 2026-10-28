//go:build systembackup_mysql

package systembackupbusinessa

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// TestABusinessHistoryRowsMySQL checks that A's three new complete rows fit
// the real migrated MySQL column shapes. Its B proof fixtures are synthetic;
// this test does not authenticate a dump or execute a production restore.
func TestABusinessHistoryRowsMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	run := os.Getenv("D_INVARIANT_RUN")
	uid := os.Getenv("D_INVARIANT_NAMESPACE_UID")
	password := os.Getenv("MYSQL_ROOT_PASSWORD")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) ||
		!regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(uid) || password == "" {
		t.Fatal("isolated MySQL run marker and credential required")
	}
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var gotRun, gotUID, pinnedUUID, actualUUID string
	if err := admin.QueryRowContext(ctx,
		"SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").
		Scan(&gotRun, &gotUID, &pinnedUUID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&actualUUID); err != nil {
		t.Fatal(err)
	}
	if gotRun != run || gotUID != uid || pinnedUUID != actualUUID {
		t.Fatal("isolated MySQL identity mismatch")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	databaseName := "abiz_" + hex.EncodeToString(nonce[:])
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var currentRun, currentUID, currentPinnedUUID, currentUUID string
		if err := admin.QueryRowContext(cleanupCtx,
			"SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").
			Scan(&currentRun, &currentUID, &currentPinnedUUID); err != nil ||
			currentRun != run || currentUID != uid || currentPinnedUUID != actualUUID {
			t.Error("CLEANUP_PENDING A business database marker identity")
			return
		}
		if err := admin.QueryRowContext(cleanupCtx, "SELECT @@server_uuid").Scan(&currentUUID); err != nil || currentUUID != actualUUID {
			t.Error("CLEANUP_PENDING A business database identity")
			return
		}
		if _, err := admin.ExecContext(cleanupCtx, "DROP DATABASE "+databaseName); err != nil {
			t.Error("CLEANUP_PENDING A business database drop")
			return
		}
		var count int
		if err := admin.QueryRowContext(cleanupCtx,
			"SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=?", databaseName).
			Scan(&count); err != nil || count != 0 {
			t.Error("CLEANUP_PENDING A business database absence")
			return
		}
		t.Log("CLEANED A business run-owned database")
	}()
	for _, table := range []string{"model_invocations", "audit_events", "cost_records"} {
		statement := fmt.Sprintf("CREATE TABLE %s.%s LIKE clawmanager.%s", databaseName, table, table)
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			t.Fatalf("clone migrated %s table: %v", table, err)
		}
	}
	cfg.DBName = databaseName
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope, invocation, invocationMap, sessions := modelInvocationFixture(t)
	invocations, err := NormalizeModelInvocationsForRestore(ctx, scope,
		[]ModelInvocationRestoreSource{invocation}, []ModelInvocationRestoreMapping{invocationMap},
		sessions, "sev_model_invocations", &modelInvocationProofFixture{})
	if err != nil || len(invocations) != 1 {
		t.Fatalf("normalize model invocation: %v", err)
	}
	_, audit, auditMap, auditSessions := auditEventFixture(t)
	audits, err := NormalizeAuditEventsForRestore(ctx, scope,
		[]AuditEventRestoreSource{audit}, []AuditEventRestoreMapping{auditMap},
		auditSessions, "sev_audit_events", &auditEventProofFixture{})
	if err != nil || len(audits) != 1 {
		t.Fatalf("normalize audit event: %v", err)
	}
	_, cost, costMap, costSessions := costRecordFixture(t)
	costs, err := NormalizeCostRecordsForRestore(ctx, scope,
		[]CostRecordRestoreSource{cost}, []CostRecordRestoreMapping{costMap},
		costSessions, "sev_cost_records", &costRecordProofFixture{})
	if err != nil || len(costs) != 1 {
		t.Fatalf("normalize cost record: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	m := invocations[0]
	if err := insertAHistoryRow(ctx, tx, "model_invocations",
		"id,trace_id,session_id,request_id,user_id,instance_id,instance_mode,runtime_type,gateway_id,runtime_pod_id,model_id,provider_type,requested_model,actual_provider_model,traffic_class,request_payload,response_payload,prompt_tokens,completion_tokens,total_tokens,cached_tokens,reasoning_tokens,latency_ms,is_streaming,status,error_message,created_at,completed_at",
		m.ID, m.TraceID, m.SessionID, m.RequestID, m.UserID, m.InstanceID, m.InstanceMode,
		m.RuntimeType, m.GatewayID, m.RuntimePodID, m.ModelID, m.ProviderType,
		m.RequestedModel, m.ActualProviderModel, m.TrafficClass, m.RequestPayload,
		m.ResponsePayload, m.PromptTokens, m.CompletionTokens, m.TotalTokens,
		m.CachedTokens, m.ReasoningTokens, m.LatencyMs, m.IsStreaming, m.Status,
		m.ErrorMessage, m.CreatedAt, m.CompletedAt); err != nil {
		t.Fatal(err)
	}
	a := audits[0]
	if err := insertAHistoryRow(ctx, tx, "audit_events",
		"id,trace_id,session_id,request_id,user_id,instance_id,instance_mode,runtime_type,gateway_id,runtime_pod_id,invocation_id,event_type,traffic_class,severity,message,details,created_at",
		a.ID, a.TraceID, a.SessionID, a.RequestID, a.UserID, a.InstanceID,
		a.InstanceMode, a.RuntimeType, a.GatewayID, a.RuntimePodID, a.InvocationID,
		a.EventType, a.TrafficClass, a.Severity, a.Message, a.Details, a.CreatedAt); err != nil {
		t.Fatal(err)
	}
	c := costs[0]
	if err := insertAHistoryRow(ctx, tx, "cost_records",
		"id,trace_id,session_id,request_id,user_id,instance_id,instance_mode,runtime_type,gateway_id,runtime_pod_id,invocation_id,model_id,provider_type,model_name,currency,prompt_tokens,completion_tokens,total_tokens,input_unit_price,output_unit_price,estimated_cost,actual_cost,internal_cost,recorded_at",
		c.ID, c.TraceID, c.SessionID, c.RequestID, c.UserID, c.InstanceID,
		c.InstanceMode, c.RuntimeType, c.GatewayID, c.RuntimePodID, c.InvocationID,
		c.ModelID, c.ProviderType, c.ModelName, c.Currency, c.PromptTokens,
		c.CompletionTokens, c.TotalTokens, c.InputUnitPrice, c.OutputUnitPrice,
		c.EstimatedCost, c.ActualCost, c.InternalCost, c.RecordedAt); err != nil {
		t.Fatal(err)
	}
	var requestPayload, responsePayload, status, errorMessage string
	if err := tx.QueryRowContext(ctx,
		"SELECT request_payload,response_payload,status,error_message FROM model_invocations WHERE id=?", m.ID).
		Scan(&requestPayload, &responsePayload, &status, &errorMessage); err != nil {
		t.Fatal(err)
	}
	if requestPayload != "[REDACTED]" || responsePayload != "[REDACTED]" ||
		errorMessage != "[REDACTED]" || status != m.Status {
		t.Fatal("model invocation lost redaction or terminal status")
	}
	var message, details string
	if err := tx.QueryRowContext(ctx,
		"SELECT message,details FROM audit_events WHERE id=?", a.ID).
		Scan(&message, &details); err != nil {
		t.Fatal(err)
	}
	if message != "[REDACTED]" || details != "[REDACTED]" {
		t.Fatal("audit event lost redaction")
	}
	var inputPrice, outputPrice, estimated, actual, internal string
	if err := tx.QueryRowContext(ctx,
		"SELECT CAST(input_unit_price AS CHAR),CAST(output_unit_price AS CHAR),CAST(estimated_cost AS CHAR),CAST(actual_cost AS CHAR),CAST(internal_cost AS CHAR) FROM cost_records WHERE id=?", c.ID).
		Scan(&inputPrice, &outputPrice, &estimated, &actual, &internal); err != nil {
		t.Fatal(err)
	}
	if inputPrice != c.InputUnitPrice || outputPrice != c.OutputUnitPrice ||
		estimated != c.EstimatedCost || actual != *c.ActualCost || internal != c.InternalCost {
		t.Fatal("cost record DECIMAL precision changed")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS A business history rows fit migrated MySQL columns")
}

func insertAHistoryRow(ctx context.Context, tx *sql.Tx, table, columns string, values ...any) error {
	count := strings.Count(columns, ",") + 1
	if count != len(values) {
		return fmt.Errorf("%s column/value count mismatch: %d/%d", table, count, len(values))
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", count), ",")
	_, err := tx.ExecContext(ctx, "INSERT INTO "+table+" ("+columns+") VALUES ("+placeholders+")", values...)
	return err
}
