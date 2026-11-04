package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestSafeFailureDoesNotExposeDriverSecrets(t *testing.T) {
	err := fmt.Errorf("private DSN secret: %w", &mysql.MySQLError{Number: 1054, Message: "private row and password"})
	d := safeFailure("before", err)
	raw, _ := json.Marshal(d)
	if d.MySQLCode != 1054 || d.Reason != "mysql_read_rejected" || strings.Contains(string(raw), "private") || strings.Contains(string(raw), "password") {
		t.Fatal("unsafe or missing failure coordinates", string(raw))
	}
}

func TestSafeFailureDistinguishesSchemaAndBudget(t *testing.T) {
	for message, expected := range map[string]string{
		"legacy copy schema differs from reviewed source/copy variants": "copy_schema_variant_unreviewed",
		"backup import preservation budget exceeded":                    "rowproof_budget_exceeded",
	} {
		if got := safeFailure("before", fmt.Errorf("phase: %w", errors.New(message))); got.Reason != expected {
			t.Fatal("missing exact safe reason", got)
		}
	}
}

func TestSafeFailureUnknownAndDeadline(t *testing.T) {
	if d := safeFailure("before", errors.New("secret unreviewed message")); d.Reason != "read_or_proof_rejected" {
		t.Fatal("unknown error was exposed", d)
	}
	if d := safeFailure("before", context.DeadlineExceeded); d.Reason != "proof_deadline_exceeded" {
		t.Fatal("deadline coordinate missing", d)
	}
}

func TestSafeFailureCopyInventoryRejectsOriginalDatabaseBeforeConnecting(t *testing.T) {
	root := t.TempDir()
	dsn, inventory := filepath.Join(root, "private.dsn"), filepath.Join(root, "inventory.json")
	if err := os.WriteFile(inventory, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, database := range []string{"clawmanager", "other", "cm_import_invalid"} {
		if err := os.WriteFile(dsn, []byte("root:TEST_ONLY@tcp(127.0.0.1:1)/"+database), 0600); err != nil {
			t.Fatal(err)
		}
		err := runPhase(context.Background(), dsn, inventory, "copy-inventory", io.Discard)
		if err == nil || safeFailure("copy-inventory", err).Reason != "isolated_copy_identity_rejected" {
			t.Fatal("copy inventory must reject original/non-copy databases without connecting", database, err)
		}
	}
}
