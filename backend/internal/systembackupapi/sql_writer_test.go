package systembackupapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	read "clawreef/internal/systembackupread"
)

func testExecutionProfile() ExecutionProfile {
	return ExecutionProfile{InstallationID: "installation_admission", Revision: "v1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "recovery-zone", RestoreTargetRef: "isolated-v1", RestoreTargetHash: strings.Repeat("a", 64)}
}

func TestTaskRequestRejectsAmbiguityAndUnsafeParts(t *testing.T) {
	w, err := NewSQLTaskWriter(testExecutionProfile())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`null`, `[]`, `{"task_purpose":null}`, `{"task_purpose":"acceptance","task_purpose":"functional_test"}`, `{"owner":"other"}`, `{"requested_parts":[]}`, `{"requested_parts":["mysql","mysql"]}`, `{"requested_parts":["mysql"]}`, `{"requested_parts":["secrets"]}`, `{} {}`} {
		if _, err := w.Prepare(context.Background(), read.BackupTask, "createSystemBackup", json.RawMessage(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	a, err := w.Prepare(context.Background(), read.BackupTask, "createSystemBackup", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.Prepare(context.Background(), read.BackupTask, "createSystemBackup", json.RawMessage(`{"requested_parts":["secret_bundle","workspace","mysql","redis","deployment_resources","object_storage"],"task_purpose":"acceptance"}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.(*preparedSQLTask).hash != b.(*preparedSQLTask).hash {
		t.Fatal("equivalent defaults/part order hash differently")
	}
	if _, err := w.Prepare(context.Background(), read.BackupTask, "createSystemBackup", json.RawMessage(`{"TASK_PURPOSE":"acceptance"}`)); err == nil {
		t.Fatal("case-insensitive request alias accepted")
	}
	if _, err = w.Prepare(context.Background(), read.PreflightTask, "createSystemBackupPreflight", json.RawMessage(`{"source_public_id":"sbk_01234567890123456789012345678901"}`)); err == nil {
		t.Fatal("accepted legacy ID in v2")
	}
}

func TestExecutionProfileCopiedAndValidationClosed(t *testing.T) {
	p := testExecutionProfile()
	p.TargetRisks = []string{"same_failure_domain"}
	w, err := NewSQLTaskWriter(p)
	if err != nil {
		t.Fatal(err)
	}
	p.TargetRisks[0] = "source_overlap"
	if w.profile.TargetRisks[0] != "same_failure_domain" {
		t.Fatal("caller changed admitted profile")
	}
	p.RestoreTargetRef = "/etc/private"
	if _, err = NewSQLTaskWriter(p); err == nil {
		t.Fatal("path accepted as immutable ref")
	}
}
