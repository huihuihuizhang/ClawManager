package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	b "clawreef/internal/systembackup/relaywire"
	d "clawreef/internal/systembackupdispatch"
)

// Certificate verification is real; SQL pointers, grants and all identity facts
// remain synthetic. These tests do not exercise B wire/cursor or real SQL.
func relayMessageFixture(c RelayPeerConfig) (d.Authority, d.JobBinding, b.RelayMessage) {
	a, j := relayDispatchInputs(c)
	m := b.RelayMessage{SchemaVersion: b.RelayVersion, InstallationID: a.InstallationID,
		TaskPublicID: a.TaskPublicID, TaskType: a.TaskType, AttemptNo: strconv.FormatUint(a.AttemptNo, 10),
		Phase: a.Phase, JobUnitKey: j.JobUnitKey, Namespace: j.Namespace, JobName: j.Name,
		JobUID: j.UID, JobGeneration: strconv.FormatUint(j.Generation, 10),
		RelayIdentityRef: j.RelayIdentityRef, RelayIdentityVersion: j.RelayIdentityVersion,
		Sequence: "1", Status: "ready"}
	return a, j, m
}

func TestRelayMessageRejectsEveryForeignIdentityAndConsumesProof(t *testing.T) {
	changes := map[string]func(*b.RelayMessage){
		"schema":        func(m *b.RelayMessage) { m.SchemaVersion = "other.v1" },
		"installation":  func(m *b.RelayMessage) { m.InstallationID = "installation_other" },
		"task":          func(m *b.RelayMessage) { m.TaskPublicID = "other" },
		"kind":          func(m *b.RelayMessage) { m.TaskType = "preflight" },
		"attempt":       func(m *b.RelayMessage) { m.AttemptNo = "01" },
		"phase":         func(m *b.RelayMessage) { m.Phase = "publish" },
		"unit":          func(m *b.RelayMessage) { m.JobUnitKey = "other" },
		"namespace":     func(m *b.RelayMessage) { m.Namespace = "other" },
		"name":          func(m *b.RelayMessage) { m.JobName = "other" },
		"uid":           func(m *b.RelayMessage) { m.JobUID = "other" },
		"generation":    func(m *b.RelayMessage) { m.JobGeneration = "01" },
		"relay":         func(m *b.RelayMessage) { m.RelayIdentityRef = "other" },
		"relay_version": func(m *b.RelayMessage) { m.RelayIdentityVersion = "other" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			auth, f, c := relayPeerFixture(t)
			a, j, m := relayMessageFixture(c)
			p, err := auth.AuthenticateRequest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
			defer cancel()
			wrong := m
			change(&wrong)
			tx := new(sql.Tx)
			now := time.Now().UTC().Truncate(time.Microsecond)
			if check, _, err := auth.BindDispatchMessage(ctx, tx, p, c.Binding.Scope, a, j, wrong, now); err != ErrAuth || check != nil {
				t.Fatal("foreign message reached transaction guard")
			}
			if _, _, err := auth.BindDispatchMessage(ctx, tx, p, c.Binding.Scope, a, j, m, now); err != ErrAuth {
				t.Fatal("repair reused rejected proof")
			}
			if f.db.begins != 0 {
				t.Fatal("message adapter opened SQL")
			}
		})
	}
}

func TestRelayMessageFreezesDataAndSharesFailure(t *testing.T) {
	for _, change := range []string{"sequence", "status", "result_hash", "result_id", "result_missing"} {
		t.Run(change, func(t *testing.T) {
			auth, f, c := relayPeerFixture(t)
			a, j, m := relayMessageFixture(c)
			m.Status = "completed"
			m.ResultEvidence = &b.RelayEvidence{PublicID: "sev_01234567-89ab-cdef-0123-456789abcdef", SHA256: strings.Repeat("a", 64)}
			p, err := auth.AuthenticateRequest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(p.Context(), time.Minute)
			defer cancel()
			tx := new(sql.Tx)
			now := time.Now().UTC().Truncate(time.Microsecond)
			check, first, err := auth.BindDispatchMessage(ctx, tx, p, c.Binding.Scope, a, j, m, now)
			if err != nil {
				t.Fatal(err)
			}
			original := copyRelayMessage(m)
			again, err := check.RecheckDispatchMessage(ctx, tx, c.Binding.Scope, a, j, original, now)
			if err != nil || !again.ValidUntil.Equal(first.ValidUntil) {
				t.Fatal("detached equal result changed validity", err)
			}
			if _, err := json.Marshal(check); err == nil {
				t.Fatal("message guard serialized")
			}
			if json.Unmarshal([]byte(`{}`), &DispatchRelayMessageCheck{}) == nil {
				t.Fatal("JSON minted message guard")
			}
			switch change {
			case "sequence":
				m.Sequence = "2"
			case "status":
				m.Status = "running"
			case "result_hash":
				m.ResultEvidence.SHA256 = strings.Repeat("b", 64)
			case "result_id":
				m.ResultEvidence.PublicID = "sev_other"
			case "result_missing":
				m.ResultEvidence = nil
			}
			copied := *check
			if _, err := copied.RecheckDispatchMessage(ctx, tx, c.Binding.Scope, a, j, m, now); err != ErrAuth {
				t.Fatal("changed message revived")
			}
			if _, err := check.RecheckDispatchMessage(ctx, tx, c.Binding.Scope, a, j, original, now); err != ErrAuth {
				t.Fatal("guard copy reset failure")
			}
			if f.db.begins != 0 {
				t.Fatal("message adapter opened SQL")
			}
		})
	}
}
