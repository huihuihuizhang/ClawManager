package control

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"testing"

	"clawreef/internal/systembackup/quiesce"
)

func appFixture() AppProcess {
	return AppProcess{ID: "app-incarnation", Namespace: "source", NodeUID: "node-uid", ImageID: "sha256:image", Pod: quiesce.PodIdentity{Name: "app", UID: "pod-uid", Node: "node", Containers: []string{"containerd://old"}}}
}
func TestProcessPermitRefusesRevokedOwner(t *testing.T) {
	s, script := scriptStore(t, sqlStep{contains: "SELECT closed", rows: [][]driver.Value{{false}}}, sqlStep{contains: "SELECT revoked", rows: [][]driver.Value{{true}}})
	if release, e := (ProcessGate{Store: s, Process: appFixture()}).Enter(context.Background(), "api"); e == nil || release != nil || script.writes != 0 {
		t.Fatal("revoked process acquired permit")
	}
}
func TestResolverRequiresExactProcessAndRemoteCompletion(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{true: "completed", false: "remote-still-running"}[success], func(t *testing.T) {
			task, _, _ := grantFixture()
			task.Status = "acquiring_gate"
			p := appFixture()
			raw, _ := json.Marshal(p)
			steps := workerCommit(task)
			steps = append(steps, sqlStep{contains: "SELECT task_id,closed", rows: [][]driver.Value{{task.ID, true}}}, sqlStep{contains: "SELECT identity_json,revoked", rows: [][]driver.Value{{raw, false}}}, sqlStep{contains: "WHERE process_id=? ORDER BY token FOR UPDATE", rows: [][]driver.Value{{"permit", "api", p.ID}}})
			if success {
				steps = append(steps, workerCommit(task)...)
				steps = append(steps, sqlStep{contains: "SET revoked=TRUE", affected: 1}, sqlStep{contains: "INSERT INTO system_backup_mutation_resolutions", affected: 1}, sqlStep{contains: "DELETE FROM system_backup_mutations WHERE process_id=?", affected: 1})
			}
			s, script := scriptStore(t, steps...)
			calls := 0
			e := s.ResolveApplication(context.Background(), task, p, func(_ context.Context, observed AppProcess, permits []MutationPermit) error {
				calls++
				if observed.Pod.Containers[0] != "containerd://old" || len(permits) != 1 || permits[0].Token != "permit" {
					t.Fatal("proof identity changed")
				}
				if !success {
					return errors.New("remote effects still live")
				}
				return nil
			})
			if calls != 1 || success != (e == nil) {
				t.Fatal(e)
			}
			if !success && (script.writes != 0 || script.commits != 0) {
				t.Fatal("unproved permit removed")
			}
			if success && script.commits != 1 {
				t.Fatal("resolution not atomic")
			}
		})
	}
}
func TestLegacyResolverDoesNotAdoptOwnedOrAmbiguousPermit(t *testing.T) {
	task, _, _ := grantFixture()
	steps := workerCommit(task)
	steps = append(steps, sqlStep{contains: "SELECT task_id,closed", rows: [][]driver.Value{{task.ID, true}}}, sqlStep{contains: "WHERE token=? FOR UPDATE", rows: [][]driver.Value{{"legacy", "api", "another-process"}}})
	s, script := scriptStore(t, steps...)
	e := s.ResolveLegacyMutation(context.Background(), task, "legacy", appFixture(), func(context.Context, AppProcess, MutationPermit) error {
		t.Fatal("attempted proof for wrong owner")
		return nil
	})
	if e == nil || script.writes != 0 {
		t.Fatal("reassigned a permit")
	}
}
func TestApplicationCannotRegisterWhileGateClosed(t *testing.T) {
	s, script := scriptStore(t, sqlStep{contains: "SELECT closed", rows: [][]driver.Value{{true}}})
	if e := s.RegisterApplication(context.Background(), appFixture()); !errors.Is(e, ErrConflict) || script.writes != 0 {
		t.Fatal(e)
	}
}

func TestApplicationResolverLostCommitIsReadBackWithoutDeletingTwice(t *testing.T) {
	task, _, _ := grantFixture()
	p := appFixture()
	raw, _ := json.Marshal(p)
	steps := workerCommit(task)
	steps = append(steps, sqlStep{contains: "SELECT task_id,closed", rows: [][]driver.Value{{task.ID, true}}}, sqlStep{contains: "SELECT identity_json,revoked", rows: [][]driver.Value{{raw, false}}}, sqlStep{contains: "WHERE process_id=? ORDER BY token FOR UPDATE", rows: [][]driver.Value{{"permit", "api", p.ID}}})
	steps = append(steps, workerCommit(task)...)
	steps = append(steps, sqlStep{contains: "SET revoked=TRUE", affected: 1}, sqlStep{contains: "INSERT INTO system_backup_mutation_resolutions", affected: 1}, sqlStep{contains: "DELETE FROM system_backup_mutations WHERE process_id=?", affected: 1})
	s, script := scriptStore(t, steps...)
	script.loseCommit = true
	if s.ResolveApplication(context.Background(), task, p, func(context.Context, AppProcess, []MutationPermit) error { return nil }) == nil {
		t.Fatal("lost commit response reported as success")
	}
	writes := script.writes
	script.steps = append(workerCommit(task), sqlStep{contains: "SELECT task_id,closed", rows: [][]driver.Value{{task.ID, true}}}, sqlStep{contains: "SELECT identity_json,revoked", rows: [][]driver.Value{{raw, true}}})
	if e := s.ResolveApplication(context.Background(), task, p, func(context.Context, AppProcess, []MutationPermit) error {
		t.Fatal("repeated external proof after committed resolution")
		return nil
	}); e != nil || writes != script.writes {
		t.Fatal("committed resolution not idempotent", e)
	}
}

func TestApplicationResolverRechecksFenceAfterSlowProof(t *testing.T) {
	task, _, _ := grantFixture()
	p := appFixture()
	raw, _ := json.Marshal(p)
	steps := workerCommit(task)
	steps = append(steps, sqlStep{contains: "SELECT task_id,closed", rows: [][]driver.Value{{task.ID, true}}}, sqlStep{contains: "SELECT identity_json,revoked", rows: [][]driver.Value{{raw, false}}}, sqlStep{contains: "WHERE process_id=? ORDER BY token FOR UPDATE", rows: [][]driver.Value{{"permit", "api", p.ID}}})
	expired := task
	expired.LeaseUntil = 1
	steps = append(steps, workerCommit(expired)...)
	s, script := scriptStore(t, steps...)
	if e := s.ResolveApplication(context.Background(), task, p, func(context.Context, AppProcess, []MutationPermit) error { return nil }); e == nil || script.writes != 0 || script.commits != 0 {
		t.Fatal("expired controller deleted permits", e)
	}
}
