//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

// Native scenarios accept ONLY already verified A issuer output from
// nativeSignerIssuedInputs. They mint no replacement grant or Passed result.
// Top-level lifecycle roots are added after A's target-bound issuer helper
// exists; these functions must not be counted as executed tests themselves.
func nativeSignerForbidDML(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture) func() {
	t.Helper()
	// Four server triggers make ANY replay/resolve INSERT or UPDATE an actual
	// SQL error; retaining equal rows after an UPDATE does not satisfy this case.
	triggers := []string{"owned_signer_head_insert", "owned_signer_head_update", "owned_signer_grant_insert", "owned_signer_grant_update"}
	for index, name := range triggers {
		table, verb := "system_backup_signing_resource_heads", "INSERT"
		if index >= 2 {
			table = "system_backup_signing_resource_grants"
		}
		if index%2 == 1 {
			verb = "UPDATE"
		}
		if _, err := f.n.root.ExecContext(ctx, "CREATE TRIGGER `"+name+"` BEFORE "+verb+" ON `"+table+"` FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned_signer_replay_dml'"); err != nil {
			t.Fatal("owned replay DML guard", err)
		}
	}
	return func() {
		for _, name := range triggers {
			if _, err := f.n.root.ExecContext(ctx, "DROP TRIGGER `"+name+"`"); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func runNativeSignerLifecycle(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput) {
	t.Helper()
	n := f.n
	result, err := n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs)
	if err != nil || len(result.Items) != 2 {
		t.Fatal("native original four-row install", err)
	}
	nativeSignerExactFour(t, ctx, f, inputs)
	nativeSignerRejectIndexedStateAndSignatureDrift(t, ctx, f, inputs)
	consumer := nativeSignerConsumer(t, ctx, f, inputs, true)
	if consumer.Rollback() != nil {
		t.Fatal("native SELECT-only consumer close")
	}
	var rowVersion uint64
	p := inputs[0].Pin
	err = n.consumer.QueryRowContext(ctx, `SELECT row_version FROM system_backup_signing_resource_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? FOR UPDATE`, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose).Scan(&rowVersion)
	requireNativeAuthorityDenied(t, err)
	allowDML := nativeSignerForbidDML(t, ctx, f)
	replayed, err := n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs)
	if err != nil || len(replayed.Items) != 2 || !replayed.Items[0].Replayed || !replayed.Items[1].Replayed {
		t.Fatal("actual replay attempted a write", err)
	}
	allowDML()
	nativeSignerExactFour(t, ctx, f, inputs)
	revoked := nativeSignerRevoke(t, ctx, f, inputs)
	result, err = n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, revoked)
	if err != nil || len(result.Items) != 2 || result.Items[0].Comparison.State != "revoked" || result.Items[1].Comparison.State != "revoked" {
		t.Fatal("native terminal four-row revoke", err)
	}
	nativeSignerExactFour(t, ctx, f, revoked)
	consumer = nativeSignerConsumer(t, ctx, f, revoked, false)
	if consumer.Rollback() != nil {
		t.Fatal("revoked data read close")
	}
	if _, err = n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs); err == nil {
		t.Fatal("native revoked grant revived")
	}
	if _, err = n.f.i.ResolveSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs); err == nil {
		t.Fatal("old active tuple resolved over actual revoked SQL")
	}
	if _, err = n.f.i.ResolveSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, revoked); err != nil {
		t.Fatal("actual revoked exact tuple did not resolve", err)
	}
}

func runNativeSignerRollbackAndLostACK(t *testing.T, ctx context.Context, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput) {
	t.Helper()
	n := f.n
	if _, err := n.root.ExecContext(ctx, `CREATE TRIGGER owned_signer_install_fail BEFORE INSERT ON system_backup_signing_resource_grants FOR EACH ROW BEGIN IF NEW.purpose='catalog_record' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned_signer_install_rollback'; END IF; END`); err != nil {
		t.Fatal(err)
	}
	result, err := n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs)
	if err == nil || errors.Is(err, ErrCommitUnknown) || result.Version != "" {
		t.Fatal("mid-install SQL failure became success/unknown", err)
	}
	for _, table := range []string{"system_backup_signing_resource_heads", "system_backup_signing_resource_grants"} {
		var count int
		if n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("mid-install trigger left partial real rows", table)
		}
	}
	if _, err := n.root.ExecContext(ctx, `DROP TRIGGER owned_signer_install_fail`); err != nil {
		t.Fatal(err)
	}
	lost := &nativeAuthorityLostAck{base: n.installerConnector}
	lost.armed.Store(true)
	db := sql.OpenDB(lost)
	db.SetMaxOpenConns(4)
	defer db.Close()
	writer := *n.f.i
	writer.db = db
	result, err = writer.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs)
	if !errors.Is(err, ErrCommitUnknown) || result.Version != "" || lost.committed.Load() != 1 || lost.suppressed.Load() != 1 {
		t.Fatal("actual successful COMMIT ACK loss was not unknown", err)
	}
	nativeSignerExactFour(t, ctx, f, inputs)
	writes := lost.execs.Load()
	// Resolve on the ORIGINAL independent installer pool, never the fault
	// connector. Real server triggers forbid DML on that independent pool too;
	// the fault connector's unchanged counter alone cannot prove no writes there.
	allowDML := nativeSignerForbidDML(t, ctx, f)
	resolved, err := n.f.i.ResolveSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs)
	if err != nil || len(resolved.Items) != 2 || !resolved.Items[0].Replayed || !resolved.Items[1].Replayed || lost.execs.Load() != writes {
		t.Fatal("independent native original tuple resolve failed", err)
	}
	allowDML()
	nativeSignerExactFour(t, ctx, f, inputs)
	revoked := nativeSignerRevoke(t, ctx, f, inputs)
	if _, err := n.root.ExecContext(ctx, `CREATE TRIGGER owned_signer_revoke_fail BEFORE UPDATE ON system_backup_signing_resource_grants FOR EACH ROW BEGIN IF OLD.purpose='catalog_record' AND NEW.grant_state='revoked' THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned_signer_revoke_rollback'; END IF; END`); err != nil {
		t.Fatal(err)
	}
	if result, err = n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, revoked); err == nil || errors.Is(err, ErrCommitUnknown) || result.Version != "" {
		t.Fatal("mid-revoke SQL failure became success/unknown", err)
	}
	nativeSignerExactFour(t, ctx, f, inputs)
	if _, err := n.root.ExecContext(ctx, `DROP TRIGGER owned_signer_revoke_fail`); err != nil {
		t.Fatal(err)
	}
	if _, err = n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, revoked); err != nil {
		t.Fatal("exact same original revoke did not apply after owned fault removed", err)
	}
	nativeSignerExactFour(t, ctx, f, revoked)
}

func runNativeSignerLockCase(t *testing.T, ctx context.Context, cancel context.CancelFunc, f *nativeSigningSQLFixture, inputs []SigningResourceSQLInput, blocked string) {
	t.Helper()
	n := f.n
	if _, err := n.f.i.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, inputs); err != nil {
		t.Fatal(err)
	}
	revoked := nativeSignerRevoke(t, ctx, f, inputs)
	var blocker *sql.Tx
	if blocked == "head:acceptance_record" {
		blocker = nativeSignerConsumer(t, ctx, f, inputs, true)
	} else {
		// Diagnostic SELECT-only blocker, NOT an A terminal approval: hold
		// original current admin then only catalog grant to expose later order.
		var err error
		blocker, err = n.consumer.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		p := inputs[1].Pin
		var username, role, provider string
		var active bool
		if blocker.QueryRowContext(ctx, `SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR SHARE`, p.Actor.UserID).Scan(&username, &role, &active, &provider) != nil || username != p.Actor.Username || role != "admin" || !active || provider != "local" {
			blocker.Rollback()
			t.Fatal("actual native current-admin shared prefix")
		}
		var sha string
		if blocker.QueryRowContext(ctx, `SELECT record_sha256 FROM system_backup_signing_resource_grants WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? AND grant_id=? AND record_revision=1 FOR SHARE`, p.Target.InstallationID, p.EnrollmentID, p.AuthorityID, p.Purpose, p.GrantID).Scan(&sha) != nil || sha != p.GrantSHA256 {
			blocker.Rollback()
			t.Fatal("actual diagnostic catalog grant shared lock")
		}
	}
	defer blocker.Rollback()
	var blockerID int64
	if blocker.QueryRowContext(ctx, `SELECT CONNECTION_ID()`).Scan(&blockerID) != nil || blockerID < 1 {
		t.Fatal("actual native blocker ID")
	}
	monitor := &nativeSignerLockMonitor{base: n.installerConnector, events: make(chan nativeSignerLockEvent, 64)}
	db := sql.OpenDB(monitor)
	db.SetMaxOpenConns(4)
	defer func() { blocker.Rollback(); cancel(); db.Close() }()
	writer := *n.f.i
	writer.db = db
	type outcome struct {
		receipt SigningResourceSQLReceipt
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		receipt, err := writer.ImportSigningResourceSQLAuthority(ctx, n.f.password, n.f.enrollment, revoked)
		done <- outcome{receipt, err}
	}()
	acquired := []string{}
	var waiting int64
awaitBlocked:
	for {
		select {
		case event := <-monitor.events:
			if event.acquired {
				acquired = append(acquired, event.key)
			} else if event.key == blocked {
				waiting = event.connectionID
				break awaitBlocked
			}
		case result := <-done:
			t.Fatal("native revoke finished before expected actual lock wait", result.err)
		case <-ctx.Done():
			t.Fatal("native writer did not reach original signer lock")
		}
	}
	prefix := []string{}
	table := "system_backup_signing_resource_heads"
	if blocked == "grant:catalog_record" {
		prefix = []string{"head:acceptance_record", "grant:acceptance_record", "head:catalog_record"}
		table = "system_backup_signing_resource_grants"
	}
	if !reflect.DeepEqual(acquired, prefix) {
		t.Fatal("actual signer acquired prefix differs", acquired, prefix)
	}
	requireNativeSignerWait(t, ctx, f, waiting, blockerID, table)
	select {
	case result := <-done:
		t.Fatal("actual native revoke passed held consumer lock", result.err)
	default:
	}
	if blocker.Rollback() != nil {
		t.Fatal("native blocker release")
	}
	var result outcome
	select {
	case result = <-done:
	case <-ctx.Done():
		t.Fatal("native revoke did not finish after actual shared lock released")
	}
	if result.err != nil || len(result.receipt.Items) != 2 || result.receipt.Items[0].Comparison.State != "revoked" || result.receipt.Items[1].Comparison.State != "revoked" {
		t.Fatal("native original terminal revoke after wait", result.err)
	}
	for {
		select {
		case event := <-monitor.events:
			if event.acquired {
				acquired = append(acquired, event.key)
			}
		default:
			goto drained
		}
	}
drained:
	cycle := []string{"head:acceptance_record", "grant:acceptance_record", "head:catalog_record", "grant:catalog_record"}
	// Actual importer performs one exclusive comparison cycle before writes
	// and another exact exclusive readback cycle before COMMIT.
	want := append(append([]string{}, cycle...), cycle...)
	if !reflect.DeepEqual(acquired, want) {
		t.Fatal("actual purpose head/grant lock cycles differ", acquired, want)
	}
	nativeSignerExactFour(t, ctx, f, revoked)
}
