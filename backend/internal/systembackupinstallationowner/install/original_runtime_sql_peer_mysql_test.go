//go:build systembackup_mysql

package install

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Native READ-ONLY role-boundary check against actual independent role source
// files. No synthetic shared account may satisfy the positive case. This is
// SQL identity/permission validation, not enrollment or original grant issuance.
func TestOriginalRuntimeSQLPeerMySQLRequiresSeparateBusinessRuntimeAndSource(t *testing.T) {
	path := os.Getenv("A_RUNTIME_SQL_ROLE_SOURCES_FILE")
	if path == "" {
		t.Fatal("actual independently pinned role sources required")
	}
	raw, e := ReadPrivateFile(path, 262144)
	if e != nil {
		t.Fatal("role sources")
	}
	defer clear(raw)
	var in struct {
		Plan                                   BootstrapSourceFilePin
		RuntimeDSN, BusinessDSN, SourceDSN, CA BootstrapSourceFilePin
	}
	if json.Unmarshal(raw, &in) != nil {
		t.Fatal("role sources shape")
	}
	planRaw, e := readBootstrapSourcePin(in.Plan, 262144)
	if e != nil {
		t.Fatal("original plan")
	}
	plan, e := DecodePlan(planRaw, in.Plan.SHA256)
	if e != nil {
		t.Fatal("original plan decode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	runtime, runtimeID, e := openOriginalEnrollmentDatabase(ctx, in.RuntimeDSN, in.CA, plan.DatabaseTLSServerName)
	if e != nil {
		t.Fatal("native runtime TLS SQL")
	}
	defer runtime.Close()
	business, businessID, e := openOriginalEnrollmentDatabase(ctx, in.BusinessDSN, in.CA, plan.DatabaseTLSServerName)
	if e != nil {
		t.Fatal("native business TLS SQL")
	}
	defer business.Close()
	source, sourceID, e := openOriginalEnrollmentDatabase(ctx, in.SourceDSN, in.CA, plan.DatabaseTLSServerName)
	if e != nil {
		t.Fatal("native source TLS SQL")
	}
	defer source.Close()
	if businessID.Account != plan.Target.DatabaseAccount || runtimeID.Account == businessID.Account || runtimeID.Account == sourceID.Account || sourceID.Account == businessID.Account || strings.Split(runtimeID.Account, "@")[0] == strings.Split(sourceID.Account, "@")[0] {
		t.Fatal("roles were not independently produced")
	}
	i := &Installer{plan: plan}
	if got, e := i.checkOriginalRuntimeSQLPeer(ctx, runtime, runtimeID.Account); e != nil || got != runtimeID.Account {
		t.Fatal("actual full48 runtime rejected", e)
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, business, businessID.Account); e == nil {
		t.Fatal("business treated as runtime")
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, source, sourceID.Account); e == nil {
		t.Fatal("source treated as runtime")
	}
	if _, e := i.checkOriginalRuntimeSQLPeer(ctx, runtime, sourceID.Account); e == nil {
		t.Fatal("foreign expected peer")
	}
	if plan.Target.DatabaseAccount != businessID.Account {
		t.Fatal("original business Plan was rewritten")
	}
}
