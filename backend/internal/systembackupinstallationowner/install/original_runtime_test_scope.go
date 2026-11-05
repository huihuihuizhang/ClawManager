package install

import (
	"context"
	"path/filepath"

	"clawreef/internal/systembackup/domain"
	c "clawreef/internal/systembackupcontroller"
)

type OriginalRuntimeTestScopeReceipt struct {
	Version, State   string
	Scope            BootstrapSourceFilePin
	RuntimeTestScope *domain.RuntimeTestScope
}

// Explicitly invoked DATA issuance under the actual original admin/enrollment.
// It cannot alter SQL rows, defer sources in a live task or grant a config. The
// original administrator must subsequently sign a config/request whose existing
// source-writers registry reference commits this exact scope.
func (i *Installer) ProduceOriginalRuntimeTestScope(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string, query bool) (OriginalRuntimeTestScopeReceipt, error) {
	var zero OriginalRuntimeTestScopeReceipt
	if i == nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	p, e := i.PrepareOriginalWriterMaintenance(ctx, password, enrollment, c.GatePolicy{LockTTL: c.DefaultMaintenanceLockTTL, AcquisitionTimeout: c.DefaultGateAcquisitionTime, MaxHold: c.DefaultQuiesceMaxHold})
	if e != nil {
		return zero, e
	}
	scope, e := domain.NewKnownErrorLiteRuntimeTestScope(i.plan.Target.InstallationID, i.plan.Target.ServerUUID, i.plan.Target.Database, i.plan.Target.NamespaceUID, p.instances)
	if e != nil {
		return zero, ErrInstall
	}
	name := filepath.Join(directory, "runtime-test-scope.json")
	raw, e := canonical(scope)
	if e != nil || p.check(ctx) != nil || p.checkInstances(ctx) != nil {
		return zero, ErrInstall
	}
	if !query && writeNewFiles(directory, map[string][]byte{"runtime-test-scope.json": raw}) != nil {
		return zero, ErrInstall
	}
	got, e := ReadPrivateFile(name, 262144)
	if e != nil || string(got) != string(raw) || p.checkInstances(ctx) != nil || p.check(ctx) != nil {
		return zero, ErrInstall
	}
	return OriginalRuntimeTestScopeReceipt{Version: "original-runtime-test-scope-result.v1", State: "exact_original_two_error_lite_runtime_scope_DATA_not_signed_or_admitted", Scope: BootstrapSourceFilePin{File: name, SHA256: hash(got)}, RuntimeTestScope: scope.Clone()}, nil
}
