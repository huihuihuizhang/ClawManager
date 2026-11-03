package install

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

// Keep an actual SQL floor across BOTH independent export snapshots, including
// all intervening local/consumer-API work. The frozen lifecycle helper returns
// rows only, so it cannot by itself retain this export's last observed time.
func signingResourceExportSnapshot(ctx context.Context, s *authenticatedOperator, changes []signingResourceSQLChange, floor time.Time) ([]*signingResourceSQLRows, time.Time, error) {
	tx, err := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, time.Time{}, ErrInstall
	}
	defer tx.Rollback()
	now, err := s.lockAdmin(ctx, tx)
	if err != nil || now.Before(floor) {
		return nil, time.Time{}, ErrInstall
	}
	view := &signingResourceSQLView{ctx: ctx, tx: tx, operator: s, floor: now}
	rows := make([]*signingResourceSQLRows, 0, len(changes))
	for _, change := range changes {
		row, absent, err := readSigningResourceSQLRows(ctx, view, change.input.Pin, false)
		if err != nil || absent || change.bundle.Action != "install" || !exactSigningResourceSQLRows(row, change.bundle, change.head) {
			return nil, time.Time{}, ErrInstall
		}
		rows = append(rows, row)
	}
	now, err = s.lockAdmin(ctx, tx)
	if err != nil || now.Before(view.floor) {
		return nil, time.Time{}, ErrInstall
	}
	for _, change := range changes {
		if now.Before(change.grant.NotBefore) || !now.Before(change.grant.Until) {
			return nil, time.Time{}, ErrInstall
		}
	}
	return rows, now, nil
}

func signingResourceExportNames() []string {
	names := []string{"signing.plan.json", "signing.issuer.public", "signing.enrollment-pin.json", "signing-consumer.json", "signing-consumer.sha256"}
	for _, purpose := range owner.SigningResourcePurposes() {
		for _, suffix := range []string{".pin.json", ".record", ".signature"} {
			names = append(names, purpose+suffix)
		}
	}
	return names
}

func openSigningResourceOutput(directory string) (*os.Root, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrInstall
	}
	for _, name := range signingResourceExportNames() {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			root.Close()
			return nil, ErrInstall
		}
	}
	return root, nil
}

func CheckNewSigningResourceBundleDirectory(directory, purpose string) error {
	if privateDirectory(directory) != nil || owner.SigningResourceBootstrapPurpose(purpose) == "" {
		return ErrInstall
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return ErrInstall
	}
	defer root.Close()
	for _, suffix := range []string{".signing-resource.bundle.json", ".signing-resource.bundle.sha256"} {
		if _, err := root.Lstat(purpose + suffix); !os.IsNotExist(err) {
			return ErrInstall
		}
	}
	return nil
}

// ExportSigningResourceConsumer authenticates the original administrator and
// enrollment, exact committed active four-row tuple and original SQL window.
// It never signs, repairs or changes SQL, probes providers or creates a task.
// Independently deploy/select the returned public pins and private locators;
// writing these files is not resource admission.
func (i *Installer) ExportSigningResourceConsumer(ctx context.Context, password []byte, enrollment EnrollmentPin, inputs []SigningResourceSQLInput, assets []SigningResourceConsumerAsset, consumerKubeconfig, consumerKubeSHA, directory string) (SigningResourceSQLReceipt, error) {
	var zero SigningResourceSQLReceipt
	if CheckNewSigningResourceConsumerDirectory(directory) != nil || len(inputs) != 2 || len(assets) != 2 {
		return zero, ErrInstall
	}
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	changes, err := signingResourceSQLChanges(ctx, s, enrollment, inputs)
	if err != nil {
		return zero, ErrInstall
	}
	for n, change := range changes {
		if change.bundle.Action != "install" || assets[n].Purpose != change.input.Pin.Purpose {
			return zero, ErrInstall
		}
		if _, err := readSigningResourceAsset(ctx, assets[n], change.grant); err != nil {
			return zero, ErrInstall
		}
	}
	_, floor, err := signingResourceExportSnapshot(ctx, s, changes, s.sqlTime)
	if err != nil {
		return zero, ErrInstall
	}
	plan, err := canonical(i.plan)
	if err != nil {
		return zero, ErrInstall
	}
	enrol, err := canonical(enrollment)
	if err != nil {
		return zero, ErrInstall
	}
	path := func(name string) string { return filepath.Join(directory, name) }
	document := SigningResourceConsumerFiles{
		Version: SigningResourceConsumerVersion, PlanFile: path("signing.plan.json"), PlanSHA256: hash(plan),
		IssuerPublicFile: path("signing.issuer.public"), IssuerPublicSHA256: hash(i.public),
		EnrollmentPinFile: path("signing.enrollment-pin.json"), EnrollmentPinSHA256: hash(enrol),
		KubeconfigFile: consumerKubeconfig, KubeconfigSHA256: consumerKubeSHA,
	}
	files := map[string][]byte{"signing.plan.json": plan, "signing.issuer.public": i.public, "signing.enrollment-pin.json": enrol}
	for n, change := range changes {
		purpose := change.input.Pin.Purpose
		pin, err := canonical(change.input.Pin)
		if err != nil {
			return zero, ErrInstall
		}
		document.Items = append(document.Items, SigningResourceConsumerItem{PinFile: path(purpose + ".pin.json"), PinSHA256: hash(pin), RecordFile: path(purpose + ".record"), SignatureFile: path(purpose + ".signature"), Asset: assets[n]})
		files[purpose+".pin.json"], files[purpose+".record"], files[purpose+".signature"] = pin, change.bundle.Grant, change.bundle.GrantSignature
	}
	raw, err := canonical(document)
	if err != nil || len(raw) > 262144 {
		return zero, ErrInstall
	}
	files["signing-consumer.json"], files["signing-consumer.sha256"] = raw, []byte(hash(raw))
	if writeNewFiles(directory, files) != nil {
		return zero, ErrInstall
	}
	// Export files now exist: any subsequent failure is uncertain output, never
	// an instruction to overwrite/re-sign them. No SQL mutation happened here.
	consumer, err := OpenSigningResourceConsumer(ctx, path("signing-consumer.json"), path("signing-consumer.sha256"))
	if err != nil {
		return zero, ErrCommitUnknown
	}
	defer consumer.Close()
	for n, change := range changes {
		if _, err := readSigningResourceAsset(ctx, assets[n], change.grant); err != nil || s.signingResourcePin(ctx, enrollment, change.input.Pin) != nil {
			return zero, ErrCommitUnknown
		}
	}
	if consumer.current(ctx) != nil {
		return zero, ErrCommitUnknown
	}
	// The last authority boundary is the original SQL window/current four-row
	// tuple, after all local reads and consumer enrollment API inspection.
	rows, _, err := signingResourceExportSnapshot(ctx, s, changes, floor)
	if err != nil {
		return zero, ErrCommitUnknown
	}
	return signingResourceSQLReceipt(changes, rows, []bool{true, true}), nil
}
