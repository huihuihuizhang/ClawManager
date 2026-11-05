package install

import (
	"clawreef/internal/mysqltls"
	"context"
	"io"
	"os"
	"path/filepath"
)

type OriginalRelaySQLTLSLocationInputs struct {
	Version, OutputDirectory string
	OriginalTLS              BootstrapSourceFilePin
}
type OriginalRelaySQLTLSLocationReceipt struct {
	Version, State                   string
	OriginalTLS, OriginalCA, CA, TLS BootstrapSourceFilePin
	ServerName, CASHA256             string
}

// Only CA file location changes. Original audited TLS/DSN/principal files stay
// intact; ServerName and CA bytes/SHA are independently preserved by this owner.
func (i *Installer) PrepareOriginalRelaySQLTLSLocation(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalRelaySQLTLSLocationInputs) (OriginalRelaySQLTLSLocationReceipt, error) {
	var zero OriginalRelaySQLTLSLocationReceipt
	if i == nil || ctx == nil || in.Version != "original-relay-sql-tls-location-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(in.OriginalTLS, 65536)
	var original mysqltls.Material
	if e != nil || decodeExact(raw, &original) != nil || !original.Selected() {
		return zero, ErrInstall
	}
	if _, e = original.TLSConfig(); e != nil {
		return zero, ErrInstall
	}
	f, e := os.Open(original.CAFile)
	if e != nil {
		return zero, ErrInstall
	}
	ca, e := io.ReadAll(io.LimitReader(f, 65537))
	ce := f.Close()
	if e != nil || ce != nil || len(ca) > 65536 || hash(ca) != original.CASHA256 {
		return zero, ErrInstall
	}
	selected := original
	selected.CAFile = filepath.Join(in.OutputDirectory, "database-ca.pem")
	encoded, e := canonical(selected)
	if e != nil || op.authority(ctx, enrollment) != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"database-ca.pem": ca, "listener-sql-tls.json": encoded}) != nil {
		return zero, ErrInstall
	}
	if _, e = selected.TLSConfig(); e != nil {
		return zero, ErrInstall
	}
	check, e := readBootstrapSourcePin(in.OriginalTLS, 65536)
	if e != nil || hash(check) != hash(raw) {
		return zero, ErrInstall
	}
	return OriginalRelaySQLTLSLocationReceipt{Version: "original-relay-sql-tls-location-result.v1", State: "same_original_SQL_CA_and_server_name_new_location_verified", OriginalTLS: in.OriginalTLS, OriginalCA: BootstrapSourceFilePin{File: original.CAFile, SHA256: original.CASHA256}, CA: BootstrapSourceFilePin{File: selected.CAFile, SHA256: original.CASHA256}, TLS: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "listener-sql-tls.json"), SHA256: hash(encoded)}, ServerName: original.ServerName, CASHA256: original.CASHA256}, nil
}
