package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"

	ma "clawreef/internal/systembackupminioauthority"
)

func CheckNewMinIOSQLBundleDirectory(directory string) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	if _, e := os.Lstat(filepath.Join(directory, "minio-sql-authority.bundle.json")); !os.IsNotExist(e) {
		return ErrInstall
	}
	return nil
}

// AuthorizeMinIOSQLInstallation authenticates actual ORIGINAL operator,
// enrollment, independent issuer/plan and exact signed install scope BEFORE
// taskless native probes can touch their dedicated original keys. It issues
// no capability/Passed DTO and performs no writes or native provider probes.
// An absent original SQL head is allowed only for the initial installation;
// an existing head must match the SAME active frozen bundle exactly. A revoked
// or different head in that independently selected original domain is refused.
func (i *Installer) AuthorizeMinIOSQLInstallation(ctx context.Context, password []byte, enrollment EnrollmentPin, pin ma.SQLTrustPin, raw []byte, sha string) error {
	pin.IssuerPublic = bytes.Clone(pin.IssuerPublic)
	s, e := i.authenticate(ctx, password)
	if e != nil {
		return ErrInstall
	}
	b, g, h, refs, e := minioSQLBundle(ctx, s, enrollment, pin, raw, sha)
	if e != nil || b.Action != ma.SQLActionInstall || h.State != ma.StateActive {
		return ErrInstall
	}
	current, absent, e := minioSQLRead(ctx, s, pin)
	if e != nil || !absent && !minioSQLExact(current, b, h) {
		return ErrInstall
	}
	now, e := i.database(ctx, i.db, s.until)
	if e != nil || now.Before(g.NotBefore) || !now.Before(g.Until) || s.minioSQLKubernetes(ctx, g, refs, now) != nil || s.minioSQLPin(ctx, enrollment, pin) != nil {
		return ErrInstall
	}
	return nil
}
