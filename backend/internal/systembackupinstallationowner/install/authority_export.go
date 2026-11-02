package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"

	owner "clawreef/internal/systembackupinstallationowner"
)

func privateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrInstall
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return ErrInstall
	}
	return nil
}

// CheckNewBundleDirectory is a non-authorizing preflight before any one-shot
// signing/probe. An existing frozen output is never overwritten or re-signed.
func CheckNewBundleDirectory(directory string) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	if _, e := os.Lstat(filepath.Join(directory, "authority.bundle.json")); !os.IsNotExist(e) {
		return ErrInstall
	}
	return nil
}
func writeNewFiles(directory string, files map[string][]byte) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return ErrInstall
	}
	defer root.Close()
	for name := range files {
		if _, e := root.Lstat(name); !os.IsNotExist(e) {
			return ErrInstall
		}
	}
	created := map[string]os.FileInfo{}
	ok := false
	defer func() {
		if !ok {
			for name, original := range created {
				if current, e := root.Lstat(name); e == nil && os.SameFile(original, current) {
					_ = root.Remove(name)
				}
			}
		}
	}()
	for name, raw := range files {
		f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrInstall
		}
		original, e := f.Stat()
		if e != nil {
			_ = f.Close()
			return ErrInstall
		}
		created[name] = original
		n, e := f.Write(raw)
		if e == nil && n != len(raw) {
			e = ErrInstall
		}
		if e == nil {
			e = f.Sync()
		}
		closed := f.Close()
		if e != nil || closed != nil {
			return ErrInstall
		}
	}
	ok = true
	return nil
}

// SaveFrozenBundle writes only inert transport bytes, not a consumer trust
// file. Actual import independently authenticates the enrollment and issuer.
func SaveFrozenBundle(directory string, raw []byte) error {
	var b AuthorityBundle
	if len(raw) == 0 || len(raw) > 262144 {
		return ErrInstall
	}
	raw = bytes.Clone(raw)
	if decodeExact(raw, &b) != nil || b.SchemaVersion != AuthorityBundleVersion && b.SchemaVersion != RevocationBundleVersion {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"authority.bundle.json": raw})
}

// ExportCommitted is the only consumer-file exporter. A record/candidate's
// self-declared key cannot create these files: original enrollment, actual
// current operator and exact committed signed SQL head/grant are all required.
func (i *Installer) ExportCommitted(ctx context.Context, password []byte, enrollment EnrollmentPin, raw []byte, rawSHA, directory string) (AuthorityReceipt, error) {
	var zero AuthorityReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, r, _, e := s.decodeBundle(raw, rawSHA, enrollment)
	if e != nil || b.SchemaVersion != AuthorityBundleVersion {
		return zero, ErrInstall
	}
	c, now, e := snapshot(ctx, s)
	if e != nil || !exactCommitted(c, b) || now.Before(r.NotBefore) || !now.Before(r.Until) || now.Before(c.head.NotBefore) || !now.Before(c.head.Until) {
		return zero, ErrInstall
	}
	pin, e := canonical(b.Pin)
	if e != nil {
		return zero, ErrInstall
	}
	enrol, e := canonical(enrollment)
	if e != nil {
		return zero, ErrInstall
	}
	if writeNewFiles(directory, map[string][]byte{"owner.record": b.Record, "owner.signature": b.RecordSignature, "owner.head": b.Head, "owner.head-signature": b.HeadSignature, "owner.pin.json": pin, "owner.enrollment-pin.json": enrol}) != nil {
		return zero, ErrInstall
	}
	return s.confirmCommitted(ctx, b, false)
}

// RecordFilesAt returns fixed locators only. It neither loads nor trusts a pin
// and never substitutes an issuer from a record or import bundle.
func RecordFilesAt(directory string) owner.RecordFiles {
	return owner.RecordFiles{RecordFile: filepath.Join(directory, "owner.record"), SignatureFile: filepath.Join(directory, "owner.signature")}
}
