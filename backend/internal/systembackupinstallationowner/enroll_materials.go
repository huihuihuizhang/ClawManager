package systembackupinstallationowner

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
)

const EnrollmentCandidateVersion = "system-backup-installation-owner-enrollment-candidate.v1"

type EnrollmentCandidate struct{ SchemaVersion, Status, Algorithm, PublicKeySHA256 string }

// GenerateEnrollmentCandidate only creates untrusted key material. It cannot
// create a TrustPin, signed owner approval, Kubernetes enrollment or SQL head.
// Existing private directory only; every fixed file uses O_EXCL, fsync, 0600.
func GenerateEnrollmentCandidate(directory string) (EnrollmentCandidate, error) {
	var zero EnrollmentCandidate
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return zero, ErrOwner
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0) {
		return zero, ErrOwner
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return zero, ErrOwner
	}
	defer clear(private)
	candidate := EnrollmentCandidate{EnrollmentCandidateVersion, "untrusted_candidate_requires_user_enrollment", "Ed25519", digest(public)}
	raw, e := canonical(candidate)
	if e != nil {
		return zero, e
	}
	// Preflight avoids a partial private key on an obvious existing-name failure.
	names := []string{"owner-issuer.private", "owner-issuer.public", "enrollment-candidate.json"}
	for _, name := range names {
		if _, e := os.Lstat(filepath.Join(directory, name)); !os.IsNotExist(e) {
			return zero, ErrOwner
		}
	}
	created := []string{}
	ok := false
	defer func() {
		if !ok {
			for _, p := range created {
				_ = os.Remove(p)
			}
		}
	}()
	for i, body := range [][]byte{private, public, raw} {
		p := filepath.Join(directory, names[i])
		f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return zero, ErrOwner
		}
		created = append(created, p)
		_, e = f.Write(body)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return zero, ErrOwner
		}
	}
	ok = true
	return candidate, nil
}
