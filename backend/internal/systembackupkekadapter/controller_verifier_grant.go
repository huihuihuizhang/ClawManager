package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const ControllerVerifierGrantDomain = "system-backup-original-controller-verifier-grant.v1\x00"

// ControllerVerifierGrant is independently issued by the ORIGINAL verification
// business owner for the real verifier workload. It supplements but NEVER
// replaces the existing deploymentAuthorization/capture-record custody chain.
// It authorizes automatic original-task verification, not arbitrary unwrap,
// source capture, signature issuance, production restore or future key use.
type ControllerVerifierGrant struct {
	Version         string
	InstallationID  string
	Database        reg.DatabaseIdentity
	DatabaseAccount string
	// Workload.GrantSHA256 is empty in this signed payload; its public runtime
	// value is the independently deployed hash of the complete grant envelope.
	Workload           ControllerVerifierWorkload
	CaptureGrantSHA256 string
	NotBefore, Until   time.Time
	Revoked            bool
}

type ControllerVerifierGrantMount struct {
	File, SHA256 string
	Issuer       ed25519.PublicKey
}

type SignedControllerVerifierGrant struct{ Record, Signature []byte }

func readControllerVerifierGrant(ctx context.Context, m ControllerVerifierGrantMount, w ControllerVerifierWorkload, installation, capture string, database reg.DatabaseIdentity) (ControllerVerifierGrant, error) {
	bad := func() (ControllerVerifierGrant, error) { return ControllerVerifierGrant{}, kms.ErrPermission }
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(m.File) || !authorityHash.MatchString(m.SHA256) || len(m.Issuer) != ed25519.PublicKeySize || w.GrantSHA256 != m.SHA256 || capture == m.SHA256 || !authorityHash.MatchString(capture) {
		return bad()
	}
	f, err := os.Open(m.File)
	if err != nil {
		return bad()
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return bad()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		return bad()
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != m.SHA256 {
		return bad()
	}
	if _, err = jsoncanonicalizer.Transform(raw); err != nil {
		return bad()
	}
	var envelope SignedControllerVerifierGrant
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || len(envelope.Record) == 0 || len(envelope.Record) > 32768 || !ed25519.Verify(m.Issuer, append([]byte(ControllerVerifierGrantDomain), envelope.Record...), envelope.Signature) {
		return bad()
	}
	if _, err = jsoncanonicalizer.Transform(envelope.Record); err != nil {
		return bad()
	}
	var grant ControllerVerifierGrant
	d = json.NewDecoder(bytes.NewReader(envelope.Record))
	d.DisallowUnknownFields()
	if d.Decode(&grant) != nil || d.Decode(new(any)) != io.EOF {
		return bad()
	}
	expectedWorkload := w
	expectedWorkload.GrantSHA256 = ""
	now := time.Now()
	if grant.Version != "system-backup-controller-verifier-grant.v1" || grant.InstallationID != installation || grant.Database != database || grant.DatabaseAccount == "" || len(grant.DatabaseAccount) > 256 || grant.Workload != expectedWorkload || grant.CaptureGrantSHA256 != capture || grant.NotBefore.IsZero() || now.Before(grant.NotBefore) || !now.Before(grant.Until) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour || grant.Revoked {
		return bad()
	}
	return grant, nil
}
