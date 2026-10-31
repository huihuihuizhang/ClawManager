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
	"reflect"
	"regexp"
	"runtime"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const ProviderPermitIssuerGrantDomain = "system-backup-original-generate-permit-issuer.v1\x00"

// This deployment-level delegation is issued by the ORIGINAL Generate business
// owner independently of config/capture/artifact signers and the identity CA.
// It contains no future task/Invocation/Job/Pod hash. It alone grants no task.
type ProviderPermitIssuerGrant struct {
	Version                                                            string
	Binding                                                            reg.Binding
	Database                                                           reg.DatabaseIdentity
	DatabaseAccount                                                    string
	Workload                                                           ControllerVerifierWorkload // identity DTO; GrantSHA256 empty in payload
	SigningPublicKey                                                   ed25519.PublicKey
	GeneratePermission                                                 ProviderCapabilityPermission
	WorkerNamespace, WorkerServiceAccountName, WorkerServiceAccountUID string
	WorkerJWTIdentityFile                                              string
	NotBefore, Until                                                   time.Time
	Revoked                                                            bool
}

type SignedProviderPermitIssuerGrant struct{ Record, Signature []byte }
type ProviderPermitIssuerGrantMount struct {
	File, SHA256 string
	Issuer       ed25519.PublicKey
}

func readPermitIssuerGrant(ctx context.Context, cfg ProviderPermitIssuerConfig) (ProviderPermitIssuerGrant, error) {
	bad := func() (ProviderPermitIssuerGrant, error) { return ProviderPermitIssuerGrant{}, kms.ErrPermission }
	m := cfg.GrantMount
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(m.File) || !authorityHash.MatchString(m.SHA256) || len(m.Issuer) != ed25519.PublicKeySize || cfg.Workload.GrantSHA256 != m.SHA256 || m.SHA256 == cfg.CaptureGrantSHA256 {
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
	if hex.EncodeToString(h[:]) != m.SHA256 || strictPermitIssuerJSON(raw, new(any)) != nil {
		return bad()
	}
	var envelope SignedProviderPermitIssuerGrant
	if strictPermitIssuerJSON(raw, &envelope) != nil || len(envelope.Record) > 32768 || !ed25519.Verify(m.Issuer, append([]byte(ProviderPermitIssuerGrantDomain), envelope.Record...), envelope.Signature) {
		return bad()
	}
	var g ProviderPermitIssuerGrant
	if strictPermitIssuerJSON(envelope.Record, &g) != nil {
		return bad()
	}
	w := cfg.Workload
	w.GrantSHA256 = ""
	now := time.Now()
	p := g.GeneratePermission
	narrowName := regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	if p.Path != "transit/datakey/plaintext/"+cfg.Binding.Provider.KeyName || p.ProviderVersion != cfg.Binding.Key.ProviderVersion || !narrowName.MatchString(p.AuthMount) || !narrowName.MatchString(p.Role) || !narrowName.MatchString(p.Policy) || !authorityHash.MatchString(p.PolicySHA256) || !authorityHash.MatchString(p.RoleSHA256) || !authorityHash.MatchString(p.JWTTrustSHA256) || !reflect.DeepEqual(p.Reference, cfg.Binding.GenerateRef) {
		return bad()
	}
	if g.Version != "system-backup-provider-permit-issuer-grant.v1" || !reflect.DeepEqual(g.Binding, cfg.Binding) || g.Database != cfg.Capabilities.database || g.DatabaseAccount == "" || g.Workload != w || len(g.SigningPublicKey) != ed25519.PublicKeySize || bytes.Equal(g.SigningPublicKey, m.Issuer) || g.WorkerNamespace == "" || g.WorkerServiceAccountName == "" || g.WorkerServiceAccountUID == "" || !filepath.IsAbs(g.WorkerJWTIdentityFile) || g.GeneratePermission.ControllerVerifier != nil || g.NotBefore.IsZero() || now.Before(g.NotBefore) || !now.Before(g.Until) || g.Until.Sub(g.NotBefore) > 24*time.Hour || g.Revoked {
		return bad()
	}
	return g, nil
}

func strictPermitIssuerJSON(raw []byte, out any) error {
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return kms.ErrPermission
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return kms.ErrPermission
	}
	return nil
}

func readPermitSigningKey(path string, public ed25519.PublicKey) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, kms.ErrPermission
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != ed25519.PrivateKeySize || (runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0) {
		return nil, kms.ErrPermission
	}
	raw, err := io.ReadAll(io.LimitReader(f, ed25519.PrivateKeySize+1))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		clear(raw)
		return nil, kms.ErrPermission
	}
	canonical := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(canonical, raw) || !bytes.Equal(raw[ed25519.SeedSize:], public) {
		clear(raw)
		return nil, kms.ErrPermission
	}
	return ed25519.PrivateKey(raw), nil
}
