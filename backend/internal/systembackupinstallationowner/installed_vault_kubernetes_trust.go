package systembackupinstallationowner

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sort"

	a "clawreef/internal/systembackupkekadapter"
	"k8s.io/client-go/kubernetes"
)

// Public trust metadata from the actual already-authenticated Kubernetes API,
// never a selected future JWT, workload claim, candidate or signing-key issue.
func ReadInstalledVaultKubernetesTrust(ctx context.Context, kube kubernetes.Interface) (a.VaultJWTTrust, error) {
	var out a.VaultJWTTrust
	if !sameContext(ctx, ctx) || ctx.Err() != nil || nilInterface(kube) || kube.Discovery().RESTClient() == nil {
		return out, ErrOwner
	}
	client := kube.Discovery().RESTClient()
	raw, e := client.Get().AbsPath("/.well-known/openid-configuration").Do(ctx).Raw()
	var doc struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	if e != nil || len(raw) > 65536 || json.Unmarshal(raw, &doc) != nil {
		return out, ErrOwner
	}
	keysRequest := client.Get().AbsPath("/openid/v1/jwks")
	if !installedVaultDiscoveryURL(doc.Issuer, doc.JWKS, keysRequest.URL()) {
		return out, ErrOwner
	}
	raw, e = keysRequest.Do(ctx).Raw()
	var set struct {
		Keys []struct{ Kty, N, E, Use, Alg string }
	}
	if e != nil || len(raw) > 262144 || json.Unmarshal(raw, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 32 {
		return out, ErrOwner
	}
	seen := map[string]bool{}
	for _, key := range set.Keys {
		if key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" {
			return out, ErrOwner
		}
		n, e := base64.RawURLEncoding.Strict().DecodeString(key.N)
		exponent, e2 := base64.RawURLEncoding.Strict().DecodeString(key.E)
		if e != nil || e2 != nil || len(exponent) == 0 || len(exponent) > 4 {
			return out, ErrOwner
		}
		v := 0
		for _, b := range exponent {
			v = v<<8 | int(b)
		}
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: v}
		if public.N.BitLen() < 2048 || v < 3 {
			return out, ErrOwner
		}
		der, e := x509.MarshalPKIXPublicKey(public)
		if e != nil || seen[digest(der)] {
			return out, ErrOwner
		}
		seen[digest(der)] = true
		out.ValidationPublicKeys = append(out.ValidationPublicKeys, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	}
	sort.Strings(out.ValidationPublicKeys)
	out.Issuer, out.Algorithms = doc.Issuer, []string{"RS256"}
	if _, e := a.VaultJWTAuthConfig(out); e != nil {
		return a.VaultJWTTrust{}, ErrOwner
	}
	return out, nil
}
