package systembackupinstallationowner

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	a "clawreef/internal/systembackupkekadapter"
)

// The metadata identity is read-only across ALL installed signing purposes.
// Reading capture's public metadata does not reuse its grant or sign with it.
func SigningResourceObserverACL(r SigningResourceGrant, observerPolicy string) (string, error) {
	if !safeName.MatchString(observerPolicy) || strings.EqualFold(observerPolicy, "root") || strings.EqualFold(observerPolicy, "default") || len(r.Bindings) != 3 || len(r.Histories) != 3 {
		return "", ErrOwner
	}
	paths := map[string]bool{"auth/token/lookup-self": true, "sys/policies/acl/" + observerPolicy: true}
	for n, b := range r.Bindings {
		if !signingBindingValid(b, r.Target) || b.Policy == observerPolicy || r.Histories[n].Purpose != b.Purpose || r.Histories[n].KeyName != b.KeyName {
			return "", ErrOwner
		}
		for _, p := range []string{"sys/policies/acl/" + b.Policy, "auth/" + b.AuthMount + "/role/" + b.Role, "auth/" + b.AuthMount + "/config", b.TransitMount + "/keys/" + b.KeyName} {
			paths[p] = true
		}
	}
	ordered := make([]string, 0, len(paths))
	for p := range paths {
		ordered = append(ordered, p)
	}
	sort.Strings(ordered)
	var out strings.Builder
	for _, p := range ordered {
		out.WriteString("path \"" + p + "\" { capabilities = [\"read\"] }\n")
	}
	return out.String(), nil
}

func (o *SigningResourceObserver) metadata(ctx context.Context, r SigningResourceGrant, token []byte) ([]byte, time.Time, error) {
	t := o.transport
	started := time.Now().UTC()
	raw, e := t.read(ctx, "/v1/auth/token/lookup-self", token)
	var self struct {
		Policies         []string `json:"policies"`
		IdentityPolicies []string `json:"identity_policies"`
		TTL              int64    `json:"ttl"`
	}
	if e != nil || !requiredFields(raw, "policies", "identity_policies", "ttl") || json.Unmarshal(raw, &self) != nil || len(self.Policies) != 1 || self.Policies[0] != t.cfg.ObserverPolicy || len(self.IdentityPolicies) != 0 || self.TTL < 1 || self.TTL > 86400 {
		return nil, time.Time{}, ErrOwner
	}
	expected, e := SigningResourceObserverACL(r, t.cfg.ObserverPolicy)
	if e != nil {
		return nil, time.Time{}, ErrOwner
	}
	var stamp []json.RawMessage
	policy := func(name, want string, sum string) error {
		v, e := t.read(ctx, "/v1/sys/policies/acl/"+name, token)
		var got struct{ Name, Policy string }
		if e != nil || !requiredFields(v, "name", "policy") || json.Unmarshal(v, &got) != nil || got.Name != name || got.Policy != want || sum != "" && digest([]byte(got.Policy)) != sum {
			return ErrOwner
		}
		stamp = append(stamp, v)
		return nil
	}
	if policy(t.cfg.ObserverPolicy, expected, "") != nil {
		return nil, time.Time{}, ErrOwner
	}
	for n, b := range r.Bindings {
		acl, e := CaptureSigningACL(b)
		if e != nil || policy(b.Policy, acl, b.PolicySHA256) != nil {
			return nil, time.Time{}, ErrOwner
		}
		role, e := t.read(ctx, "/v1/auth/"+b.AuthMount+"/role/"+b.Role, token)
		rc, re := canonicalRaw(role)
		want, we := a.VaultJWTAuthRole(a.VaultPermissionRole{AuthMount: b.AuthMount, Role: b.Role, Policy: b.Policy, Audience: b.Audience, Namespace: b.Namespace, ServiceAccountName: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodUID: b.PodUID})
		if e != nil || re != nil || we != nil || digest(rc) != b.RoleSHA256 || !jsonSubset(role, want) {
			return nil, time.Time{}, ErrOwner
		}
		stamp = append(stamp, role)
		trust, e := t.read(ctx, "/v1/auth/"+b.AuthMount+"/config", token)
		tc, te := canonicalRaw(trust)
		wanted, we := a.VaultJWTAuthConfig(t.cfg.Trust)
		if e != nil || te != nil || we != nil || digest(tc) != b.JWTConfigSHA256 || !jsonSubset(trust, wanted) {
			return nil, time.Time{}, ErrOwner
		}
		stamp = append(stamp, trust)
		meta, e := t.read(ctx, "/v1/"+b.TransitMount+"/keys/"+b.KeyName, token)
		var key struct {
			Type                 string `json:"type"`
			SupportsSigning      bool   `json:"supports_signing"`
			Derived, Exportable  bool
			AllowPlaintextBackup bool `json:"allow_plaintext_backup"`
			DeletionAllowed      bool `json:"deletion_allowed"`
			Keys                 map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		}
		if e != nil || !requiredFields(meta, "type", "supports_signing", "derived", "exportable", "allow_plaintext_backup", "deletion_allowed", "keys") || json.Unmarshal(meta, &key) != nil || key.Type != "ed25519" || !key.SupportsSigning || key.Derived || key.Exportable || key.AllowPlaintextBackup || key.DeletionAllowed || len(key.Keys) != len(r.Histories[n].Keys) {
			return nil, time.Time{}, ErrOwner
		}
		for _, k := range r.Histories[n].Keys {
			if key.Keys[k.Version].PublicKey != k.PublicKey {
				return nil, time.Time{}, ErrOwner
			}
		}
		stamp = append(stamp, meta)
	}
	result, e := canonical(stamp)
	return result, started.Add(time.Duration(self.TTL) * time.Second), e
}
