// Package systembackupkekadmission contains A's checks before original KEK
// admission. This candidate check grants no operation and cannot create a
// systembackupkms.Config. The original mapping authority and D's locked
// transaction remain mandatory for production admission.
package systembackupkekadmission

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	reg "clawreef/internal/systembackupkekregistry"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrCandidate = errors.New("backup KEK candidate unavailable")

var hash64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var exactVersion = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var keyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func version(s string) bool {
	return exactVersion.MatchString(s) && s != "latest" && s != "current" && s != "default"
}

func source(s reg.SourceRecord) bool {
	return len(s.SourceID) > 0 && len(s.SourceID) <= 256 && len(s.RecordID) > 0 && len(s.RecordID) <= 256 && version(s.RecordVersion) && hash64.MatchString(s.ContentSHA256)
}

func exactProvider(b reg.Binding) bool {
	u, err := url.Parse(b.Provider.Endpoint)
	v, parseErr := strconv.ParseUint(b.Key.ProviderVersion, 10, 32)
	// Match the live Transit endpoint rule: an empty query/fragment
	// delimiter is still a different endpoint and must not be admitted.
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == "" && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && !strings.ContainsAny(b.Provider.Endpoint, "?#\r\n") &&
		keyName.MatchString(b.Provider.KeyName) && len(b.Key.ProviderKeyID) > 0 && len(b.Key.ProviderKeyID) <= 256 &&
		parseErr == nil && v > 0 && strconv.FormatUint(v, 10) == b.Key.ProviderVersion
}

func typed(r reg.TypedReference, purpose string, b reg.Binding) bool {
	if len(r.RawJSON) == 0 || len(r.RawJSON) > 16384 || !hash64.MatchString(r.SHA256) {
		return false
	}
	h := sha256.Sum256(r.RawJSON)
	if hex.EncodeToString(h[:]) != r.SHA256 {
		return false
	}
	d, err := refs.DecodeSecurityReference(r.RawJSON, r.SHA256)
	// DecodeSecurityReference's external_kms_key variant already fixes the
	// capability for each purpose in its closed schema.
	return err == nil && d.Kind() == "external_kms_key" && d.Purpose() == purpose &&
		d.ProviderIdentity() == b.Provider.ProviderIdentityHash && d.ScopeHash() == b.Provider.ScopeHash
}

func keyBindingHash(b reg.Binding) string {
	key := b.Key
	raw, err := json.Marshal(map[string]string{
		"provider": key.Provider, "identity_hash": key.IdentityHash,
		"registry_version": key.RegistryVersion, "provider_key_id": key.ProviderKeyID,
		"provider_version": key.ProviderVersion,
	})
	if err != nil {
		return ""
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}

// CheckUnadmittedInput checks only candidate-internal and prepared comparison
// facts. Even a nil error does not authenticate an original source, an entire
// historical scan, a provider capability or current task permission. Callers
// must obtain a PreparedAdmission from the original owner before use.
func CheckUnadmittedInput(in reg.AdmissionInput, now time.Time) error {
	bad := ErrCandidate
	b, o, s := in.Candidate, in.Observation, in.Snapshot
	if now.IsZero() || b.InstallationID == "" || o.InstallationID != b.InstallationID || s.InstallationID != b.InstallationID ||
		!hash64.MatchString(b.ConfigRef.IdentityHash) || !version(b.ConfigRef.Version) ||
		b.Key.Provider != "external-kms" || b.Key.IdentityHash != b.ConfigRef.IdentityHash || b.Key.RegistryVersion != b.ConfigRef.Version ||
		!version(b.Key.RegistryVersion) || !exactProvider(b) || !hash64.MatchString(b.Provider.CAPEMSHA256) ||
		!hash64.MatchString(b.Provider.ProviderIdentityHash) || !hash64.MatchString(b.Provider.ScopeHash) || !source(b.Provider.CASource) ||
		!typed(b.GenerateRef, "data_key_generation", b) || !typed(b.UnwrapRef, "kek_unwrap", b) ||
		!hash64.MatchString(o.ConfigSHA256) || !version(o.SourceRevision) || !source(o.MappingSource) ||
		!source(o.GenerateCapabilitySource) || !source(o.UnwrapCapabilitySource) ||
		!o.NotBefore.Before(o.ValidUntil) || now.Before(o.NotBefore) || !now.Before(o.ValidUntil) ||
		s.Database.ServerUUID == "" || s.Database.Database == "" || s.ObservedAt.IsZero() || s.ObservedAt.After(now) ||
		in.Coverage == nil || len(s.Coverage) != 4 || s.Bindings == nil || s.References == nil {
		return bad
	}
	want := map[reg.Partition]bool{
		reg.RetainedArtifacts: false, reg.InflightAndUnknownWrites: false,
		reg.HoldsAndCatalog: false, reg.RestoreAndPrune: false,
	}
	for _, c := range s.Coverage {
		seen, ok := want[c.Partition]
		if !ok || seen || c.SourceID == "" || !version(c.SnapshotRevision) || !version(c.FenceRevision) || !source(c.AdoptionSource) {
			return bad
		}
		want[c.Partition] = true
	}
	for _, covered := range want {
		if !covered {
			return bad
		}
	}
	bindings := map[reg.ReferencePin]reg.Binding{}
	for _, f := range s.Bindings {
		key := reg.ReferencePin{IdentityHash: f.Binding.Key.IdentityHash, Version: f.Binding.Key.RegistryVersion}
		if f.Binding.InstallationID != b.InstallationID || !hash64.MatchString(key.IdentityHash) || !version(key.Version) ||
			f.Binding.ConfigRef != key || f.Binding.Key.Provider != "external-kms" || !exactProvider(f.Binding) ||
			!hash64.MatchString(f.Binding.Provider.CAPEMSHA256) || !hash64.MatchString(f.Binding.Provider.ProviderIdentityHash) ||
			!hash64.MatchString(f.Binding.Provider.ScopeHash) || !source(f.Binding.Provider.CASource) ||
			!typed(f.Binding.GenerateRef, "data_key_generation", f.Binding) || !typed(f.Binding.UnwrapRef, "kek_unwrap", f.Binding) ||
			f.BindingSHA256 != keyBindingHash(f.Binding) || f.RowVersion == 0 {
			return bad
		}
		if _, found := bindings[key]; found {
			return bad
		}
		bindings[key] = f.Binding
	}
	for _, r := range s.References {
		if _, ok := want[r.Partition]; !ok || r.SourceRecordID == "" || !version(r.SourceRecordVersion) ||
			r.BackupPublicID == "" || r.AttemptNo == "" || r.EnvelopeID == "" || !hash64.MatchString(r.BindingSHA256) ||
			!source(r.MappingSource) || !source(r.ExpectedRequestSource) || !source(r.LifecycleSource) {
			return bad
		}
		key := reg.ReferencePin{IdentityHash: r.Key.IdentityHash, Version: r.Key.RegistryVersion}
		bound, ok := bindings[key]
		if !ok || bound.Key != r.Key || r.BindingSHA256 != keyBindingHash(bound) {
			return bad
		}
	}
	return nil
}
