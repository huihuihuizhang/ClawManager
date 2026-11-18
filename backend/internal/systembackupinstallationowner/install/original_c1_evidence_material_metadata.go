package install

import (
	"bytes"
	owner "clawreef/internal/systembackupinstallationowner"
	"context"
	"os"
	"path/filepath"
	"reflect"
)

func recoverOriginalC1EvidenceIntent(recovery OriginalC1EvidenceRecovery, expected originalC1EvidenceIntent, current map[string]string, mount string) ([]byte, []byte, error) {
	intent, err := readBootstrapSourcePin(recovery.Intent, 262144)
	var prior originalC1EvidenceIntent
	if err != nil || decodeExact(intent, &prior) != nil {
		return nil, nil, ErrInstall
	}
	priorDir := prior.Options.OutputDirectory
	if priorDir == expected.Options.OutputDirectory || privateDirectory(priorDir) != nil ||
		recovery.Intent.File != filepath.Join(priorDir, "c1-evidence-material.intent.json") ||
		recovery.BeforeMetadata.File != filepath.Join(priorDir, "c1-provider-metadata.before.json") {
		return nil, nil, ErrInstall
	}
	prior.Options.OutputDirectory = expected.Options.OutputDirectory
	prior.Options.Until = expected.Options.Until
	if !reflect.DeepEqual(prior, expected) {
		return nil, nil, ErrInstall
	}
	sent, err := ReadPrivateFile(filepath.Join(priorDir, "c1-key.sent.json"), 262144)
	if err != nil || !bytes.Equal(sent, intent) {
		return nil, nil, ErrInstall
	}
	for _, name := range []string{"c1-evidence.material.json", "c1-evidence.material.signature"} {
		if _, err := os.Lstat(filepath.Join(priorDir, name)); !os.IsNotExist(err) {
			return nil, nil, ErrInstall
		}
	}
	beforeRaw, err := readBootstrapSourcePin(recovery.BeforeMetadata, 262144)
	var before map[string]string
	if err != nil || decodeExact(beforeRaw, &before) != nil ||
		!originalC1OnlyOwnedMetadataChanged(before, current, mount, prior.Key, prior.Role) {
		return nil, nil, ErrInstall
	}
	return intent, beforeRaw, nil
}

// Per-resource hashes preserve the COMPLETE native metadata document for all
// pre-existing keys/roles/policies, including fields beyond the DTO projection.
// Only provider-owned metadata is read; no token or key material is exported.
func originalC1VaultMetadata(ctx context.Context, v *originalPublicationVault, token []byte, mount string, data owner.InstalledVaultDependencyData) (map[string]string, error) {
	result := map[string]string{}
	add := func(path string) error {
		raw, err := v.data(ctx, path, token)
		if err != nil {
			return ErrInstall
		}
		raw, err = originalPublicationObjectCanonical(raw)
		if err != nil {
			return ErrInstall
		}
		result[path] = hash(raw)
		return nil
	}
	for _, k := range data.Keys {
		if !originalPublicationName(k.Name) || add("/v1/transit/keys/"+k.Name) != nil {
			return nil, ErrInstall
		}
	}
	for _, r := range data.Roles {
		if !originalPublicationName(r.Name) || !originalPublicationName(r.Policy) || add("/v1/auth/"+mount+"/role/"+r.Name) != nil || add("/v1/sys/policies/acl/"+r.Policy) != nil {
			return nil, ErrInstall
		}
	}
	if add("/v1/auth/"+mount+"/config") != nil {
		return nil, ErrInstall
	}
	return result, nil
}
func originalC1OnlyOwnedMetadataChanged(before, after map[string]string, mount, key, role string) bool {
	strip := func(in map[string]string) map[string]string {
		out := map[string]string{}
		for path, pin := range in {
			if path != "/v1/transit/keys/"+key && path != "/v1/auth/"+mount+"/role/"+role && path != "/v1/sys/policies/acl/"+role {
				out[path] = pin
			}
		}
		return out
	}
	return reflect.DeepEqual(strip(before), strip(after))
}
