// Original installation owner only. One real provider observation produces the
// existing signed mapping and two permission records. No SQL/adoption/deploy.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	r "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var errMaterials = errors.New("original installation KEK materials rejected")

// Deployment-owned independent source locators and issuer public pins. This
// file is NOT a ConfigValues candidate, approval or a provider receipt. The two
// private issuers are distinct and remain in the original owner directory.
type materialInput struct {
	Provider                                                a.VaultPermissionObserverConfig
	MappingSource, GenerateSource, UnwrapSource             r.SourceRecord
	Revision                                                string
	Until                                                   time.Time
	MappingIssuerPublicSHA256, PermissionIssuerPublicSHA256 string
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func readBounded(path string, limit int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errMaterials
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errMaterials
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit || private && runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return nil, errMaterials
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, errMaterials
	}
	return raw, nil
}
func readIssuer(path, publicSHA string) (ed25519.PrivateKey, error) {
	raw, err := readBounded(path, ed25519.PrivateKeySize, true)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		clear(raw)
		return nil, errMaterials
	}
	key := ed25519.PrivateKey(raw)
	canonical := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	defer clear(canonical)
	if !bytes.Equal(raw, canonical) || digest(key.Public().(ed25519.PublicKey)) != publicSHA {
		clear(raw)
		return nil, errMaterials
	}
	return key, nil
}

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("system-backup-installation-kek-materials", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFile := flags.String("config-file", "", "original owner mapping/observer input, not a config candidate")
	configSHA := flags.String("config-sha256", "", "independent exact original input SHA256")
	ownerFile := flags.String("mapping-private-key-file", "", "original installation owner raw64 Ed25519 key")
	permissionFile := flags.String("permission-private-key-file", "", "separate original permission observer raw64 Ed25519 key")
	output := flags.String("output-directory", "", "existing private owner directory; new fixed files only")
	if flags.Parse(args) != nil || flags.NArg() != 0 || ctx == nil || ctx.Err() != nil || len(*configSHA) != 64 || !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
		return errMaterials
	}
	dir, err := os.Lstat(*output)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && dir.Mode().Perm()&0077 != 0 {
		return errMaterials
	}
	raw, err := readBounded(*configFile, 262144, false)
	if err != nil || digest(raw) != *configSHA {
		return errMaterials
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return errMaterials
	}
	var input materialInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.MappingIssuerPublicSHA256) != 64 || len(input.PermissionIssuerPublicSHA256) != 64 || input.MappingIssuerPublicSHA256 == input.PermissionIssuerPublicSHA256 || input.MappingSource.RecordID == input.GenerateSource.RecordID || input.MappingSource.RecordID == input.UnwrapSource.RecordID || input.GenerateSource.RecordID == input.UnwrapSource.RecordID {
		return errMaterials
	}
	ownerKey, err := readIssuer(*ownerFile, input.MappingIssuerPublicSHA256)
	defer clear(ownerKey)
	if err != nil {
		return errMaterials
	}
	permissionKey, err := readIssuer(*permissionFile, input.PermissionIssuerPublicSHA256)
	defer clear(permissionKey)
	if err != nil {
		return errMaterials
	}
	observer, err := a.NewVaultPermissionObserver(input.Provider)
	if err != nil {
		return errMaterials
	}
	defer observer.Close()
	observed, err := observer.Observe(ctx)
	if err != nil {
		return errMaterials
	}
	mapping, err := observed.SignInstallationMapping(input.MappingSource, input.Revision, input.Until, ownerKey)
	if err != nil {
		return errMaterials
	}
	generate, err := observed.Sign(k.Generate, input.GenerateSource, input.Revision, input.Until, permissionKey)
	if err != nil {
		return errMaterials
	}
	unwrap, err := observed.Sign(k.Unwrap, input.UnwrapSource, input.Revision, input.Until, permissionKey)
	if err != nil {
		return errMaterials
	}
	var m a.OriginalRecord
	var g, u a.ProviderCapabilityRecord
	if json.Unmarshal(mapping.Record, &m) != nil || json.Unmarshal(generate.Record, &g) != nil || json.Unmarshal(unwrap.Record, &u) != nil || ctx.Err() != nil {
		return errMaterials
	}
	pins := struct {
		MappingSource    r.SourceRecord
		MappingIssuer    ed25519.PublicKey
		Generate, Unwrap a.ProviderCapabilityPin
	}{m.Source, ownerKey.Public().(ed25519.PublicKey), a.ProviderCapabilityPin{Source: g.Source, Issuer: permissionKey.Public().(ed25519.PublicKey)}, a.ProviderCapabilityPin{Source: u.Source, Issuer: permissionKey.Public().(ed25519.PublicKey)}}
	pinRaw, err := json.Marshal(pins)
	if err != nil {
		return errMaterials
	}
	gRaw, err := json.Marshal(generate)
	if err != nil {
		return errMaterials
	}
	uRaw, err := json.Marshal(unwrap)
	if err != nil {
		return errMaterials
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"installation-authority.record.json", mapping.Record}, {"installation-authority.signature", mapping.Signature}, {"installation-authority.public-key", ownerKey.Public().(ed25519.PublicKey)}, {"generate.capability.json", gRaw}, {"unwrap.capability.json", uRaw}, {"original-source-pins.json", pinRaw}} {
		f, err := os.OpenFile(filepath.Join(*output, file.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errMaterials
		}
		_, writeErr := f.Write(file.raw)
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errMaterials
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "actual_provider_observed_original_owner_materials_signed", "same_provider_observation": true, "sql_mutated": false, "coverage_adopted": false, "bootstrap_admitted": false, "provider_operations_run": false})
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	if run(ctx, os.Args[1:], os.Stdout) != nil {
		os.Stderr.WriteString("original installation materials failed; inspect original owner inputs before retry\n")
		os.Exit(1)
	}
}
