// Installation-owner command. It reads the REAL TLS provider with a separate
// narrow observer credential, then signs only the observed permission metadata.
// It does not initialize/unseal Vault, mutate SQL, bootstrap configuration,
// Generate/Unwrap, deploy workloads or claim that a backup task succeeded.
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

var errObserve = errors.New("original installed provider observation rejected")

type observationInput struct {
	Provider                     a.VaultPermissionObserverConfig
	GenerateSource, UnwrapSource r.SourceRecord
	Revision                     string
	Until                        time.Time
	SignerPublicSHA256           string
}

func readFile(path string, max int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errObserve
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errObserve
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max || private && runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return nil, errObserve
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		clear(raw)
		return nil, errObserve
	}
	return raw, nil
}
func hash(raw []byte) string { digest := sha256.Sum256(raw); return hex.EncodeToString(digest[:]) }

func run(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("system-backup-provider-observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configFile := flags.String("config-file", "", "independently pinned installation observer mapping")
	configSHA := flags.String("config-sha256", "", "exact original observer mapping SHA256")
	issuerFile := flags.String("issuer-private-key-file", "", "installation permission-observer signing key; never a Vault root token")
	output := flags.String("output-directory", "", "existing private installation owner directory; new files only")
	planOnly := flags.Bool("plan-only", false, "emit desired installation payloads only; no provider I/O, signing or admission")
	if flags.Parse(args) != nil || flags.NArg() != 0 || len(*configSHA) != 64 || !filepath.IsAbs(*output) || filepath.Clean(*output) != *output {
		return errObserve
	}
	dir, err := os.Lstat(*output)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && dir.Mode().Perm()&0077 != 0 {
		return errObserve
	}
	raw, err := readFile(*configFile, 262144, false)
	if err != nil || hash(raw) != *configSHA {
		return errObserve
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return errObserve
	}
	var input observationInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.GenerateSource.RecordID == input.UnwrapSource.RecordID || len(input.SignerPublicSHA256) != 64 {
		return errObserve
	}
	if *planOnly {
		if *issuerFile != "" {
			return errObserve
		}
		return writePlan(input, *output, out)
	}
	key, err := readFile(*issuerFile, ed25519.PrivateKeySize, true)
	defer clear(key)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return errObserve
	}
	private := ed25519.PrivateKey(key)
	canonicalKey := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(canonicalKey)
	if !bytes.Equal(key, canonicalKey) {
		return errObserve
	}
	if hash(private.Public().(ed25519.PublicKey)) != input.SignerPublicSHA256 {
		return errObserve
	}
	observer, err := a.NewVaultPermissionObserver(input.Provider)
	if err != nil {
		return errObserve
	}
	defer observer.Close()
	observed, err := observer.Observe(ctx)
	if err != nil {
		return errObserve
	}
	generate, err := observed.Sign(k.Generate, input.GenerateSource, input.Revision, input.Until, private)
	if err != nil {
		return errObserve
	}
	unwrap, err := observed.Sign(k.Unwrap, input.UnwrapSource, input.Revision, input.Until, private)
	if err != nil {
		return errObserve
	}
	var g, u a.ProviderCapabilityRecord
	if json.Unmarshal(generate.Record, &g) != nil || json.Unmarshal(unwrap.Record, &u) != nil {
		return errObserve
	}
	pins := struct{ Generate, Unwrap a.ProviderCapabilityPin }{a.ProviderCapabilityPin{Source: g.Source, Issuer: private.Public().(ed25519.PublicKey)}, a.ProviderCapabilityPin{Source: u.Source, Issuer: private.Public().(ed25519.PublicKey)}}
	files := []struct {
		name  string
		value any
	}{{"generate.capability.json", generate}, {"unwrap.capability.json", unwrap}, {"capability-pins.json", pins}}
	for _, file := range files {
		encoded, err := json.Marshal(file.value)
		if err != nil {
			return errObserve
		}
		path := filepath.Join(*output, file.name)
		// Fixed names, no overwrite, no inferred deletion on an uncertain ACK.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errObserve
		}
		_, writeErr := f.Write(encoded)
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errObserve
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "actual_permission_metadata_observed", "provider_operations_run": false, "sql_mutated": false, "bootstrap_admitted": false})
}

func writePlan(input observationInput, output string, out io.Writer) error {
	cfg := input.Provider
	generate, err := a.VaultRuntimeACL(k.Generate, cfg.Binding.Provider.KeyName, cfg.Binding.Key.ProviderVersion)
	if err != nil {
		return errObserve
	}
	unwrap, err := a.VaultRuntimeACL(k.Unwrap, cfg.Binding.Provider.KeyName, cfg.Binding.Key.ProviderVersion)
	if err != nil {
		return errObserve
	}
	observer, err := a.VaultObserverACL(cfg.Binding.Provider.KeyName, cfg.Worker, cfg.Publisher, cfg.ObserverPolicy)
	if err != nil {
		return errObserve
	}
	trust, err := a.VaultJWTAuthConfig(cfg.Trust)
	if err != nil {
		return errObserve
	}
	worker, err := a.VaultJWTAuthRole(cfg.Worker)
	if err != nil {
		return errObserve
	}
	publisher, err := a.VaultJWTAuthRole(cfg.Publisher)
	if err != nil {
		return errObserve
	}
	policy := func(text string) []byte { raw, _ := json.Marshal(map[string]string{"policy": text}); return raw }
	paths := map[string]string{"worker-policy.json": "/v1/sys/policies/acl/" + cfg.Worker.Policy, "publisher-policy.json": "/v1/sys/policies/acl/" + cfg.Publisher.Policy, "observer-policy.json": "/v1/sys/policies/acl/" + cfg.ObserverPolicy, "worker-role.json": "/v1/auth/" + cfg.Worker.AuthMount + "/role/" + cfg.Worker.Role, "publisher-role.json": "/v1/auth/" + cfg.Publisher.AuthMount + "/role/" + cfg.Publisher.Role, "worker-jwt-config.json": "/v1/auth/" + cfg.Worker.AuthMount + "/config", "publisher-jwt-config.json": "/v1/auth/" + cfg.Publisher.AuthMount + "/config", "key-create.json": "/v1/transit/keys/" + cfg.Binding.Provider.KeyName}
	pathRaw, _ := json.Marshal(paths)
	files := []struct {
		name string
		body []byte
	}{{"worker-policy.json", policy(generate)}, {"publisher-policy.json", policy(unwrap)}, {"observer-policy.json", policy(observer)}, {"worker-role.json", worker}, {"publisher-role.json", publisher}, {"worker-jwt-config.json", trust}, {"publisher-jwt-config.json", trust}, {"key-create.json", a.VaultTransitKeyPayload()}, {"request-paths.json", pathRaw}}
	for _, file := range files {
		f, err := os.OpenFile(filepath.Join(output, file.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errObserve
		}
		_, writeErr := f.Write(file.body)
		syncErr, closeErr := f.Sync(), f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errObserve
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"status": "desired_installation_payloads_only", "provider_observed": false, "bootstrap_admitted": false})
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	if run(ctx, os.Args[1:], os.Stdout) != nil {
		os.Stderr.WriteString("provider observation failed; inspect exact original owner files before retry\n")
		os.Exit(1)
	}
}
