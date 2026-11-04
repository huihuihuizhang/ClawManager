package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

// Existing offline enrollment binary; no new image or task API. Private bytes
// are read from the original owner's files and never returned through stdout.
func runRuntimeIssuers(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("system-backup-original-enroll runtime-issuers", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	values := map[string]*string{}
	for _, name := range []string{"mode", "plan-file", "plan-sha256", "issuer-public-file", "issuer-public-sha256", "enrollment-pin-file", "enrollment-pin-sha256", "kubeconfig-file", "kubeconfig-sha256", "dsn-file", "dsn-sha256", "database-ca-file", "local-admin-password-file", "source-issuer-private-file", "output-directory", "material-file", "material-sha256"} {
		values[name] = f.String(name, "", "")
	}
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	get := func(name string) string { return *values[name] }
	mode, directory := get("mode"), get("output-directory")
	if mode != "prepare" && mode != "query" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return 2
	}
	read := func(file, expected string, limit int64) ([]byte, error) {
		raw, err := install.ReadPrivateFile(file, limit)
		if err != nil {
			return nil, install.ErrInstall
		}
		sum := sha256.Sum256(raw)
		if expected != "" && hex.EncodeToString(sum[:]) != expected {
			clear(raw)
			return nil, install.ErrInstall
		}
		return raw, nil
	}
	for _, name := range []string{"plan-sha256", "issuer-public-sha256", "enrollment-pin-sha256", "kubeconfig-sha256", "dsn-sha256"} {
		if len(get(name)) != 64 {
			return 2
		}
	}
	planRaw, err := read(get("plan-file"), get("plan-sha256"), 262144)
	if err != nil {
		return 1
	}
	plan, err := install.DecodePlan(planRaw, get("plan-sha256"))
	if err != nil {
		return 1
	}
	public, err := read(get("issuer-public-file"), get("issuer-public-sha256"), 32)
	if err != nil || len(public) != 32 {
		return 1
	}
	enrollmentRaw, err := read(get("enrollment-pin-file"), get("enrollment-pin-sha256"), 262144)
	if err != nil {
		return 1
	}
	// Decode through the native canonical enrollment-pin reader.
	enrollment, err := install.DecodeEnrollmentPin(enrollmentRaw, get("enrollment-pin-sha256"))
	if err != nil {
		return 1
	}
	password, err := read(get("local-admin-password-file"), "", 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	dsn, err := read(get("dsn-file"), get("dsn-sha256"), 16384)
	if err != nil {
		return 1
	}
	clear(dsn)
	db, kube, err := install.OpenConnections(plan, get("kubeconfig-file"), get("kubeconfig-sha256"), get("dsn-file"), get("database-ca-file"))
	if err != nil {
		return 1
	}
	defer db.Close()
	owner, err := install.New(db, kube, planRaw, get("plan-sha256"), public, get("issuer-public-sha256"))
	if err != nil {
		return 1
	}
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var pin install.BootstrapSourceFilePin
	if mode == "prepare" {
		if get("material-file") != "" || get("material-sha256") != "" {
			return 2
		}
		issuerKey, e := read(get("source-issuer-private-file"), "", 64)
		if e != nil || len(issuerKey) != 64 {
			clear(issuerKey)
			return 1
		}
		defer clear(issuerKey)
		parent := filepath.Dir(directory)
		resolved, e := filepath.EvalSymlinks(parent)
		if e != nil || resolved != parent || os.Mkdir(directory, 0700) != nil {
			return 1
		}
		pin, err = owner.PrepareOriginalRuntimeIssuerMaterial(active, password, enrollment, issuerKey, directory)
		if errors.Is(err, install.ErrOriginalRuntimeIssuerMaterialUnconfirmed) {
			return 3
		}
		if err != nil {
			return 1
		}
	} else {
		if get("source-issuer-private-file") != "" || get("material-file") != filepath.Join(directory, "original-runtime-issuers.json") || len(get("material-sha256")) != 64 {
			return 2
		}
		pin = install.BootstrapSourceFilePin{File: get("material-file"), SHA256: get("material-sha256")}
	}
	if _, err = owner.ReadOriginalRuntimeIssuerMaterial(active, password, enrollment, pin); err != nil {
		return 3
	}
	result := struct {
		Version, State                     string
		Material                           install.BootstrapSourceFilePin
		GrantsIssued, ConfigurationMutated bool
	}{
		Version: "original-runtime-purpose-issuers-produced.v1", State: "original_owner_authenticated_purpose_material_only", Material: pin,
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 3
	}
	return 0
}
