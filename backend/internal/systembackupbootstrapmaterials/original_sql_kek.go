package systembackupbootstrapmaterials

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"clawreef/internal/systembackupinstallationowner/install"
	kek "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const OriginalSQLBootstrapKEKSourceVersion = "original-sql-bootstrap-kek-source.v1"

// This document selects existing original mapping, separate Generate/Unwrap,
// adoption and sixteen witness sources. It creates none of those records or
// permissions. The file pin must be installed independently of this document.
type OriginalSQLBootstrapKEKSource struct {
	SchemaVersion string
	Preparation   kek.SQLBootstrapKEKConfig
}

// LinkOriginalSQLBootstrapKEK connects the EXISTING concrete deferred database
// preparation, including both real purpose authorities and all four coverage
// partitions. It opens only the selected local pin file; no SQL/credentials or
// provider are opened here. It fills NO missing BootstrapTerminalResource slot.
func LinkOriginalSQLBootstrapKEK(base sec.BootstrapOwnerAdapters, sourceFile, sourceSHA string) (sec.BootstrapOwnerAdapters, error) {
	bad := func() (sec.BootstrapOwnerAdapters, error) {
		return sec.BootstrapOwnerAdapters{}, sec.ErrRegistrationUnavailable
	}
	if base.KEK != nil || len(sourceSHA) != 64 {
		return bad()
	}
	raw, err := install.ReadPrivateFile(sourceFile, 262144)
	if err != nil {
		return bad()
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != sourceSHA {
		return bad()
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return bad()
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var source OriginalSQLBootstrapKEKSource
	if decoder.Decode(&source) != nil || decoder.Decode(new(any)) != io.EOF || source.SchemaVersion != OriginalSQLBootstrapKEKSourceVersion {
		return bad()
	}
	roundtrip, err := json.Marshal(source)
	if err != nil {
		return bad()
	}
	roundtrip, err = jsoncanonicalizer.Transform(roundtrip)
	if err != nil || !bytes.Equal(raw, roundtrip) {
		return bad()
	}
	preparation, err := kek.NewSQLBootstrapKEKPreparation(source.Preparation)
	if err != nil {
		return bad()
	}
	// Keep maps detached and preserve the exact candidate/other owner objects.
	// In particular, do not turn the independent KEK admission source into a
	// dummy reference:kek validator or replace a current source silently.
	out := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{}, References: map[string]sec.BootstrapResourceValidator{}, CrossResources: base.CrossResources, Candidates: base.Candidates, KEK: preparation}
	for key, owner := range base.Registries {
		out.Registries[key] = owner
	}
	for key, owner := range base.References {
		out.References[key] = owner
	}
	return out, nil
}
