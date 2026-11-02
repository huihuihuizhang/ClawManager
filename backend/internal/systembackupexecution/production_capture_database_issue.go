package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"

	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// IssueDatabaseSourceGrant adds actual native DB grant issuance to the SAME
// B sequence, context, original enrolled issuer and absolute window. Unlike
// Redis/Skill metadata signing, this operation requires an actual TLS MySQL
// finite-account/full-census observation before the DB source signature.
func (s *OriginalCaptureSequence) IssueDatabaseSourceGrant(ctx context.Context, file, sha256 string) (_ install.DatabaseSourceIssueResult, resultErr error) {
	var zero install.DatabaseSourceIssueResult
	leave, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer func() {
		if resultErr != nil {
			s.failed = true
		}
		leave()
	}()
	// The native issuer has no access to this sequence's eventual output
	// coordinates. Refuse collisions before owner/native I/O or private-key
	// loading; never publish a DB grant over a later metadata/bundle output.
	if s.databaseSourceOutputDisjoint(file, sha256) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if s.authority == nil || s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	key, err := install.ReadPrivateFile(s.privateFile, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return zero, c.ErrExecutionAuthority
	}
	defer clear(key)
	return s.authority.IssueDatabaseSource(ctx, file, sha256, key)
}

// This is a data-only path check; the actual issuer still independently
// reopens/authenticates every original input and runs all native checks.
func (s *OriginalCaptureSequence) databaseSourceOutputDisjoint(file, sha256 string) error {
	if s == nil || s.core.CaptureModules == nil || s.materials.Discovery == nil {
		return c.ErrExecutionAuthority
	}
	raw, err := install.ReadSourceMaterialFile(file)
	var definition install.DatabaseSourceIssueDefinition
	if err != nil || len(raw) > 262144 || hash(raw) != sha256 || json.Unmarshal(raw, &definition) != nil {
		return c.ErrExecutionAuthority
	}
	// The installation issuer uses JCS rather than struct-field JSON order.
	// Exact typed roundtrip also refuses unknown/duplicate/case-aliased fields.
	encoded, err := json.Marshal(definition)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil || !bytes.Equal(canonical, raw) {
		return c.ErrExecutionAuthority
	}
	original, err := json.Marshal(s.definition)
	output := definition.Source.GrantFile
	if err != nil || definition.Version != install.DatabaseSourceIssueVersion || definition.OriginalDefinitionSHA256 != hash(original) || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return c.ErrExecutionAuthority
	}
	for _, reserved := range []string{s.core.CaptureModules.Path, s.materials.Discovery.GrantFile, s.materials.Redis.GrantFile, s.materials.Objects.GrantFile, s.definition.CoreFile, s.definition.ConfigFile, s.core.ForwardGrant.Path, s.privateFile, file, definition.Source.CredentialFile} {
		if output == reserved {
			return c.ErrExecutionAuthority
		}
	}
	return nil
}
