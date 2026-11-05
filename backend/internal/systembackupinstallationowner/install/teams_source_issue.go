package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrTeamsSourceUnavailable = errors.New("original complete native Teams object inventory unavailable")

const TeamsSourceIssueVersion = "original-teams-object-source-issue.v1"

// DATA inside the ORIGINAL whole-definition pin, not a signed observation or
// an alternative authority. Teams selects its own mount explicitly; existing
// Redis/Skills grant signatures never authorize this distinct operation.
type TeamsSourceIssueDefinition struct {
	Version, DatabaseAccount, DatabaseService, DatabaseServiceUID string
	DatabasePort                                                  int
	DatabaseCredential, PartsRegistry                             BootstrapSourceFilePin
	Source                                                        worker.FormalSourceMount
}

type TeamsSourceIssueResult struct {
	Version, State, OriginalDefinitionSHA256, ScopeSHA256, InventorySHA256 string
	Source                                                                 worker.FormalSourceMount
	Grant                                                                  BootstrapSourceFilePin
	NotBefore, Until                                                       time.Time
}

func teamsExactJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 8<<20 || json.Unmarshal(raw, out) != nil {
		return ErrInstall
	}
	typed, e := json.Marshal(out)
	a, ae := jsoncanonicalizer.Transform(raw)
	b, be := jsoncanonicalizer.Transform(typed)
	if e != nil || ae != nil || be != nil || !bytes.Equal(a, b) {
		return ErrInstall
	}
	return nil
}

// ValidateTeamsSourceInventory is pure DATA validation. Only Issue/Query below
// authenticate an owner and perform native observations; this function grants
// nothing. An explicit empty inventory still requires TWO native empty LISTs;
// a missing inventory never inherits the Skills provider root.
func ValidateTeamsSourceInventory(m worker.FormalSourceMount, inventory *team.Inventory) error {
	if inventory == nil || inventory.Objects == nil || len(inventory.Objects) > 100000 {
		return ErrTeamsSourceUnavailable
	}
	if m.Redis != nil || m.RedisScope != nil || m.Objects == nil || m.GrantSHA256 != "" || len(m.RedisPrefixes) != 0 || len(m.RedisExcludedPrefixes) != 0 {
		return ErrInstall
	}
	if _, e := worker.TeamObjectsSourceScopeSHA256(m); e != nil {
		return ErrInstall
	}
	// Preserve the owner's finite roots exactly. They need not equal a
	// directory synthesized from current references: a complete zero inventory
	// and a later complete nonzero inventory may use the SAME original root.
	for n, a := range m.ObjectPrefixes {
		for _, b := range m.ObjectPrefixes[n+1:] {
			if a.Bucket == b.Bucket && (strings.HasPrefix(a.Prefix, b.Prefix) || strings.HasPrefix(b.Prefix, a.Prefix)) {
				return ErrInstall
			}
		}
	}
	seen := map[string]bool{}
	for _, ref := range inventory.Objects {
		key := ref.Bucket + "\x00" + ref.Key
		if ref.Validate() != nil || seen[key] {
			return ErrInstall
		}
		seen[key] = true
		covered := false
		for _, prefix := range m.ObjectPrefixes {
			covered = covered || ref.Bucket == prefix.Bucket && strings.HasPrefix(ref.Key, prefix.Prefix)
		}
		if !covered {
			return ErrInstall
		}
	}

	return nil
}

func (p *SourceMaterialIssuer) teamsSourceDefinition(ctx context.Context) (TeamsSourceIssueDefinition, *team.Inventory, error) {
	var zero TeamsSourceIssueDefinition
	if p == nil || p.Recheck(ctx) != nil {
		return zero, nil, ErrInstall
	}
	// Reuse the real full-definition/core/Forward1/config/actor authentication,
	// without using its ControlEvidence signature as Teams source authority.
	header, _, _, _, e := p.controlEvidenceSourceDefinition(ctx)
	if e != nil {
		return zero, nil, ErrInstall
	}
	raw, e := ReadSourceMaterialFile(p.intent.DefinitionFile)
	var top map[string]json.RawMessage
	if e != nil || hash(raw) != p.intent.DefinitionSHA256 || json.Unmarshal(raw, &top) != nil {
		return zero, nil, ErrInstall
	}
	var d TeamsSourceIssueDefinition
	if teamsExactJSON(top["TeamsSource"], &d) != nil || d.Version != TeamsSourceIssueVersion {
		return zero, nil, ErrTeamsSourceUnavailable
	}
	configRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: header.ConfigFile, SHA256: header.ConfigSHA256}, 262144)
	if e != nil {
		return zero, nil, ErrInstall
	}
	config, e := sec.DecodeConfigValues(configRaw)
	if e != nil {
		return zero, nil, ErrInstall
	}
	var selectedParts sec.BootstrapRegistryRef
	for _, ref := range config.Registries() {
		if ref.Kind == "parts" {
			selectedParts = ref
		}
	}
	if selectedParts.Version == "" || selectedParts.SHA256 != d.PartsRegistry.SHA256 {
		return zero, nil, ErrInstall
	}
	m := d.Source
	if m.Objects == nil || !bytes.Equal(m.Issuer, p.operator.installer.public) || !digestPattern.MatchString(m.CredentialSHA256) || !bootstrapSourcePinValid(d.DatabaseCredential) || !bootstrapSourcePinValid(d.PartsRegistry) {
		return zero, nil, ErrInstall
	}
	for _, file := range []string{m.GrantFile, m.CredentialFile, m.Objects.CAFile} {
		if !filepath.IsAbs(file) || filepath.Clean(file) != file {
			return zero, nil, ErrInstall
		}
	}
	for _, file := range []string{p.intent.DefinitionFile, d.DatabaseCredential.File, d.PartsRegistry.File, m.CredentialFile, m.Objects.CAFile} {
		if m.GrantFile == file {
			return zero, nil, ErrInstall
		}
	}
	var materials struct {
		Redis, Objects worker.FormalSourceMount
		Discovery      struct{ GrantFile string }
	}
	if json.Unmarshal(top["Materials"], &materials) != nil {
		return zero, nil, ErrInstall
	}
	for _, reserved := range []string{materials.Redis.GrantFile, materials.Objects.GrantFile, materials.Discovery.GrantFile} {
		if m.GrantFile == reserved {
			return zero, nil, ErrInstall
		}
	}
	partsRaw, e := readBootstrapSourcePin(d.PartsRegistry, 8<<20)
	var parts struct {
		SchemaVersion, Installation, Version string
		Parts                                []struct{ Module, Part, Operation string }
		Source                               struct {
			ServerUUID, Database string
			Teams                *team.Inventory
		}
	}
	if e != nil {
		return zero, nil, ErrTeamsSourceUnavailable
	}
	if _, e = jsoncanonicalizer.Transform(partsRaw); e != nil || json.Unmarshal(partsRaw, &parts) != nil || parts.SchemaVersion != "system-backup-original-source-parts.v2" || parts.Installation != p.intent.InstallationID || parts.Version != selectedParts.Version || parts.Source.ServerUUID != p.intent.ServerUUID || parts.Source.Database != p.intent.Database {
		return zero, nil, ErrTeamsSourceUnavailable
	}
	count := 0
	for _, part := range parts.Parts {
		if part.Part == "teams_objects" || part.Operation == "capture-team-objects" {
			if part.Module != "teams" || part.Part != "teams_objects" || part.Operation != "capture-team-objects" {
				return zero, nil, ErrTeamsSourceUnavailable
			}
			count++
		}
	}
	if ValidateTeamsSourceInventory(m, parts.Source.Teams) != nil {
		return zero, nil, ErrTeamsSourceUnavailable
	}
	wantParts := 0
	if len(parts.Source.Teams.Objects) > 0 {
		wantParts = 1
	}
	// Original catalog omits the object operation for a truly empty inventory.
	// Count==0 is DATA only: native SQL + two complete empty version LISTs
	// are still mandatory before any signature may be issued.
	if count != wantParts {
		return zero, nil, ErrTeamsSourceUnavailable
	}
	return d, parts.Source.Teams, nil
}

// ValidateTeamsSource performs real, complete observation without signing or
// writing. The factory calls it BEFORE Begin can publish Redis/Skills grants.
func (p *SourceMaterialIssuer) ValidateTeamsSource(ctx context.Context) error {
	d, inventory, e := p.teamsSourceDefinition(ctx)
	if e != nil {
		return e
	}
	if _, e = p.observeTeamsSource(ctx, d, inventory); e != nil {
		return e
	}
	return p.Recheck(ctx)
}

func (p *SourceMaterialIssuer) IssueTeamsSource(ctx context.Context, private []byte) (TeamsSourceIssueResult, error) {
	var zero TeamsSourceIssueResult
	d, inventory, e := p.teamsSourceDefinition(ctx)
	if e != nil {
		return zero, e
	}
	// An existing/unknown/partial result is never re-signed or rewritten. Query
	// is the sole recovery path and independently repeats all observations.
	if _, e = os.Lstat(d.Source.GrantFile); !os.IsNotExist(e) {
		return zero, ErrInstall
	}
	freshUntil, e := p.observeTeamsSource(ctx, d, inventory)
	if e != nil {
		return zero, e
	}
	key, e := p.operator.privateKey(private)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	scope, e := worker.TeamObjectsSourceScopeSHA256(d.Source)
	if e != nil {
		return zero, ErrInstall
	}
	i := p.intent
	g := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: i.InstallationID, ConfigSHA256: i.ConfigSHA256, WorkerNamespace: i.Namespace, WorkerServiceAccountUID: i.WorkerServiceAccountUID, Operation: "capture-team-objects", ScopeSHA256: scope, CredentialSHA256: d.Source.CredentialSHA256, NotBefore: i.NotBefore, Until: i.Until}
	record, e := json.Marshal(g)
	if e != nil {
		return zero, ErrInstall
	}
	signed, e := json.Marshal(worker.SignedFormalSourceGrant{Record: record, Signature: ed25519.Sign(key, append([]byte(worker.FormalSourceGrantDomain), record...))})
	if e != nil || p.Recheck(ctx) != nil || teamsSourcePins(d) != nil || !time.Now().Before(freshUntil) {
		return zero, ErrInstall
	}
	if e = writeNewFiles(filepath.Dir(d.Source.GrantFile), map[string][]byte{filepath.Base(d.Source.GrantFile): signed}); e != nil {
		return zero, ErrInstall
	}
	return p.QueryTeamsSource(ctx)
}

func (p *SourceMaterialIssuer) QueryTeamsSource(ctx context.Context) (TeamsSourceIssueResult, error) {
	var zero TeamsSourceIssueResult
	d, inventory, e := p.teamsSourceDefinition(ctx)
	if e != nil {
		return zero, e
	}
	freshUntil, e := p.observeTeamsSource(ctx, d, inventory)
	if e != nil {
		return zero, e
	}
	raw, e := ReadSourceMaterialFile(d.Source.GrantFile)
	var signed worker.SignedFormalSourceGrant
	if e != nil || len(raw) > 65536 || teamsExactJSON(raw, &signed) != nil || !ed25519.Verify(p.operator.installer.public, append([]byte(worker.FormalSourceGrantDomain), signed.Record...), signed.Signature) {
		return zero, ErrInstall
	}
	var actual worker.FormalSourceGrant
	i := p.intent
	scope, e := worker.TeamObjectsSourceScopeSHA256(d.Source)
	want := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: i.InstallationID, ConfigSHA256: i.ConfigSHA256, WorkerNamespace: i.Namespace, WorkerServiceAccountUID: i.WorkerServiceAccountUID, Operation: "capture-team-objects", ScopeSHA256: scope, CredentialSHA256: d.Source.CredentialSHA256, NotBefore: i.NotBefore, Until: i.Until}
	if e != nil || teamsExactJSON(signed.Record, &actual) != nil || actual != want || p.Recheck(ctx) != nil || teamsSourcePins(d) != nil || ctx.Err() != nil || time.Now().Before(i.NotBefore) || !time.Now().Before(i.Until) || !time.Now().Before(freshUntil) {
		return zero, ErrInstall
	}
	d.Source.GrantSHA256 = hash(raw)
	return TeamsSourceIssueResult{Version: "original-teams-object-source-result.v1", State: "original_native_source_grant_readback_not_task_qualification", OriginalDefinitionSHA256: i.DefinitionSHA256, ScopeSHA256: scope, InventorySHA256: inventory.SHA256(), Source: d.Source, Grant: BootstrapSourceFilePin{File: d.Source.GrantFile, SHA256: hash(raw)}, NotBefore: i.NotBefore, Until: i.Until}, nil
}
