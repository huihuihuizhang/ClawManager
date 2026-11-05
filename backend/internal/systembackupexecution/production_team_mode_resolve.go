package systembackupexecution

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/buildinfo"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type originalTeamModeAuthority struct{ sequence *OriginalCaptureSequence }

func (originalTeamModeAuthority) sourceMetadataReadAuthority() {}
func (a originalTeamModeAuthority) Recheck(ctx context.Context) error {
	if a.sequence == nil || ctx == nil || ctx.Err() != nil || a.sequence.ctx == nil || a.sequence.ctx.Err() != nil || a.sequence.authority == nil {
		return install.ErrTeamsSourceUnavailable
	}
	// HTTP may derive cancellation contexts. Recheck the SAME original issuer
	// context retained by the private consumer, never adopt a derived authority.
	return a.sequence.authority.Recheck(a.sequence.ctx)
}

func (s *OriginalCaptureSequence) teamModeAPI(ctx context.Context) (*productionMetadataClients, func(), error) {
	zero := func() {}
	p := s.materials.Discovery
	if p == nil {
		return nil, zero, install.ErrTeamsSourceUnavailable
	}
	u, err := url.Parse(p.SourceAPI.Server)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, zero, install.ErrTeamsSourceUnavailable
	}
	ca, err := pinnedDeploymentFile(p.SourceAPI.CAFile, p.SourceAPI.CASHA256, 1<<20)
	if err != nil {
		return nil, zero, err
	}
	token, err := readPrivate(p.SourceAPI.TokenFile, 64<<10)
	if err != nil {
		return nil, zero, err
	}
	defer clear(token)
	if hash(token) != p.SourceAPITokenSHA256 {
		return nil, zero, install.ErrTeamsSourceUnavailable
	}
	value := strings.TrimSpace(string(token))
	if value == "" || strings.ContainsAny(value, " \r\n\t\x00") {
		return nil, zero, install.ErrTeamsSourceUnavailable
	}
	cfg := &rest.Config{Host: u.String(), BearerToken: value, TLSClientConfig: rest.TLSClientConfig{CAData: ca}, QPS: 5, Burst: 5}
	base, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, zero, err
	}
	guarded := sourceMetadataTransport{originalTeamModeAuthority{s}, u.Host, base}
	httpClient := &http.Client{Transport: guarded, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	close := func() { guarded.CloseIdleConnections() }
	api, err := kubernetes.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		close()
		return nil, zero, err
	}
	identity, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil || identity.Status.UserInfo.UID != p.SourceAPIServiceAccountUID || identity.Status.UserInfo.Username != "system:serviceaccount:"+s.core.Namespace+":"+p.SourceAPIServiceAccount {
		close()
		return nil, zero, install.ErrTeamsSourceUnavailable
	}
	return &productionMetadataClients{API: api}, close, nil
}

// Snapshot data stays private in this stack; only canonical file paths survive.
func teamFilesFromSnapshot(snapshot domain.Snapshot) (*team.SharedFileSource, error) {
	facts := &team.SharedFileSource{Codec: team.SharedFileSourceVersion, SchemaSHA256: team.SchemaSHA256(), AppVersion: buildinfo.Version, GitCommit: buildinfo.Commit, References: []team.SharedFileReference{}}
	ids := map[int]bool{}
	for _, table := range snapshot.Tables {
		if table.Name != "team_tasks" && table.Name != "team_work_items" && table.Name != "team_events" {
			continue
		}
		for _, row := range table.Rows {
			id, err := strconv.Atoi(row["team_id"].String())
			if err != nil || id <= 0 {
				return nil, install.ErrTeamsSourceUnavailable
			}
			ids[id] = true
			facts.Rows++
		}
	}
	ordered := []int{}
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Ints(ordered)
	for _, id := range ordered {
		refs, err := domain.TeamArtifactReferences(snapshot, id)
		if err != nil {
			return nil, err
		}
		facts.References = append(facts.References, team.SharedFileReference{TeamID: id, Paths: refs})
	}
	return facts, nil
}

// A supplies the private enum; this concrete consumer never accepts a caller
// mode. Same original context, issuer, config/Parts pin, full SQL double-read,
// actual writer image and closed codec are all checked BEFORE returning it.
func (s *OriginalCaptureSequence) resolveOriginalTeamObjectMode(ctx context.Context) (mode originalTeamObjectMode, failure error) {
	mode = originalTeamObjectUnknown
	leave, err := s.enter(ctx)
	if err != nil {
		return mode, err
	}
	defer func() {
		if failure != nil {
			s.failed = true
		}
		leave()
	}()
	if s.authority == nil || s.authority.Recheck(ctx) != nil || s.definition.TeamsSource == nil || s.materials.Discovery == nil {
		return mode, install.ErrTeamsSourceUnavailable
	}
	definition := s.definition.TeamsSource
	raw, err := pinnedDeploymentFile(definition.PartsRegistry.File, definition.PartsRegistry.SHA256, 8<<20)
	var parts bootstrapSourcePartsRegistry
	if err != nil || strictBootstrapSourceJSON(raw, &parts) != nil || parts.SchemaVersion != bootstrapSourcePartsVersion || parts.Installation != s.core.InstallationID || parts.Source.Teams == nil || parts.Source.TeamFacts == nil || parts.Source.TeamFacts.SharedFiles == nil || parts.Source.Teams.Objects == nil {
		return mode, install.ErrTeamsSourceUnavailable
	}
	configRaw, err := pinnedDeploymentFile(s.definition.ConfigFile, s.definition.ConfigSHA256, 262144)
	if err != nil {
		return mode, err
	}
	config, err := sec.DecodeConfigValues(configRaw)
	if err != nil {
		return mode, err
	}
	pinned := false
	for _, ref := range config.Registries() {
		if ref.Kind == "parts" && ref.Version == parts.Version && ref.SHA256 == definition.PartsRegistry.SHA256 {
			pinned = true
		}
	}
	if !pinned || parts.Source.Database != s.core.SourceDatabase || parts.Source.ServerUUID != s.core.SourceServerUUID {
		return mode, install.ErrTeamsSourceUnavailable
	}
	selected := s.materials.TeamObjects != nil || !reflect.DeepEqual(definition.Source, worker.FormalSourceMount{})
	if selected {
		if s.materials.TeamObjects == nil || validateTeamObjectsSource(s.materials) != nil {
			return mode, install.ErrTeamsSourceUnavailable
		}
		expected := definition.Source
		expected.GrantSHA256 = s.materials.TeamObjects.Source.GrantSHA256
		if !reflect.DeepEqual(expected, s.materials.TeamObjects.Source) {
			return mode, install.ErrTeamsSourceUnavailable
		}
	} else {
		if originalHasTeamObjectMaterial(s.definition.Materials) || len(parts.Source.Teams.Objects) != 0 || parts.TeamObjects == nil || parts.TeamObjects.Mode != "files-only-no-object-scope" {
			return mode, install.ErrTeamsSourceUnavailable
		}
		if _, exists := s.materials.Operations["capture-team-objects"]; exists {
			return mode, install.ErrTeamsSourceUnavailable
		}
		for _, part := range parts.Parts {
			if part.Part == "teams_objects" || part.Operation == "capture-team-objects" {
				return mode, install.ErrTeamsSourceUnavailable
			}
		}
	}
	spec := s.materials.Operations["capture-database"].Request.Database
	if spec == nil || spec.SourceScope != domain.BusinessTableSourceScope || spec.SchemaCensus == nil || spec.Name != s.core.SourceDatabase || spec.ServerUUID != s.core.SourceServerUUID {
		return mode, install.ErrTeamsSourceUnavailable
	}
	credentialRaw, err := pinnedDeploymentFile(definition.DatabaseCredential.File, definition.DatabaseCredential.SHA256, 16384)
	if err != nil {
		return mode, err
	}
	defer clear(credentialRaw)
	var credential worker.DatabaseCredential
	if decodeMetadataCanonical(credentialRaw, &credential) != nil || credential.Username == "root" || !strings.HasPrefix(definition.DatabaseAccount, credential.Username+"@") {
		return mode, install.ErrTeamsSourceUnavailable
	}
	defer clear(credential.Password)
	db, err := worker.OpenDatabase(spec, &credential)
	if err != nil {
		return mode, err
	}
	defer db.Close()
	identity := func() error {
		var account, role string
		if db.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE()").Scan(&account, &role) != nil || account != definition.DatabaseAccount || role != "NONE" {
			return install.ErrTeamsSourceUnavailable
		}
		return s.authority.Recheck(ctx)
	}
	read := func() (string, error) {
		if identity() != nil {
			return "", install.ErrTeamsSourceUnavailable
		}
		snapshot, err := domain.CaptureBusinessSourceGuarded(ctx, db, domain.Limits{MaxRows: spec.MaxRows, MaxBytes: spec.MaxMemoryBytes}, spec.Name, spec.ServerUUID, s.authority.Recheck, *spec.SchemaCensus)
		if err != nil {
			return "", err
		}
		defer clearTeamModeSnapshot(snapshot)
		if domain.VerifyBusinessCapturedSnapshot(snapshot, parts.SQL.Schema) != nil || domain.VerifyTeamCapture(snapshot, *parts.Source.Teams) != nil {
			return "", install.ErrTeamsSourceUnavailable
		}
		files, err := teamFilesFromSnapshot(snapshot)
		if err != nil || !reflect.DeepEqual(files, parts.Source.TeamFacts.SharedFiles) {
			return "", install.ErrTeamsSourceUnavailable
		}
		digest, err := domain.Digest(snapshot)
		if err != nil || identity() != nil {
			return "", install.ErrTeamsSourceUnavailable
		}
		return digest, nil
	}
	first, err := read()
	if err != nil {
		return mode, err
	}
	clients, close, err := s.teamModeAPI(ctx)
	if err != nil {
		return mode, err
	}
	defer close()
	observed, err := readTeamZeroCensus(ctx, s.materials, parts.Source.TeamFacts.SharedFiles, originalTeamModeAuthority{s}, s.core, clients, nil)
	if err != nil {
		return mode, err
	}
	last, err := read()
	if err != nil || first != last {
		return mode, install.ErrTeamsSourceUnavailable
	}
	observedAgain, err := readTeamZeroCensus(ctx, s.materials, parts.Source.TeamFacts.SharedFiles, originalTeamModeAuthority{s}, s.core, clients, nil)
	if err != nil || !reflect.DeepEqual(observed, observedAgain) || !reflect.DeepEqual(observed, parts.TeamObjects) || s.authority.Recheck(ctx) != nil {
		return mode, install.ErrTeamsSourceUnavailable
	}
	current, err := pinnedDeploymentFile(definition.PartsRegistry.File, definition.PartsRegistry.SHA256, 8<<20)
	if err != nil || string(current) != string(raw) {
		return mode, install.ErrTeamsSourceUnavailable
	}
	if selected {
		return originalTeamObjectScopeSelected, nil
	}
	return originalTeamFilesOnly, nil
}

func clearTeamModeSnapshot(snapshot domain.Snapshot) {
	for _, table := range snapshot.Tables {
		for _, row := range table.Rows {
			for _, cell := range row {
				clear(cell.Bytes)
			}
		}
	}
}
