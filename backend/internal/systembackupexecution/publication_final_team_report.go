package systembackupexecution

import (
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	source "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// TeamContentReport is a restricted content observation, NOT an authentication,
// acceptance, restore grant or public manifest. Paths/owner labels are business
// metadata: only an already-authorized reporting consumer may export it.
type TeamContentReport struct {
	Version, Scope, Selection, ContentObservationsSHA256 string
	CaptureContextSHA256, ConfigSHA256                   string
	AuthenticatedRead                                    publicationContentSampleReport
	RelationsComplete                                    bool
	Teams                                                []TeamContentObservation
}
type TeamContentObservation struct {
	TeamID, UserID             int
	ResourceScope, Owner       string
	SQLRows                    []TeamSQLObservation
	TaskStates, WorkItemStates []TeamStateObservation
	Workspace                  *TeamWorkspaceObservation
	ObjectScope                string
	Objects                    []team.ObjectRef
	Redis                      TeamRedisObservation
}
type TeamSQLObservation struct {
	Table string
	Rows  int64
}
type TeamStateObservation struct {
	State string
	Rows  int64
}
type TeamFileObservation struct {
	Path  string
	Bytes int64
}
type TeamWorkspaceObservation struct {
	Part                                   string
	Entries, RegularFiles, ContentBytes    int64
	ReferencesExpected, ReferencesVerified int
	SampledFiles                           []TeamFileObservation
	SampledReferences                      []TeamFileObservation
}
type TeamRedisObservation struct {
	Scope, SourceID, ServerID            string
	Database                             int
	CapturedAtMillis, Keys, ContentBytes int64
}

// Tentative observations live on the EXISTING relation round. They become
// reportable only after the public C reader confirms all members and the typed
// terminal reporting boundary supplies its original, digest-bound observations.
type publicationTeamObservations struct {
	rows          map[int]map[string]int64
	tasks, work   map[int]map[string]int64
	workspaces    map[string]*publicationFinalTeamWorkspaceRead
	redis         map[int]TeamRedisObservation
	redisObserved bool
}

func newPublicationTeamObservations(inv *team.Inventory) *publicationTeamObservations {
	o := &publicationTeamObservations{rows: map[int]map[string]int64{}, tasks: map[int]map[string]int64{}, work: map[int]map[string]int64{}, workspaces: map[string]*publicationFinalTeamWorkspaceRead{}, redis: map[int]TeamRedisObservation{}}
	for _, t := range inv.Teams {
		o.rows[t.ID] = map[string]int64{}
		o.tasks[t.ID] = map[string]int64{}
		o.work[t.ID] = map[string]int64{}
	}
	return o
}
func (o *publicationTeamObservations) observeSQL(snapshot domain.Snapshot) {
	owned := map[string]bool{}
	for _, name := range team.SQLTableNames() {
		owned[name] = true
	}
	for _, tbl := range snapshot.Tables {
		if !owned[tbl.Name] {
			continue
		}
		for _, row := range tbl.Rows {
			key := "team_id"
			if tbl.Name == "teams" {
				key = "id"
			}
			id, _ := strconv.Atoi(row[key].String())
			if o.rows[id] == nil {
				continue
			}
			// Tables without a Team FK (templates, users, operations, etc.)
			// remain in AuthenticatedRead.SQLTables; do not invent a Team join.
			o.rows[id][tbl.Name]++
			if tbl.Name == "team_tasks" {
				o.tasks[id][row["status"].String()]++
			}
			if tbl.Name == "team_work_items" {
				o.work[id][row["status"].String()]++
			}
		}
	}
}

func (r *publicationFinalTeamRelations) observeSharedRedis(snapshot source.RedisSourceSnapshot) error {
	if r == nil || r.failed || r.observations == nil || r.observations.redisObserved || r.confirmed[b.UsersInstancesDatabasePart] == "" {
		return c.ErrExecutionRecord
	}
	byTeam := map[int]TeamRedisObservation{}
	for _, scope := range r.inventory.Redis {
		if scope.ID != snapshot.Header.Source.ID || scope.ServerID != snapshot.Header.ServerID || scope.Database != snapshot.Header.Database {
			return c.ErrExecutionRecord
		}
		for _, id := range scope.TeamIDs {
			byTeam[id] = TeamRedisObservation{Scope: "authenticated_prefix_counts_not_sql_stream_semantic_join", SourceID: scope.ID, ServerID: scope.ServerID, Database: scope.Database, CapturedAtMillis: snapshot.Header.CapturedAtMillis}
		}
	}
	for _, item := range snapshot.Items {
		tail, ok := strings.CutPrefix(string(item.Key), "claw:team:")
		if !ok {
			continue
		}
		number, _, ok := strings.Cut(tail, ":")
		if !ok {
			continue
		}
		id, err := strconv.Atoi(number)
		if err != nil || strconv.Itoa(id) != number {
			continue
		}
		observed, exists := byTeam[id]
		if !exists {
			continue
		} // Other domains/deleted history are legitimate.
		observed.Keys++
		observed.ContentBytes += int64(len(item.Key) + len(item.Dump) + len(item.StreamGroups))
		byTeam[id] = observed
	}
	r.observations.redis, r.observations.redisObserved = byTeam, true
	return nil
}

func sortedTeamStates(values map[string]int64) []TeamStateObservation {
	out := []TeamStateObservation{}
	for state, rows := range values {
		out = append(out, TeamStateObservation{state, rows})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].State < out[j].State })
	return out
}

func (r *publicationFinalTeamRelations) contentReport(authenticated publicationContentSampleReport, digest string) (TeamContentReport, error) {
	var zero TeamContentReport
	if r == nil || r.complete() != nil || r.observations == nil || !formalCandidateDigest(digest) || authenticated.Version != "system-backup-final-content-observations.v1" || authenticated.Backup != r.backup || strconv.FormatUint(authenticated.Attempt, 10) != r.attempt || authenticated.TeamsInventorySHA256 != r.inventory.SHA256() || !formalCandidateDigest(authenticated.SourceSHA256) || !formalCandidateDigest(authenticated.ArtifactReadIdentitySHA256) || !fixedPublicationReadVersion(authenticated.Manifest.Version) || !formalCandidateDigest(authenticated.Manifest.SHA256) || authenticated.Manifest.Size < 1 {
		return zero, c.ErrExecutionRecord
	}
	raw, err := ce.Canonical(authenticated)
	if err != nil || hash(raw) != digest {
		return zero, c.ErrExecutionRecord
	}
	parts := map[string]publicationContentMemberSample{}
	for _, member := range authenticated.Members {
		if parts[member.Part].Part != "" || !member.Counts.Complete || !fixedPublicationReadVersion(member.Container.Version) || member.Member.ObjectVersion != member.Container.Version || !formalCandidateDigest(member.Container.SHA256) {
			return zero, c.ErrExecutionRecord
		}
		parts[member.Part] = member
	}
	if len(parts) != len(r.confirmed) {
		return zero, c.ErrExecutionRecord
	}
	for part, h := range r.confirmed {
		member, ok := parts[part]
		if !ok || member.InvocationSHA256 != h {
			return zero, c.ErrExecutionRecord
		}
	}
	// Observing decrypted Redis is tentative, just like SQL/workspace parsing.
	// It may be exported only with this round's confirmed shared Redis member.
	if _, ok := parts[b.SourceRedisPart]; ok != r.observations.redisObserved {
		return zero, c.ErrExecutionRecord
	}
	if len(r.inventory.Objects) > 0 {
		member := parts["teams_objects"]
		var size int64
		for _, ref := range r.inventory.Objects {
			size += ref.Size
		}
		if member.Counts.Items != int64(len(r.inventory.Objects)) || member.Counts.ContentBytes != size {
			return zero, c.ErrExecutionRecord
		}
	}
	report := TeamContentReport{Version: "system-backup-team-content-report.v1", Scope: "same_authenticated_final_read_only_not_acceptance", Selection: "all inventory Teams; all artifact references checked; up to 3 lexicographically first regular files and references per Team shown", ContentObservationsSHA256: digest, CaptureContextSHA256: r.context, ConfigSHA256: r.config, AuthenticatedRead: authenticated, RelationsComplete: true}
	for _, t := range r.inventory.Teams {
		observed := TeamContentObservation{TeamID: t.ID, UserID: t.UserID, ResourceScope: t.ResourceScope, Owner: t.Owner, ObjectScope: "original_inventory_empty_not_absence_proof", TaskStates: sortedTeamStates(r.observations.tasks[t.ID]), WorkItemStates: sortedTeamStates(r.observations.work[t.ID]), Redis: TeamRedisObservation{Scope: "no_authenticated_shared_redis_member"}}
		for _, name := range team.SQLTableNames() {
			if name != "custom_team_templates" {
				observed.SQLRows = append(observed.SQLRows, TeamSQLObservation{name, r.observations.rows[t.ID][name]})
			}
		}
		if value, ok := r.observations.redis[t.ID]; ok {
			observed.Redis = value
		}
		part := "team_" + strconv.Itoa(t.ID) + "_workspace"
		if _, expected := r.workspaces[part]; expected {
			read := r.observations.workspaces[part]
			member := parts[part]
			if read == nil || read.complete() != nil || member.Counts.ArchiveEntries != read.entries || member.Counts.ContentBytes != read.bytes {
				return zero, c.ErrExecutionRecord
			}
			observed.Workspace = &TeamWorkspaceObservation{Part: part, Entries: read.entries, RegularFiles: read.files, ContentBytes: read.bytes, ReferencesExpected: len(r.refs[part]), ReferencesVerified: len(r.refs[part]), SampledFiles: read.samples, SampledReferences: read.referenceSamples}
		}
		for _, ref := range r.inventory.Objects {
			if ref.TeamID == t.ID {
				observed.Objects = append(observed.Objects, ref)
				observed.ObjectScope = "all_original_fixed_versions_read_and_verified"
			}
		}
		report.Teams = append(report.Teams, observed)
	}
	sort.Slice(report.Teams, func(i, j int) bool { return report.Teams[i].TeamID < report.Teams[j].TeamID })
	// Copy all nested report/member slices. A reporting consumer cannot modify
	// the existing authenticated receipt or subsequent snapshots through aliases.
	raw, err = json.Marshal(report)
	if err != nil {
		return zero, c.ErrExecutionRecord
	}
	defer clear(raw)
	if json.Unmarshal(raw, &zero) != nil {
		return TeamContentReport{}, c.ErrExecutionRecord
	}
	return zero, nil
}

// TeamContentSamples consumes the EXISTING public-C typed reporting boundary.
// There is no raw-JSON, caller callback or alternative authentication entry.
func (p *publicationTerminalReady) TeamContentSamples() (TeamContentReport, error) {
	authenticated, err := p.ContentSamples()
	if err != nil {
		return TeamContentReport{}, err
	}
	proof := decisionRegisteredProof(p.decision.registered)
	return proof.teamRelations.contentReport(authenticated, p.facts.ContentSamplesSHA256)
}

// WriteTeamContentSamples is for the public C coordinator's restricted report
// sink after it obtains the real typed Ready. It does not open a file, fetch a
// product, authenticate JSON, sign evidence or create/complete any task.
func (p *publicationTerminalReady) WriteTeamContentSamples(dst io.Writer) error {
	if dst == nil {
		return c.ErrExecutionRecord
	}
	report, err := p.TeamContentSamples()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(dst)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
