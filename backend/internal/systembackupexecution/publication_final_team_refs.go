package systembackupexecution

import (
	"archive/tar"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

// One remote verification round's private SQL/file join, not an authority or
// acceptance receipt. Discard it on any outer stream/authority failure. The
// caller confirms a part ONLY after full AEAD/EOF and current-claim recheck.
// Explicit per-part claim Renew within this round is allowed: no live claim,
// guard, verifier or key is retained here. Never reuse across rounds/restarts.
type publicationFinalTeamRelations struct {
	inventory                        *team.Inventory
	database, server                 string
	backup, attempt, context, config string
	workspaces                       map[string]int
	refs                             map[string][]string
	parsed, confirmed                map[string]string
	sqlObserved, failed              bool
	observations                     *publicationTeamObservations
}

func newPublicationFinalTeamRelations(source b.SourceInventory) (*publicationFinalTeamRelations, error) {
	users, owners := map[int]bool{}, map[int]int{}
	for _, id := range source.Users {
		if id <= 0 || users[id] {
			return nil, d.ErrNotReady
		}
		users[id] = true
	}
	for _, instance := range source.Instances {
		if instance.ID <= 0 || owners[instance.ID] != 0 || !users[instance.UserID] {
			return nil, d.ErrNotReady
		}
		owners[instance.ID] = instance.UserID
	}
	inv := team.CloneInventory(source.Teams)
	if source.Database == "" || source.ServerUUID == "" || inv == nil || inv.Validate(users, owners) != nil {
		return nil, d.ErrNotReady
	}
	r := &publicationFinalTeamRelations{inventory: inv, database: source.Database, server: source.ServerUUID, workspaces: map[string]int{}, refs: map[string][]string{}, parsed: map[string]string{}, confirmed: map[string]string{}}
	r.observations = newPublicationTeamObservations(inv)
	for _, mount := range inv.Mounts {
		part := "team_" + strconv.Itoa(mount.TeamID) + "_workspace"
		if _, exists := r.workspaces[part]; exists {
			return nil, d.ErrNotReady
		}
		r.workspaces[part] = mount.TeamID
	}
	return r, nil
}

func (r *publicationFinalTeamRelations) begin(i worker.Invocation) error {
	if r == nil || r.failed {
		return d.ErrNotReady
	}
	binding := i.Request.Binding
	if binding.BackupID == "" || binding.Attempt == "" || !formalCandidateDigest(binding.CaptureContextHash) || binding.Path == "" || r.parsed[binding.Path] != "" || i.FormalCapture == nil || !formalCandidateDigest(i.FormalCapture.ConfigSHA256) {
		return d.ErrNotReady
	}
	if r.backup == "" {
		r.backup, r.attempt, r.context, r.config = binding.BackupID, binding.Attempt, binding.CaptureContextHash, i.FormalCapture.ConfigSHA256
	}
	if r.backup != binding.BackupID || r.attempt != binding.Attempt || r.context != binding.CaptureContextHash || r.config != i.FormalCapture.ConfigSHA256 {
		return d.ErrNotReady
	}
	q := i.Request
	if q.Database != nil {
		if binding.Path != b.UsersInstancesDatabasePart || q.Operation != "capture-database" || q.Database.Name != r.database || q.Database.ServerUUID != r.server || q.Database.TeamsInventory == nil || q.Database.TeamsInventory.SHA256() != r.inventory.SHA256() {
			return d.ErrNotReady
		}
	} else if binding.Path == b.UsersInstancesDatabasePart {
		return d.ErrNotReady
	}
	if _, expected := r.workspaces[binding.Path]; expected {
		if q.Operation != "capture-workspace" || i.WorkspacePath != "/workspace" || q.RuntimePolicy != nil || q.WorkBuddyIdentity != nil || q.SkillWorkspace != nil || q.Teams != nil || q.Database != nil || q.SourceRedis != nil || q.Resources != nil || q.SkillObjects != nil || q.CaptureDescription != nil || q.ControlEvidence != nil || q.TeamWorkspace != nil || r.confirmed[b.UsersInstancesDatabasePart] == "" {
			return d.ErrNotReady
		}
	} else if strings.HasPrefix(binding.Path, "team_") && strings.HasSuffix(binding.Path, "_workspace") {
		return d.ErrNotReady
	}
	if q.Operation == "capture-team-objects" || binding.Path == "teams_objects" {
		if r.confirmed[b.UsersInstancesDatabasePart] == "" {
			return d.ErrNotReady
		}
		if binding.Path != "teams_objects" || q.Operation != "capture-team-objects" || len(r.inventory.Objects) == 0 || q.Teams == nil || q.Teams.Redis != nil || q.Database != nil || q.SourceRedis != nil || q.Resources != nil || q.SkillObjects != nil || q.SkillWorkspace != nil || q.CaptureDescription != nil || q.ControlEvidence != nil || q.TeamWorkspace != nil || q.Teams.InventorySHA256 != r.inventory.SHA256() || !reflect.DeepEqual(q.Teams.Objects, r.inventory.Objects) {
			return d.ErrNotReady
		}
	}
	return nil
}

// Called only on the already decoded/verified original SQL, before cells are
// cleared. Paths remain private and are never exported in counts/manifest.
func (r *publicationFinalTeamRelations) observeSQL(snapshot domain.Snapshot) error {
	if r == nil || r.failed || r.sqlObserved || domain.VerifyTeamCapture(snapshot, *r.inventory) != nil {
		return d.ErrNotReady
	}
	for _, t := range r.inventory.Teams {
		refs, err := domain.TeamArtifactReferences(snapshot, t.ID)
		if err != nil {
			return err
		}
		part := "team_" + strconv.Itoa(t.ID) + "_workspace"
		if _, exists := r.workspaces[part]; !exists && len(refs) != 0 {
			return d.ErrNotReady
		}
		r.refs[part] = refs
	}
	r.observations.observeSQL(snapshot)
	r.sqlObserved = true
	return nil
}

func (r *publicationFinalTeamRelations) parsedPart(i worker.Invocation) error {
	h, err := i.Hash()
	if r == nil || r.failed || err != nil || r.parsed[i.Request.Binding.Path] != "" {
		return d.ErrNotReady
	}
	r.parsed[i.Request.Binding.Path] = h
	return nil
}

// This acknowledges the surrounding authenticated read, not a caller-supplied
// covered flag. A prior parser error poisons this round permanently.
func (r *publicationFinalTeamRelations) confirmPart(i worker.Invocation) error {
	h, err := i.Hash()
	if r == nil {
		return d.ErrNotReady
	}
	if r.failed || err != nil || h == "" || r.parsed[i.Request.Binding.Path] != h || r.confirmed[i.Request.Binding.Path] != "" {
		r.failed = true
		return d.ErrNotReady
	}
	r.confirmed[i.Request.Binding.Path] = h
	return nil
}

func (r *publicationFinalTeamRelations) complete() error {
	if r == nil || r.failed || !r.sqlObserved || r.confirmed[b.UsersInstancesDatabasePart] == "" {
		return d.ErrNotReady
	}
	if len(r.parsed) != len(r.confirmed) {
		return d.ErrNotReady
	}
	for part := range r.workspaces {
		if r.confirmed[part] == "" {
			return d.ErrNotReady
		}
	}
	if len(r.inventory.Objects) != 0 && r.confirmed["teams_objects"] == "" {
		return d.ErrNotReady
	}
	return nil
}

type publicationFinalTeamWorkspaceRead struct {
	required, observed    map[string]byte
	entries, files, bytes int64
	samples               []TeamFileObservation
	referenceSamples      []TeamFileObservation
}

func (r *publicationFinalTeamRelations) workspaceRead(i worker.Invocation) *publicationFinalTeamWorkspaceRead {
	if _, expected := r.workspaces[i.Request.Binding.Path]; !expected {
		return nil
	}
	read := &publicationFinalTeamWorkspaceRead{required: map[string]byte{}, observed: map[string]byte{}}
	r.observations.workspaces[i.Request.Binding.Path] = read
	require := func(name string, kind byte) {
		if previous, exists := read.required[name]; exists && previous != kind {
			read.required[name] = 0
		} else {
			read.required[name] = kind
		}
	}
	for _, ref := range r.refs[i.Request.Binding.Path] {
		require(ref, tar.TypeReg)
		for parent := path.Dir(ref); parent != "."; parent = path.Dir(parent) {
			require(parent, tar.TypeDir)
		}
	}
	return read
}

func (r *publicationFinalTeamWorkspaceRead) observe(header *tar.Header) error {
	if r == nil {
		return nil
	}
	r.entries++
	r.bytes += header.Size
	if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
		r.files++
		r.samples = append(r.samples, TeamFileObservation{Path: header.Name, Bytes: header.Size})
		sort.Slice(r.samples, func(i, j int) bool { return r.samples[i].Path < r.samples[j].Path })
		if len(r.samples) > 3 {
			r.samples = r.samples[:3]
		}
	}
	if want, required := r.required[header.Name]; required {
		kind := header.Typeflag
		if kind == tar.TypeRegA {
			kind = tar.TypeReg
		}
		if kind != want || r.observed[header.Name] != 0 {
			return d.ErrNotReady
		}
		r.observed[header.Name] = kind
		if kind == tar.TypeReg {
			r.referenceSamples = append(r.referenceSamples, TeamFileObservation{Path: header.Name, Bytes: header.Size})
			sort.Slice(r.referenceSamples, func(i, j int) bool { return r.referenceSamples[i].Path < r.referenceSamples[j].Path })
			if len(r.referenceSamples) > 3 {
				r.referenceSamples = r.referenceSamples[:3]
			}
		}
	}
	return nil
}

func (r *publicationFinalTeamWorkspaceRead) complete() error {
	if r == nil {
		return nil
	}
	for name, kind := range r.required {
		if kind == 0 || r.observed[name] != kind {
			return d.ErrNotReady
		}
	}
	return nil
}
