package recovery

import (
	"crypto/sha256"
	"encoding/base32"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validID(s string) bool { return idPattern.MatchString(s) }
func digest(s string) bool  { return hashPattern.MatchString(s) }
func SixDomains() []string {
	return []string{"users", "instances", "ai_gateway", "teams", "resources", "skill_hub"}
}
func RequiredParts() []string {
	return []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}
}
func safeKey(s string) bool {
	return s != "" && s != "." && len(s) <= 1024 && !strings.HasPrefix(s, "/") && path.Clean(s) == s && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\\\x00\r\n?#")
}

type Identity struct {
	Origin       string `json:"origin_installation_id"`
	Backup       string `json:"backup_public_id"`
	Attempt      int64  `json:"attempt_no"`
	Orchestrator string `json:"orchestrator"`
	Profile      string `json:"deployment_profile"`
}

func (i Identity) Matrix() (string, error) {
	if !validID(i.Origin) || !validID(i.Backup) || i.Attempt < 1 {
		return "", ErrContract
	}
	o := i.Orchestrator
	if o == "kubernetes" {
		o = "k8s"
	}
	if o != "k8s" && o != "k3s" || i.Profile != "cluster" && i.Profile != "single-node" {
		return "", ErrContract
	}
	return o + "-" + i.Profile, nil
}

type Reference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func (r Reference) valid() bool { return validID(r.ID) && validID(r.Version) && digest(r.SHA256) }
func (r Reference) Validate() error {
	if !r.valid() {
		return ErrContract
	}
	return nil
}

type Object struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

func (o Object) valid() bool {
	return safeKey(o.Key) && o.Version != "" && len(o.Version) <= 1024 && !strings.ContainsAny(o.Version, "\x00\r\n") && o.Size > 0 && o.Size <= 1<<40 && digest(o.SHA256)
}

type Locator struct {
	Provider      string `json:"provider"`
	Bucket        string `json:"bucket"`
	Prefix        string `json:"prefix"`
	FailureDomain string `json:"failure_domain_id"`
}

func (l Locator) valid() bool {
	return l.Provider == "s3" && validID(l.Bucket) && safeKey(l.Prefix) && validID(l.FailureDomain)
}
func (l Locator) Validate() error {
	if !l.valid() {
		return ErrContract
	}
	return nil
}

type Bootstrap struct {
	ReadCredential Reference `json:"read_credential"`
	CA             Reference `json:"ca"`
	KEK            Reference `json:"kek"`
	Identity       Reference `json:"disaster_identity"`
}

func (b Bootstrap) valid() bool {
	return b.ReadCredential.valid() && b.CA.valid() && b.KEK.valid() && b.Identity.valid()
}
func (b Bootstrap) Validate() error {
	if !b.valid() {
		return ErrContract
	}
	return nil
}

type Index struct {
	Schema   string   `json:"schema_version"`
	Identity Identity `json:"identity"`
	Objects  []Object `json:"objects"`
}

func (i Index) Validate() error {
	if i.Schema != Version || len(i.Objects) == 0 || len(i.Objects) > 100000 {
		return ErrContract
	}
	if _, e := i.Identity.Matrix(); e != nil {
		return e
	}
	last := ""
	for _, o := range i.Objects {
		if !o.valid() || o.Key <= last || o.Key == "manifest.json" || o.Key == "artifact-index.json" || strings.HasPrefix(o.Key, "_") {
			return ErrContract
		}
		last = o.Key
	}
	return nil
}

type Summary struct {
	Count    int64     `json:"count"`
	Status   string    `json:"status"`
	Evidence Reference `json:"evidence"`
}
type PartSummary struct {
	Status      string    `json:"status"`
	Objects     []string  `json:"objects"`
	Checkpoint  Reference `json:"checkpoint"`
	Consistency string    `json:"consistency_class"`
}
type Warning struct {
	Code           string `json:"code"`
	Classification string `json:"classification"`
}
type Target struct {
	Class       string    `json:"class"`
	Risks       []string  `json:"risks"`
	Attestation Reference `json:"attestation"`
}
type Manifest struct {
	Schema         string                 `json:"schema_version"`
	Identity       Identity               `json:"identity"`
	AppVersion     string                 `json:"app_version"`
	GitVersion     string                 `json:"git_version"`
	CreatedAt      int64                  `json:"created_at_ms"`
	Purpose        string                 `json:"purpose"`
	MigrationHash  string                 `json:"migration_catalog_hash"`
	SchemaHash     string                 `json:"schema_hash"`
	CaptureHash    string                 `json:"capture_context_hash"`
	Config         Reference              `json:"config_snapshot"`
	SecretPolicy   Reference              `json:"secret_policy"`
	SchemaCoverage Reference              `json:"schema_object_coverage"`
	Target         Target                 `json:"target"`
	KEKRecoverable bool                   `json:"kek_recoverable"`
	Consistency    string                 `json:"consistency_class"`
	Index          Object                 `json:"artifact_index"`
	CommitMarker   string                 `json:"commit_marker"`
	Parts          map[string]PartSummary `json:"parts"`
	Domains        map[string]Summary     `json:"business_domains"`
	ControlPlane   Summary                `json:"control_plane"`
	Warnings       []Warning              `json:"warnings"`
}

func (m Manifest) Validate(index Index) error {
	if index.Validate() != nil || m.Schema != Version || m.Identity != index.Identity || m.CreatedAt <= 0 || !validID(m.AppVersion) || !validID(m.GitVersion) || !digest(m.MigrationHash) || !digest(m.SchemaHash) || !digest(m.CaptureHash) || !m.Config.valid() || !m.SecretPolicy.valid() || !m.SchemaCoverage.valid() || !m.Index.valid() || m.Index.Key != "artifact-index.json" || m.CommitMarker != "_COMMITTED" {
		return ErrContract
	}
	if m.Purpose != "acceptance" && m.Purpose != "functional_test" || m.Consistency != "strong" && m.Consistency != "bounded" {
		return ErrContract
	}
	if m.Target.Class != "dr-ready-external" && m.Target.Class != "same-cluster-copy" || !m.Target.Attestation.valid() || m.Target.Risks == nil || m.Warnings == nil {
		return ErrContract
	}
	if len(m.Parts) != 6 || len(m.Domains) != 6 || m.ControlPlane.Status != "passed" || !m.ControlPlane.Evidence.valid() || m.ControlPlane.Count < 0 {
		return ErrContract
	}
	indexRaw, e := Marshal(index)
	if e != nil || Hash(indexRaw) != m.Index.SHA256 || int64(len(indexRaw)) != m.Index.Size {
		return ErrContract
	}
	objects := map[string]bool{}
	for _, o := range index.Objects {
		objects[o.Key] = false
	}
	for _, key := range RequiredParts() {
		p, ok := m.Parts[key]
		if !ok || p.Status != "completed" || len(p.Objects) == 0 || !p.Checkpoint.valid() || p.Consistency != "strong" && p.Consistency != "bounded" || m.Consistency == "strong" && p.Consistency != "strong" {
			return ErrContract
		}
		for _, k := range p.Objects {
			if k == "restore-metadata/envelope.json" || k == "control/evidence.json.enc" {
				return ErrContract
			}
			used, exists := objects[k]
			if !exists || used {
				return ErrContract
			}
			objects[k] = true
		}
	}
	// Envelope and control evidence are indexed but not data parts.
	for k, used := range objects {
		if !used && k != "restore-metadata/envelope.json" && k != "control/evidence.json.enc" {
			return ErrContract
		}
	}
	if _, ok := objects["restore-metadata/envelope.json"]; !ok {
		return ErrContract
	}
	if _, ok := objects["control/evidence.json.enc"]; !ok {
		return ErrContract
	}
	for _, key := range SixDomains() {
		s, ok := m.Domains[key]
		if !ok || s.Status != "passed" || s.Count < 0 || !s.Evidence.valid() {
			return ErrContract
		}
	}
	if m.Domains["users"].Count < 1 {
		return ErrContract
	}
	for _, w := range m.Warnings {
		if !validID(w.Code) || (w.Classification != "operational" && w.Classification != "data-integrity" && w.Classification != "consistency" && w.Classification != "unsupported-evidence") {
			return ErrContract
		}
	}
	return nil
}

type Marker struct {
	Schema         string   `json:"schema_version"`
	Identity       Identity `json:"identity"`
	ManifestSHA256 string   `json:"manifest_checksum"`
	IndexSHA256    string   `json:"artifact_index_checksum"`
}
type Acceptance struct {
	Schema          string    `json:"schema_version"`
	Identity        Identity  `json:"identity"`
	ManifestSHA256  string    `json:"manifest_checksum"`
	MarkerSHA256    string    `json:"marker_checksum"`
	Cleanup         Reference `json:"staging_cleanup_evidence"`
	LocalAcceptance bool      `json:"local_acceptance"`
	Reasons         []string  `json:"local_reason_codes"`
	ReasonsSHA256   string    `json:"local_reason_codes_hash"`
	DecisionTime    int64     `json:"decision_time_ms"`
	Config          Reference `json:"config_snapshot"`
}

func localReasons(m Manifest) []string {
	r := []string{}
	if m.Consistency != "strong" {
		r = append(r, "consistency_not_strong")
	}
	for _, w := range m.Warnings {
		if w.Classification != "operational" {
			r = append(r, "disqualifying_warning")
			break
		}
	}
	if m.Target.Class != "dr-ready-external" {
		r = append(r, "target_not_external")
	}
	if len(m.Target.Risks) > 0 {
		r = append(r, "target_risk")
	}
	if !m.KEKRecoverable {
		r = append(r, "kek_not_recoverable")
	}
	if len(r) == 0 {
		return []string{"eligible"}
	}
	sort.Strings(r)
	return r
}
func BuildAcceptance(m Manifest, index Index, manifest, marker []byte, cleanup Reference, decision int64) (Acceptance, error) {
	if m.Validate(index) != nil || m.Purpose != "acceptance" || !cleanup.valid() || decision < m.CreatedAt {
		return Acceptance{}, ErrContract
	}
	var commit Marker
	if decode(marker, &commit) != nil || commit.Schema != Version || commit.Identity != m.Identity || commit.ManifestSHA256 != Hash(manifest) || commit.IndexSHA256 != m.Index.SHA256 {
		return Acceptance{}, ErrContract
	}
	r := localReasons(m)
	raw, _ := Marshal(r)
	return Acceptance{Version, m.Identity, Hash(manifest), Hash(marker), cleanup, len(r) == 1 && r[0] == "eligible", r, Hash(raw), decision, m.Config}, nil
}

type Core struct {
	Manifest   Object `json:"manifest"`
	Index      Object `json:"index"`
	Marker     Object `json:"marker"`
	Acceptance Object `json:"acceptance"`
}

func (c Core) valid() bool {
	return c.Manifest.valid() && c.Index.valid() && c.Marker.valid() && c.Acceptance.valid() && c.Manifest.Key == "manifest.json" && c.Index.Key == "artifact-index.json" && c.Marker.Key == "_COMMITTED" && c.Acceptance.Key == "_ACCEPTANCE"
}

type Registration struct {
	Identity      Identity  `json:"identity"`
	Matrix        string    `json:"matrix_key"`
	Locator       Locator   `json:"locator"`
	Core          Core      `json:"core"`
	Bootstrap     Bootstrap `json:"bootstrap"`
	AcceptanceKey Reference `json:"acceptance_signing_key"`
	DecisionTime  int64     `json:"decision_time_ms"`
}
type Deletion struct {
	RegistrationID     string  `json:"registration_id"`
	RegistrationSHA256 string  `json:"registration_sha256"`
	Locator            Locator `json:"locator"`
	Core               Core    `json:"core"`
	PruneRun           string  `json:"prune_run"`
	CandidateSHA256    string  `json:"candidate_sha256"`
	DeletedAt          int64   `json:"deleted_at_ms"`
	FirstActor         string  `json:"first_execute_actor"`
}
type Record struct {
	Schema       string        `json:"schema_version"`
	ID           string        `json:"record_id"`
	Type         string        `json:"record_type"`
	Registration *Registration `json:"registration,omitempty"`
	Deletion     *Deletion     `json:"deletion,omitempty"`
}

func RegistrationID(i Identity) string {
	b, e := Marshal([]any{"artifact_registered", i.Origin, i.Backup, i.Attempt})
	if e != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return "sbr_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:20]))
}
func (r Record) Key() (string, error) {
	if r.Schema != Version {
		return "", ErrContract
	}
	switch r.Type {
	case "artifact_registered":
		v := r.Registration
		if v == nil || r.Deletion != nil {
			return "", ErrContract
		}
		matrix, e := v.Identity.Matrix()
		if e != nil || matrix != v.Matrix || r.ID != RegistrationID(v.Identity) || !v.Locator.valid() || !v.Core.valid() || !v.Bootstrap.valid() || !v.AcceptanceKey.valid() || v.DecisionTime <= 0 {
			return "", ErrContract
		}
		if !strings.HasSuffix(v.Locator.Prefix, "/"+v.Identity.Origin+"/"+v.Identity.Backup+"/"+strconv.FormatInt(v.Identity.Attempt, 10)) {
			return "", ErrContract
		}
		return "registrations/" + r.ID + ".json", nil
	case "artifact_deleted":
		v := r.Deletion
		if v == nil || r.Registration != nil || !strings.HasPrefix(v.RegistrationID, "sbr_") || !validID(v.RegistrationID) || r.ID != "sbd_"+strings.TrimPrefix(v.RegistrationID, "sbr_") || !digest(v.RegistrationSHA256) || !v.Locator.valid() || !v.Core.valid() || !validID(v.PruneRun) || !digest(v.CandidateSHA256) || v.DeletedAt <= 0 || !validID(v.FirstActor) {
			return "", ErrContract
		}
		return "tombstones/" + v.RegistrationID + ".json", nil
	}
	return "", ErrContract
}
