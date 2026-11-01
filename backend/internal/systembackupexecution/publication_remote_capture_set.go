package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

// Closed location/content selection for the description-carrier version.
// This is NOT a signature, original-plan, C/business or acceptance receipt.
// Its inputs must separately be authenticated by the current publication gate.
type publicationRemoteCaptureSet struct {
	base, indexSHA                             string
	limits                                     ArtifactReadLimits
	objects                                    map[string]ArtifactReadObject
	installation, backup, root, captureContext string
	attempt                                    uint64
	index                                      []byte
}

var remoteCaptureBackupID = regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`)

func fixedPublicationReadVersion(version string) bool {
	return version != "" && version != "null" && version != "latest" && version != "current" && version != "default" && len(version) <= 256 && !strings.ContainsAny(version, "\x00\r\n")
}

// Exactly 15 observed objects: six containers, three administrative C/envelope
// pairs, public bootstrap, certificate and index. Exactly 13 index entries;
// certificate/index are bound outside the index, never self-referential.
func selectPublicationRemoteCaptureSet(installation, backup string, attempt uint64, root, captureContext string, indexRaw []byte, expectedIndexSHA string, objects map[string]ArtifactReadObject, limits ArtifactReadLimits) (*publicationRemoteCaptureSet, error) {
	// This version has 13 fixed short paths/roles/framing values. 32 KiB is
	// above its maximum encoded shape, independent of the general index ceiling.
	if installation == "" || len(backup) > 128 || !remoteCaptureBackupID.MatchString(backup) || attempt < 1 || attempt > 9007199254740991 || !strings.HasSuffix(root, "/") || !safePublicationKey(strings.TrimSuffix(root, "/")) || !formalCandidateDigest(captureContext) || limits.validate() != nil || len(indexRaw) < 2 || len(indexRaw) > 32<<10 || int64(len(indexRaw)) > limits.MaxIndexBytes || !formalCandidateDigest(expectedIndexSHA) || hash(indexRaw) != expectedIndexSHA || len(objects) != 15 {
		return nil, errPublicationConflict
	}
	var index publicationArtifactIndex
	canonical, err := ce.Canonical(json.RawMessage(indexRaw))
	if err != nil || !bytes.Equal(canonical, indexRaw) || decodeProviderDeploymentJSON(indexRaw, &index) != nil || index.Version != "system-backup-artifact-index.v1" || index.Backup != backup || index.Attempt != attempt || index.CaptureContext != captureContext || len(index.Entries) != 13 {
		return nil, errPublicationConflict
	}
	type format struct{ role, framing string }
	expected := map[string]format{
		"control/evidence.json.enc":                 {"control_evidence", w.FramingVersion},
		"control/evidence.envelope.json":            {"envelope", w.EnvelopeVersion},
		"control/evidence-proofs.json.enc":          {"control_evidence", w.FramingVersion},
		"control/evidence-proofs.envelope.json":     {"envelope", w.EnvelopeVersion},
		"control/capture-description.json.enc":      {"control_evidence", w.FramingVersion},
		"control/capture-description.envelope.json": {"envelope", w.EnvelopeVersion},
		"control/capture-bootstrap.json":            {"control_evidence", "system-backup-capture-bootstrap.v1"},
	}
	for _, part := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		expected["parts/"+part+"/container.enc"] = format{"encrypted_payload", pc.Version}
	}
	base := root + backup + "/" + strconv.FormatUint(attempt, 10) + "/"
	selected := make(map[string]ArtifactReadObject, len(objects))
	var total int64
	for path, object := range objects {
		_, indexed := expected[path]
		if !indexed && path != "artifact-index.json" && path != "control/capture-certificate.json" || object.Key != base+path || !safePublicationKey(object.Key) || !fixedPublicationReadVersion(object.Version) || !formalCandidateDigest(object.SHA256) || object.Size < 1 || object.Size > limits.MaxArtifactBytes-total {
			return nil, errPublicationConflict
		}
		total += object.Size
		selected[path] = object
	}
	indexObject := selected["artifact-index.json"]
	if indexObject.SHA256 != expectedIndexSHA || indexObject.Size != int64(len(indexRaw)) {
		return nil, errPublicationConflict
	}
	last := ""
	for _, entry := range index.Entries {
		shape, ok := expected[entry.Path]
		object, exists := selected[entry.Path]
		if !ok || !exists || entry.Path <= last || entry.Role != shape.role || entry.Framing != shape.framing || entry.Size != object.Size || entry.SHA256 != object.SHA256 {
			return nil, errPublicationConflict
		}
		delete(expected, entry.Path)
		last = entry.Path
	}
	if len(expected) != 0 {
		return nil, errPublicationConflict
	}
	return &publicationRemoteCaptureSet{base: base, indexSHA: expectedIndexSHA, limits: limits, objects: selected, installation: installation, backup: backup, root: root, captureContext: captureContext, attempt: attempt, index: bytes.Clone(indexRaw)}, nil
}

// Read every selected fixed-version body to EOF using only artifact_read.
// This checks transport bytes, including index/certificate/bootstrap. It does
// not interpret their signatures/semantics, Unwrap C or mint a capture receipt.
// The current-publication verifier must additionally authenticate the original
// certificate, bootstrap, description, E/P and all business C before its receipt.
func (r *ArtifactReadOnlyS3) inspectPublicationRemoteCaptureSetBytes(ctx context.Context, set *publicationRemoteCaptureSet, until time.Time) error {
	if r == nil || r.store == nil || !r.store.readOnly || set == nil || ctx == nil || ctx.Err() != nil || until.IsZero() || !time.Now().Before(until) || r.limits != set.limits || r.store.config.InstallationID != set.installation || r.store.config.Root != set.root {
		return errPublicationConflict
	}
	// Revalidate, copy and pin before I/O; a same-package caller cannot silently
	// rebind a selected index or adopt a wider reader budget after selection.
	owned, err := selectPublicationRemoteCaptureSet(set.installation, set.backup, set.attempt, set.root, set.captureContext, set.index, set.indexSHA, set.objects, set.limits)
	if err != nil || owned.base != set.base {
		return errPublicationConflict
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	paths := make([]string, 0, len(owned.objects))
	for path := range owned.objects {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if bounded.Err() != nil || !time.Now().Before(until) {
			return errPublicationUnavailable
		}
		if _, err := r.store.credential(false); err != nil {
			return err
		}
		object := owned.objects[path]
		observed, err := readPublicationPayloadTo(bounded, r.store, publicationPayloadIntent{Key: object.Key, SHA256: object.SHA256, Size: object.Size}, object.Version, until, io.Discard)
		if err != nil {
			return err
		}
		if observed.Key != object.Key || observed.Version != object.Version || observed.SHA256 != object.SHA256 || observed.Size != object.Size || bounded.Err() != nil || !time.Now().Before(until) {
			return errPublicationConflict
		}
		if _, err := r.store.credential(false); err != nil {
			return err
		}
	}
	return nil
}
