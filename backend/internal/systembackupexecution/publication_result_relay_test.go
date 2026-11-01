package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/control"
	ce "clawreef/internal/systembackupcontrolevidence"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func aPublicationResultTransportData() (PublicationUploadRequest, []byte, PublicationUploadResult) {
	p := PublicationUploadRequest{Version: publicationPresignedUploadVersion, Installation: "installation_result", Backup: "sbk_11111111-1111-4111-8111-111111111111", Attempt: 1, Endpoint: "https://artifact.invalid", Region: "local-1", Bucket: "original", ArtifactRoot: "installation_result/", RemoteStagingRoot: "remote/installation_result/", CAHash: strings.Repeat("a", 64), CredentialHash: strings.Repeat("b", 64), CandidateOwnerHMAC: strings.Repeat("c", 64), Deadline: time.Now().Add(45 * time.Second), IndexBytes: []byte("index DATA"), Objects: []PublicationUploadInput{{Path: "parts/original.enc", SHA256: hash([]byte("encrypted DATA")), Bytes: 14}, {Path: "artifact-index.json", SHA256: hash([]byte("index DATA")), Bytes: 10}}}
	p.ManifestInput = []byte(`{"schema_version":"system-backup.v1","origin_installation_id":"` + p.Installation + `","backup_public_id":"` + p.Backup + `","attempt_no":1,"artifact_index":{"path":"artifact-index.json","checksum":"` + p.Objects[1].SHA256 + `"}}`)
	raw, _ := json.Marshal(p)
	result := PublicationUploadResult{Version: publicationUploadVersion, Installation: p.Installation, Backup: p.Backup, Attempt: p.Attempt, RequestSHA256: hash(raw)}
	for _, o := range p.Objects {
		result.Objects = append(result.Objects, PublicationUploadObservation{Key: p.ArtifactRoot + p.Backup + "/1/" + o.Path, Version: "fixed-" + strconv.Itoa(len(result.Objects)+1), SHA256: o.SHA256, Bytes: o.Bytes})
	}
	manifest, key, _ := p.validate()
	result.Candidate = PublicationUploadObservation{Key: key, Version: "fixed-candidate", SHA256: hash(manifest), Bytes: int64(len(manifest))}
	return p, raw, result
}

func TestPublicationResultTransportRealMTLSAndExactFixedHints(t *testing.T) {
	p, raw, result := aPublicationResultTransportData()
	calls := 0
	var issuer control.IdentityIssuer
	endpoint, _ := originalMTLSControlServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != PublicationResultPath || r.Header.Get("Authorization") != "Bearer actual-publication-bound-token" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 {
			t.Error("actual mTLS/bound-token result transport missing")
			w.WriteHeader(403)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 8193))
		var m publicationResultMessage
		canonical, err := ce.Canonical(json.RawMessage(body))
		if decodeProviderDeploymentJSON(body, &m) != nil || m.Sequence != uint64(calls) || m.validate(p, hash(raw)) != nil || err != nil || !bytes.Equal(body, canonical) {
			t.Error("fixed original lookup hint changed")
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}), func(value control.IdentityIssuer) { issuer = value })
	identity, err := issuer.IssueWorker(p.Backup, p.Deadline, hash(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Clear()
	dir := t.TempDir()
	for name, data := range identity.Data {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	token := filepath.Join(dir, "token")
	if err = os.WriteFile(token, []byte("actual-publication-bound-token"), 0600); err != nil {
		t.Fatal(err)
	}
	var connectError error
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{ConnectDone: func(_, _ string, err error) { connectError = err }})
	if err = SendPublicationUploadResult(ctx, endpoint+PublicationResultPath, dir, token, raw, result); err != nil || calls != 3 {
		t.Fatal("actual controlled result transport", calls, err, "local connection", connectError)
	}
	// A wrong candidate is rejected before reporting even the first valid C.
	bad := result
	bad.Candidate.Key = p.ArtifactRoot + p.Backup + "/1/_COMMITTED"
	if err = SendPublicationUploadResult(context.Background(), endpoint+PublicationResultPath, dir, token, raw, bad); err == nil || calls != 3 {
		t.Fatal("final-marker hint reached receiver")
	}
	for _, index := range []int{0, len(p.Objects)} {
		bad = result
		bad.Objects = append([]PublicationUploadObservation(nil), result.Objects...)
		if index == len(p.Objects) {
			bad.Candidate.Version = "latest"
		} else {
			bad.Objects[index].Version = "latest"
		}
		if err = SendPublicationUploadResult(context.Background(), endpoint+PublicationResultPath, dir, token, raw, bad); err == nil || calls != 3 {
			t.Fatal("latest part/candidate reached receiver", index)
		}
	}
}

func TestPublicationResultRejectsMutablePartAndCandidateVersions(t *testing.T) {
	p, raw, result := aPublicationResultTransportData()
	for _, sequence := range []uint64{1, uint64(len(p.Objects) + 1)} {
		object := result.Objects[0]
		if sequence > uint64(len(p.Objects)) {
			object = result.Candidate
		}
		message := publicationResultMessage{Version: publicationResultVersion, Installation: p.Installation, Backup: p.Backup, RequestSHA256: hash(raw), Attempt: 1, Sequence: sequence, Object: object}
		if err := message.validate(p, hash(raw)); err != nil {
			t.Fatal("opaque fixed native version refused", sequence, err)
		}
		for _, version := range []string{"", "null", "latest", "fixed\nversion"} {
			bad := message
			bad.Object.Version = version
			if err := bad.validate(p, hash(raw)); err == nil {
				t.Fatal("mutable/invalid part or candidate version accepted", sequence, version)
			}
		}
	}
}

func TestPublicationActivationAllowsOnlyJournaledNativeGeneration(t *testing.T) {
	yes, no := true, false
	want := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "original", Namespace: "backup", Annotations: map[string]string{"backup.clawmanager.io/v2-spec-sha256": strings.Repeat("a", 64)}, Labels: map[string]string{"backup.clawmanager.io/v2-task": "original-task"}}, Spec: batchv1.JobSpec{Suspend: &yes, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "upload", AutomountServiceAccountToken: &no, Containers: []corev1.Container{{Name: "worker", Image: "original"}}}}}}
	got := want.DeepCopy()
	got.UID, got.Generation = types.UID("11111111-1111-4111-8111-111111111111"), 1
	if !publicationJobMatchesActivation(want, got, nil) {
		t.Fatal("original suspended Job refused")
	}
	got.Generation = 3
	if publicationJobMatchesActivation(want, got, nil) {
		t.Fatal("unjournaled suspend/resume cycle was adopted")
	}
	got.Generation = 1
	a := &publicationActivation{JobUID: string(got.UID), JobSpecSHA256: strings.Repeat("a", 64), BeforeGeneration: 1, AfterGeneration: 2}
	got.Spec.Suspend, got.Generation = &no, 2
	if publicationJobMatchesActivation(want, got, nil) || !publicationJobMatchesActivation(want, got, a) {
		t.Fatal("started Job did not require original activation")
	}
	for _, mode := range []string{"generation", "uid", "spec", "command", "volume", "resuspended"} {
		other := got.DeepCopy()
		switch mode {
		case "generation":
			other.Generation++
		case "uid":
			other.UID = "22222222-2222-4222-8222-222222222222"
		case "spec":
			other.Annotations["backup.clawmanager.io/v2-spec-sha256"] = strings.Repeat("b", 64)
		case "command":
			other.Spec.Template.Spec.Containers[0].Command = []string{"other"}
		case "volume":
			other.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "source"}}
		case "resuspended":
			other.Spec.Suspend = &yes
		}
		if publicationJobMatchesActivation(want, other, a) {
			t.Fatal("native drift borrowed original activation", mode)
		}
	}
}
