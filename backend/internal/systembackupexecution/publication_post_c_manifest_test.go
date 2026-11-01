package systembackupexecution

import (
	"bytes"
	"context"
	"errors"
	"testing"

	c "clawreef/internal/systembackupcontroller"
)

// Parser DATA only. This reuses the explicitly inert upload DTO fixture and
// creates no remote C receipt, authority, SQL fact, signature or native proof.
func postCManifestParserData(t *testing.T) (publicationVerifiedCapture, PublicationTargetMaterials, *publicationUploadedCaptureData) {
	t.Helper()
	observed := originalUploadPollFixtureData(t)
	data, err := originalPublicationUploadedData(observed)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodePublicationManifestV12(data.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	capture := publicationVerifiedCapture{DescriptionSHA256: hash([]byte("inert description parser DATA")), CaptureContextSHA256: m.CaptureContext}
	capture.Input.InstallationID, capture.Input.TaskPublicID = m.Installation, m.Backup
	capture.Input.ConfigVersion, capture.Input.ConfigSHA256 = m.Config.Version, m.Config.SHA256
	capture.Input.CaptureAttemptNo = m.Attempt
	capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
	target := PublicationTargetMaterials{InstallationID: m.Installation, Root: observed.Request.ArtifactRoot, RemoteStagingRoot: observed.Request.RemoteStagingRoot}
	return capture, target, data
}

func TestPostCManifestInputSelectsExactOriginalObjectsData(t *testing.T) {
	for _, mode := range []string{"complete", "missing-object", "extra-object", "foreign-key", "version-latest", "version-null", "bad-size", "index-changed", "certificate-changed", "bootstrap-changed", "manifest-context", "manifest-config", "candidate-key", "candidate-version", "candidate-hash", "no-request-hash", "missing-capture-data"} {
		t.Run(mode, func(t *testing.T) {
			capture, target, data := postCManifestParserData(t)
			switch mode {
			case "missing-object":
				delete(data.Objects, "parts/mysql/container.enc")
			case "extra-object":
				data.Objects["extra.enc"] = data.Objects["parts/mysql/container.enc"]
			case "foreign-key", "version-latest", "version-null", "bad-size":
				o := data.Objects["parts/mysql/container.enc"]
				if mode == "foreign-key" {
					o.Key = "foreign/parts/mysql/container.enc"
				}
				if mode == "version-latest" {
					o.Version = "latest"
				}
				if mode == "version-null" {
					o.Version = "null"
				}
				if mode == "bad-size" {
					o.Size++
				}
				data.Objects["parts/mysql/container.enc"] = o
			case "index-changed":
				data.Index[len(data.Index)-1] ^= 1
			case "certificate-changed":
				data.Certificate[len(data.Certificate)-1] ^= 1
			case "bootstrap-changed":
				data.Bootstrap[len(data.Bootstrap)-1] ^= 1
			case "manifest-context":
				capture.CaptureContextSHA256 = hash([]byte("foreign context DATA"))
				capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
			case "manifest-config":
				capture.Input.ConfigSHA256 = hash([]byte("foreign config DATA"))
				capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
			case "candidate-key":
				data.Candidate.Key = "foreign/manifest-candidate.json"
			case "candidate-version":
				data.Candidate.Version = "latest"
			case "candidate-hash":
				data.Candidate.SHA256 = hash([]byte("foreign manifest DATA"))
			case "no-request-hash":
				data.RequestSHA256 = ""
			case "missing-capture-data":
				capture.receipt = nil
			}
			owned, objects, err := originalPostCManifestData(capture, target, data)
			if mode != "complete" {
				if err == nil || owned != nil {
					t.Fatal("invalid inert input selected", mode)
				}
				return
			}
			if err != nil || owned == nil || len(objects.Containers) != 6 || len(objects.Control) != 6 || len(objects.Metadata) != 3 {
				t.Fatal("exact15 DATA selection", err)
			}
			manifest, index := bytes.Clone(owned.Manifest), bytes.Clone(owned.Index)
			certificate, bootstrap := bytes.Clone(owned.Certificate), bytes.Clone(owned.Bootstrap)
			object := objects.Containers["mysql"]
			originalPins := owned.ResultBodySHA256
			clear(data.Manifest)
			clear(data.Index)
			clear(data.Certificate)
			clear(data.Bootstrap)
			delete(data.Objects, "parts/mysql/container.enc")
			data.ResultBodySHA256[0] = hash([]byte("changed input pin DATA"))
			if !bytes.Equal(owned.Manifest, manifest) || !bytes.Equal(owned.Index, index) || !bytes.Equal(owned.Certificate, certificate) || !bytes.Equal(owned.Bootstrap, bootstrap) || owned.Objects["parts/mysql/container.enc"] != object || objects.Containers["mysql"] != object || owned.ResultBodySHA256 != originalPins {
				t.Fatal("input or object map aliased its caller")
			}
		})
	}
}

func TestPostCManifestProductionGateRejectsMissingRealReceipt(t *testing.T) {
	capture, target, data := postCManifestParserData(t)
	owned, objects, err := originalPostCManifestData(capture, target, data)
	if err != nil {
		t.Fatal(err)
	}
	service := &DeploymentService{}
	store := &nativePublicationS3{config: target}
	claim := c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: capture.Input.TaskPublicID}, Owner: "controller:inert-DATA", RowVersion: 1}
	// Neither nil nor a zero-value receipt has a real final SQL authority.
	for _, receipt := range []*publicationRemoteContainerReceipt{nil, {}} {
		object, err := service.publishOriginalManifestAfterRemoteCapture(context.Background(), claim, 1, store, capture, objects, receipt, owned, publicationPostCUploadSnapshot{})
		if !errors.Is(err, c.ErrExecutionAuthority) || object.Key != "" {
			t.Fatal("inert DATA minted a manifest or touched absent SQL", err)
		}
		if err := receipt.recheckTx(context.Background(), nil, service, claim, 1, target, capture, objects); !errors.Is(err, c.ErrExecutionAuthority) {
			t.Fatal("missing transaction/current receipt accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if object, err := service.completeOriginalPublicationUploadedManifest(ctx, &claim, 1, c.LeasePolicy{}, store, capture); !errors.Is(err, c.ErrExecutionAuthority) || object.Key != "" {
		t.Fatal("canceled production bridge proceeded", err)
	}
}
