package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
)

// Original production-factory protocol DATA, with an explicitly test-created
// inert capture snapshot. It is not an actual SQL, AEAD, certificate, current
// permission or private remote-capture receipt. Only parser bindings are tested.
func remoteDescriptionSemanticsData(t *testing.T) (publicationVerifiedCapture, worker.Invocation, []byte) {
	t.Helper()
	_, carrier, description := descriptionFactoryFixture(t)
	defer description.Clear()
	raw, err := cd.Encode(description)
	if err != nil {
		t.Fatal(err)
	}
	capture := publicationVerifiedCapture{CaptureContextSHA256: description.Scope.CaptureContextSHA256, DescriptionSHA256: hash(raw)}
	capture.Input.InstallationID, capture.Input.TaskPublicID = description.Scope.InstallationID, description.Scope.TaskPublicID
	capture.Input.ConfigVersion, capture.Input.ConfigSHA256 = description.Scope.ConfigVersion, description.Scope.ConfigSHA256
	capture.Input.CaptureAttemptNo = description.Scope.AttemptNo
	capture.Input.SourceSnapshot, capture.Input.SourceSHA256 = bytes.Clone(description.SourceInventoryJSON), description.SourceInventorySHA256
	for _, member := range description.Members {
		capture.Parts = append(capture.Parts, publicationVerifiedPart{Part: member.Part, Operation: member.Operation, RequestedPart: publicationRequestedPart(member.Operation), Index: member.PartIndex, InvocationSHA256: member.SHA256, CandidateSHA256: member.CandidateSHA256, ResultSHA256: member.ResultSHA256})
	}
	for _, inv := range description.AdministrativeInvocations {
		cipher, envelope := publicationPartPaths(inv.Part, inv.PartIndex, inv.SHA256)
		capture.Parts = append(capture.Parts, publicationVerifiedPart{Part: inv.Part, Operation: inv.Operation, Index: inv.PartIndex, InvocationSHA256: inv.SHA256, CipherPath: cipher, EnvelopePath: envelope, CipherBytes: 10, EnvelopeBytes: 10, CipherSHA256: hash([]byte(cipher)), EnvelopeSHA256: hash([]byte(envelope))})
		if inv.Part == ce.Part {
			var original worker.Invocation
			if json.Unmarshal(inv.JSON, &original) != nil || original.Request.ControlEvidence == nil {
				t.Fatal("factory control seed DATA")
			}
			capture.ControlSeed = *original.Request.ControlEvidence
		}
	}
	capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
	return capture, carrier, raw
}

func TestRemoteDescriptionSemanticsKeepOriginalCaptureBindings(t *testing.T) {
	for _, mode := range []string{"healthy", "config-scope", "source-bytes", "source-hash", "member-invocation", "member-candidate", "member-result", "admin-invocation", "control-seed", "unsealed-snapshot", "plain-hash", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			capture, carrier, raw := remoteDescriptionSemanticsData(t)
			defer clear(raw)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "config-scope":
				capture.Input.ConfigVersion++
			case "source-bytes":
				capture.Input.SourceSnapshot[0] ^= 1
			case "source-hash":
				capture.Input.SourceSHA256 = hash([]byte("foreign source DATA"))
			case "member-invocation":
				capture.Parts[0].InvocationSHA256 = hash([]byte("foreign invocation DATA"))
			case "member-candidate":
				capture.Parts[0].CandidateSHA256 = hash([]byte("foreign candidate DATA"))
			case "member-result":
				capture.Parts[0].ResultSHA256 = hash([]byte("foreign result DATA"))
			case "admin-invocation":
				capture.Parts[len(capture.Parts)-1].InvocationSHA256 = hash([]byte("foreign admin DATA"))
			case "control-seed":
				capture.ControlSeed.Expected.ConfigSHA256 = hash([]byte("foreign seed DATA"))
			case "plain-hash":
				raw[len(raw)-1] ^= 1
			case "canceled":
				cancel()
			}
			// Foreign outer snapshot DATA is independently supplied to the parser;
			// resealing here does not authenticate a task or mint a remote receipt.
			if mode == "unsealed-snapshot" {
				capture.receipt = nil
			} else {
				capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
			}
			err := inspectOriginalRemoteDescription(ctx, bytes.NewReader(raw), capture, carrier)
			if mode == "healthy" && err != nil {
				t.Fatal("original bindings DATA", err)
			}
			if mode != "healthy" && err == nil {
				t.Fatal("foreign description accepted", mode)
			}
		})
	}
}

func TestRemoteDescriptionLayoutAndIndexUseAuthenticatedCarrier(t *testing.T) {
	for _, mode := range []string{"healthy", "missing-original-carrier", "missing-original-description-hash", "foreign-original-operation", "foreign-original-path"} {
		t.Run(mode, func(t *testing.T) {
			capture, _, raw := remoteDescriptionSemanticsData(t)
			defer clear(raw)
			for i := range capture.Parts {
				if capture.Parts[i].Part != cd.Part {
					continue
				}
				switch mode {
				case "missing-original-carrier":
					capture.Parts = append(capture.Parts[:i], capture.Parts[i+1:]...)
				case "missing-original-description-hash":
					capture.DescriptionSHA256 = ""
				case "foreign-original-operation":
					capture.Parts[i].Operation = ce.Operation
				case "foreign-original-path":
					capture.Parts[i].CipherPath = "control/foreign.enc"
				}
				break
			}
			capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
			description, err := originalRemoteCaptureHasDescription(capture)
			if mode != "healthy" {
				if err == nil {
					t.Fatal("remote object count could replace original protocol", mode)
				}
				return
			}
			if err != nil || !description {
				t.Fatal("original carrier DATA", err)
			}
			_, flat := remoteCaptureSetData(t)
			objects := publicationRemoteContainerObjects{Containers: map[string]ArtifactReadObject{}, Control: map[string]ArtifactReadObject{}}
			for _, name := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
				objects.Containers[name] = flat["parts/"+name+"/container.enc"]
			}
			indexRaw, err := originalRemoteContainerIndex(capture, objects, []byte("opaque bootstrap index DATA"))
			var index publicationArtifactIndex
			if err != nil || json.Unmarshal(indexRaw, &index) != nil || len(index.Entries) != 13 {
				t.Fatal("container index must be 13, never per-member 22+", err, len(index.Entries))
			}
		})
	}
}
