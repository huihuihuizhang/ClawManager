package kube

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func publicationNodeRequest() PublishJobRequest {
	return PublishJobRequest{
		Identity: Identity{Namespace: "backup", Name: "original-publish", Owner: "sbk_11111111-1111-4111-8111-111111111111"},
		Image:    "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "upload-only",
		StagingClaim: "original-staging", StagingSubPath: "publication/sbk_11111111-1111-4111-8111-111111111111/1",
		InvocationConfigMap: "original-request", UploadCredentialSecret: "original-upload",
		RequestSHA256: strings.Repeat("b", 64), DeadlineSeconds: 300,
	}
}

func TestPublishJobNodeAffinityAndLegacyOmission(t *testing.T) {
	for _, mode := range []string{"subtree", "files", "relay"} {
		for _, node := range []string{"", "node-a", "node-a.example.internal"} {
			t.Run(mode+"/"+node, func(t *testing.T) {
				r := publicationNodeRequest()
				r.NodeName = node
				if mode != "subtree" {
					r.StagingSubPath = ""
					r.InputFiles = []PublishInputFile{{Path: "parts/original.enc", SubPath: ".controller-seals/seal-" + strings.Repeat("c", 64) + ".enc"}}
				}
				if mode == "relay" {
					r.ResultRelayURL = "https://controller.invalid/publication-result"
				}
				job, err := PublishJob(r)
				if err != nil {
					t.Fatal(err)
				}
				pod := job.Spec.Template.Spec
				if pod.NodeName != "" || len(pod.NodeSelector) != 0 {
					t.Fatal("publication bypassed scheduler or gained another node selector", pod.NodeName, pod.NodeSelector)
				}
				if node == "" {
					if pod.Affinity != nil {
						t.Fatal("legacy caller acquired implicit placement", pod.Affinity)
					}
					return
				}
				want := &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
						NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{
							{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{node}},
						}}},
					},
				}}
				if !reflect.DeepEqual(pod.Affinity, want) {
					t.Fatal("publication did not require the exact requested node", pod.Affinity)
				}
			})
		}
	}
}

func TestPublishJobRejectsInvalidNodeName(t *testing.T) {
	for _, node := range []string{"Node-A", "node_a", "node/a", "node:1", " node-a", "node-a ", "node\na", "node\x00a", "-node", "node-", ".node", "node.", "node..a", strings.Repeat("a", 254)} {
		t.Run(node, func(t *testing.T) {
			r := publicationNodeRequest()
			r.NodeName = node
			job, err := PublishJob(r)
			if !errors.Is(err, ErrResource) || job != nil {
				t.Fatal("invalid node produced a publication Job", node, err)
			}
		})
	}
}

func TestPublishJobNodeChangesOriginalIntentBytesAndSHA(t *testing.T) {
	r := publicationNodeRequest()
	legacy, err := PublishJob(r)
	if err != nil {
		t.Fatal(err)
	}
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	previousBytes := legacyBytes
	previousSHA := sha256.Sum256(previousBytes)
	for _, node := range []string{"node-a", "node-b"} {
		r.NodeName = node
		job, err := PublishJob(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(job)
		if err != nil {
			t.Fatal(err)
		}
		currentSHA := sha256.Sum256(raw)
		if bytes.Equal(raw, previousBytes) || currentSHA == previousSHA {
			t.Fatal("changed node did not change serialized original Job intent and SHA", node)
		}
		// Placement is part of the original Job bytes; request, identity,
		// command, mounts and every other intent field remain unchanged.
		withoutPlacement := job.DeepCopy()
		withoutPlacement.Spec.Template.Spec.Affinity = nil
		normalized, err := json.Marshal(withoutPlacement)
		if err != nil || !bytes.Equal(normalized, legacyBytes) {
			t.Fatal("node selection changed another original intent field", node, err)
		}
		repeated, err := PublishJob(r)
		if err != nil {
			t.Fatal(err)
		}
		repeatedBytes, err := json.Marshal(repeated)
		if err != nil || !bytes.Equal(raw, repeatedBytes) || currentSHA != sha256.Sum256(repeatedBytes) {
			t.Fatal("same original node request changed intent bytes or SHA", node, err)
		}
		previousBytes, previousSHA = raw, currentSHA
	}
}
