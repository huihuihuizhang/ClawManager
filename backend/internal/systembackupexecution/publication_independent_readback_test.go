package systembackupexecution

import (
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
)

func TestPublicationReadbackParts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*publicationContentSampleReport)
	}{
		{name: "complete"},
		{name: "missing part", mutate: func(r *publicationContentSampleReport) { r.Members = r.Members[1:] }},
		{name: "duplicate member", mutate: func(r *publicationContentSampleReport) { r.Members = append(r.Members, r.Members[0]) }},
		{name: "different version", mutate: func(r *publicationContentSampleReport) { r.Members[0].Container.Version = "other-version" }},
		{name: "floating version", mutate: func(r *publicationContentSampleReport) {
			r.Members[0].Container.Version = "latest"
			r.Members[0].Member.ObjectVersion = "latest"
		}},
		{name: "different checkpoint", mutate: func(r *publicationContentSampleReport) {
			r.Members[0].Member.CheckpointSHA256 = hash([]byte("other checkpoint"))
		}},
		{name: "different ciphertext", mutate: func(r *publicationContentSampleReport) {
			r.Members[0].Container.SHA256 = hash([]byte("other ciphertext"))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var sample publicationContentSampleReport
			manifest := publicationManifestV12{Parts: map[string]publicationManifestPart{}}
			for _, name := range publicationRequestedParts {
				checkpoint := hash([]byte(name + " checkpoint"))
				ciphertext := hash([]byte(name + " ciphertext"))
				raw, err := ce.Canonical([]struct{ Part, SHA256 string }{{name, checkpoint}})
				if err != nil {
					t.Fatal(err)
				}
				manifest.Parts[name] = publicationManifestPart{CipherSHA256: ciphertext, CheckpointSHA256: hash(raw)}
				sample.Members = append(sample.Members, publicationContentMemberSample{Part: name, RequestedPart: name,
					Container: ArtifactReadObject{Version: "fixed-version", SHA256: ciphertext, Size: 1},
					Member:    pc.MemberLocation{Part: name, ObjectVersion: "fixed-version", CheckpointSHA256: checkpoint}})
			}
			if tt.mutate != nil {
				tt.mutate(&sample)
			}
			parts, err := publicationReadbackParts(sample, manifest)
			if tt.mutate != nil {
				if err == nil {
					t.Fatal("invalid member set accepted")
				}
				return
			}
			if err != nil || len(parts) != len(publicationRequestedParts) {
				t.Fatalf("original member set rejected: parts=%d err=%v", len(parts), err)
			}
		})
	}
}
