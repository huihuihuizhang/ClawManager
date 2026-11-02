package systembackupexecution

import (
	"context"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

func TestPublicationReadyUniqueOuterBytes(t *testing.T) {
	identity := hash([]byte("artifact read identity DATA"))
	object := ArtifactReadObject{Key: "installation/task/1/parts/mysql/container.enc", Version: "original-v1", SHA256: hash([]byte("outer bytes DATA")), Size: 128}
	index := ArtifactReadObject{Key: "installation/task/1/artifact-index.json", Version: "index-v1", SHA256: hash([]byte("index DATA")), Size: 32}
	// Index and certificate can occur through several authenticated references;
	// the manifest/artifact alias must likewise never create another object.
	items := []publicationPhysicalObject{{identity, object}, {identity, index}, {identity, object}, {identity, index}}
	if sum, err := publicationUniqueOuterBytes(items, 160); err != nil || sum != 160 {
		t.Fatal("unique physical bytes", sum, err)
	}
	for _, mode := range []string{"checksum", "size", "limit", "negative", "latest", "unsafe-key", "identity"} {
		t.Run(mode, func(t *testing.T) {
			altered := append([]publicationPhysicalObject(nil), items...)
			limit := int64(160)
			switch mode {
			case "checksum":
				altered[2].Object.SHA256 = hash([]byte("different outer bytes"))
			case "size":
				altered[2].Object.Size++
			case "limit":
				limit--
			case "negative":
				altered[0].Object.Size = -1
			case "latest":
				altered[0].Object.Version = "latest"
			case "unsafe-key":
				altered[0].Object.Key = "../container.enc"
			case "identity":
				altered[0].Identity = ""
			}
			if _, err := publicationUniqueOuterBytes(altered, limit); err == nil {
				t.Fatal("invalid outer object set accepted", mode)
			}
		})
	}
	// A distinct fixed version/identity is physically distinct; callers supply
	// only this task's authenticated outer maps, never historical version lists.
	other := object
	other.Version = "original-v2"
	if sum, err := publicationUniqueOuterBytes([]publicationPhysicalObject{{identity, object}, {identity, other}}, 256); err != nil || sum != 256 {
		t.Fatal("distinct fixed versions aliased", sum, err)
	}
	other.Size = 1 << 62
	if _, err := publicationUniqueOuterBytes([]publicationPhysicalObject{{identity, object}, {identity, other}}, MaxPublicationArtifactBytes); err == nil {
		t.Fatal("overflow/over-budget object accepted")
	}
}

func TestPublicationReadyLocatorPreservesOriginalObject(t *testing.T) {
	target := PublicationTargetMaterials{Endpoint: "https://objects.example.invalid:9443", Bucket: "original-bucket", Root: "installation/", ReadIdentityHash: hash([]byte("read identity DATA"))}
	object := ArtifactReadObject{Key: "installation/task/1/manifest.json", Version: "original+version/1=", SHA256: hash([]byte("manifest DATA")), Size: 512}
	locator, err := publicationTerminalLocator(target, object)
	if err != nil || locator.URI != "https://objects.example.invalid:9443/original-bucket/installation/task/1/manifest.json" || locator.Version != object.Version || locator.SHA256 != object.SHA256 || locator.Size != object.Size {
		t.Fatal("original immutable locator changed", err)
	}
	for _, mode := range []string{"credential", "query", "foreign-root", "latest", "unicode-version", "long-uri"} {
		t.Run(mode, func(t *testing.T) {
			p, q := target, object
			switch mode {
			case "credential":
				p.Endpoint = "https://user:secret@objects.example.invalid"
			case "query":
				p.Endpoint += "?temporary=credential"
			case "foreign-root":
				q.Key = "other/task/manifest.json"
			case "latest":
				q.Version = "latest"
			case "unicode-version":
				q.Version = "版本"
			case "long-uri":
				p.Endpoint = "https://" + strings.Repeat("a", 2050) + ".invalid"
			}
			if _, err := publicationTerminalLocator(p, q); err == nil {
				t.Fatal("invalid terminal locator accepted", mode)
			}
		})
	}
}

func TestPublicationReadyFactsRejectUnboundDecision(t *testing.T) {
	for _, decision := range []*publicationDecisionEvidence{nil, {}, {registered: &publicationRegisteredObject{}}} {
		if _, err := originalPublicationTerminalFacts(decision, time.Now().UTC().Truncate(time.Microsecond)); err == nil {
			t.Fatal("unbound decision manufactured terminal facts")
		}
	}
	if err := recheckPublicationTerminalProjectionTx(context.Background(), nil, publicationTerminalFacts{}); err == nil {
		t.Fatal("projection check admitted no original tx")
	}
}

func TestPublicationReadyRejectsUnissuedHandles(t *testing.T) {
	for _, ready := range []*publicationTerminalReady{nil, {}, {sha256: hash([]byte("caller DTO"))}, {decision: &publicationDecisionEvidence{}, sha256: hash([]byte("caller DTO"))}} {
		if err := ready.recheckTx(context.Background(), nil); err == nil {
			t.Fatal("unissued handle admitted a terminal mutation")
		}
	}
	var service *DeploymentService
	if ready, err := service.completeOriginalPublicationReady(context.Background(), &publicationDecisionEvidence{}); err == nil || ready != nil {
		t.Fatal("unbound decision minted Ready")
	}
	for _, proof := range []*publicationFinalVerification{nil, {}, {sourceRecovery: &c.PublisherSourceRecovery{}}} {
		if _, err := publicationSourceRecoveryFacts(proof, &c.PublisherSourceRecovery{}); err == nil {
			t.Fatal("zero physical proof accepted")
		}
		if err := proof.openSourceRecovery(context.Background()); err == nil {
			t.Fatal("unbound proof opened a physical source handle")
		}
	}
}
