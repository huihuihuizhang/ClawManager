package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

type publicationCapacityRoundTrip func(*http.Request) (*http.Response, error)

func TestPublicationBudgetRequiresExactOriginalSnapshot(t *testing.T) {
	valid := []byte(`{"capacity":{"max_artifact_bytes":17179869184,"max_index_bytes":536870912},"source":"protocol DATA"}`)
	limits, err := artifactLimitsFromConfigSnapshot(valid, hash(valid))
	if err != nil || limits != (ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20}) {
		t.Fatal(limits, err)
	}
	for _, raw := range []string{`{"source":"missing capacity"}`, `{"capacity":{"max_artifact_bytes":"17179869184","max_index_bytes":536870912}}`, `{"capacity":{"max_artifact_bytes":17179869184}}`, `{"capacity":{"max_artifact_bytes":17179869184.5,"max_index_bytes":536870912}}`, `{"capacity":{"max_artifact_bytes":17179869184,"max_index_bytes":536870912},"capacity":{}}`, `{ "capacity":{"max_artifact_bytes":17179869184,"max_index_bytes":536870912}}`, `{"capacity":{"max_artifact_bytes":966367641601,"max_index_bytes":536870912}}`} {
		if got, err := artifactLimitsFromConfigSnapshot([]byte(raw), hash([]byte(raw))); !errors.Is(err, ErrPublicationConfigBudgetMismatch) || got != (ArtifactReadLimits{}) {
			t.Fatal("unauthenticated/invalid original budget accepted", raw, got, err)
		}
	}
	if _, err := artifactLimitsFromConfigSnapshot(valid, hash([]byte("foreign original"))); !errors.Is(err, ErrPublicationConfigBudgetMismatch) {
		t.Fatal("snapshot hash mismatch accepted", err)
	}
}

func (f publicationCapacityRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNativePublicationCapacityCeilingAndTightenedBudget(t *testing.T) {
	store, state := newANativePublicationStore(t, time.Minute)
	key := store.config.Root + "capacity/original.enc"
	var size int64 = 9 << 30
	state.onRead = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("x-amz-version-id", "original-v1")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		return true
	}
	until := time.Now().Add(20 * time.Second)
	for _, current := range []int64{9 << 30, MaxPublicationArtifactBytes, MaxPublicationArtifactBytes + 1} {
		size = current
		object, err := store.stat(context.Background(), key, "original-v1", until)
		if current <= MaxPublicationArtifactBytes {
			if err != nil || object.Size != current {
				t.Fatal("legal native HEAD size rejected", current, object, err)
			}
		} else if err == nil {
			t.Fatal("over-contract native HEAD accepted")
		}
	}
	limited, err := store.withObjectLimit(16 << 30)
	if err != nil {
		t.Fatal(err)
	}
	if store.maxObjectBytes != MaxPublicationArtifactBytes {
		t.Fatal("request budget mutated shared transport")
	}
	wider, err := limited.withObjectLimit(32 << 30)
	if err != nil || wider.maxObjectBytes != 16<<30 {
		t.Fatal("transport budget widened", err)
	}
	size = 17 << 30
	if _, err := limited.stat(context.Background(), key, "original-v1", until); err == nil {
		t.Fatal("HEAD exceeded actual config object budget")
	}
	// Named HTTP boundary model only: no multi-GiB body is allocated or sent.
	// It proves PUT validation uses int64/config capacity before transport.
	requests := 0
	limited.client = &http.Client{Transport: publicationCapacityRoundTrip(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != "PUT" || r.ContentLength != 9<<30 {
			t.Error("wrong bounded PUT metadata")
		}
		return &http.Response{StatusCode: 503, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})}
	if _, err := limited.create(context.Background(), key, bytes.NewReader(nil), 9<<30, hash([]byte("size protocol DATA")), until); err == nil || requests != 1 {
		t.Fatal("legal >8GiB PUT did not reach bounded transport", err, requests)
	}
	if _, err := limited.create(context.Background(), key, bytes.NewReader(nil), 17<<30, hash([]byte("size protocol DATA")), until); err == nil || requests != 1 {
		t.Fatal("over-config PUT reached transport", err, requests)
	}
}

func TestArtifactReadCapacityStillRequiresFullEOF(t *testing.T) {
	store, state := newANativePublicationStore(t, time.Minute)
	material := artifactReadMaterials(store.config)
	limits := ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20}
	reader, err := NewArtifactReadOnlyS3(material, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	key := material.Root + "capacity/original.enc"
	const size int64 = 9 << 30
	lists, heads, gets := 0, 0, 0
	state.onRead = func(w http.ResponseWriter, r *http.Request) bool {
		if _, ok := r.URL.Query()["versions"]; ok {
			lists++
			page := artifactVersionPage{XMLName: xml.Name{Local: "ListVersionsResult"}, Name: material.Bucket, Prefix: key, Versions: []artifactNativeVersion{{Key: key, Version: "original-v1", Size: size, Modified: time.Now().UTC()}}}
			if err := xml.NewEncoder(w).Encode(page); err != nil {
				t.Error(err)
			}
			return true
		}
		w.Header().Set("x-amz-version-id", "original-v1")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		if r.Method == "HEAD" {
			heads++
		} else {
			gets++
			w.Write([]byte("short"))
		}
		return true
	}
	budget := ArtifactVersionSearchBudget{MaxVersions: 2, MaxPages: 1, MaxReadBytes: size}
	if object, err := reader.ResolveIndexedObject(context.Background(), key, hash([]byte("short")), size, budget, time.Now().Add(10*time.Second)); err == nil || object != (ArtifactReadObject{}) || lists != 1 || heads != 1 || gets != 1 {
		t.Fatal("legal metadata did not reach mandatory full EOF check", object, err, lists, heads, gets)
	}
	small, err := NewArtifactReadOnlyS3(material, ArtifactReadLimits{MaxArtifactBytes: 1 << 20, MaxIndexBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	before := lists + heads + gets
	if _, err := small.ResolveIndexedObject(context.Background(), key, hash([]byte("short")), size, budget, time.Now().Add(time.Second)); err == nil || lists+heads+gets != before {
		t.Fatal("actual smaller config was bypassed", err)
	}
	if _, err := reader.ResolveHashedObject(context.Background(), key, hash([]byte("short")), limits.MaxIndexBytes+1, budget, time.Now().Add(time.Second)); err == nil || lists+heads+gets != before {
		t.Fatal("actual index budget was bypassed", err)
	}
	for _, invalid := range []ArtifactReadLimits{{}, {MaxArtifactBytes: MaxPublicationArtifactBytes + 1, MaxIndexBytes: 1 << 20}, {MaxArtifactBytes: 1 << 20, MaxIndexBytes: MaxPublicationIndexBytes + 1}} {
		if r, err := NewArtifactReadOnlyS3(material, invalid); err == nil {
			r.Close()
			t.Fatal("invalid/missing capacity config accepted", invalid)
		}
	}
}
