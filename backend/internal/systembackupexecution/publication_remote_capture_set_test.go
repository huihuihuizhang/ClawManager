package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

// Closed transport/index DATA; no signature, native read, C or task proof.
func remoteCaptureSetData(t *testing.T) (publicationArtifactIndex, map[string]ArtifactReadObject) {
	t.Helper()
	index := publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: "sbk_closed_set_DATA", Attempt: 1, CaptureContext: hash([]byte("original context DATA"))}
	objects := map[string]ArtifactReadObject{}
	add := func(path, role, framing string) {
		object := ArtifactReadObject{Key: "installation_closed/" + index.Backup + "/1/" + path, Version: "fixed-native-version-DATA", Size: 10, SHA256: hash([]byte(path))}
		objects[path] = object
		index.Entries = append(index.Entries, publicationArtifactEntry{Path: path, Role: role, Framing: framing, Size: object.Size, SHA256: object.SHA256})
	}
	for _, part := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		add("parts/"+part+"/container.enc", "encrypted_payload", pc.Version)
	}
	for _, name := range []string{"evidence", "evidence-proofs", "capture-description"} {
		add("control/"+name+".json.enc", "control_evidence", w.FramingVersion)
		add("control/"+name+".envelope.json", "envelope", w.EnvelopeVersion)
	}
	add("control/capture-bootstrap.json", "control_evidence", "system-backup-capture-bootstrap.v1")
	sort.Slice(index.Entries, func(i, j int) bool { return index.Entries[i].Path < index.Entries[j].Path })
	objects["control/capture-certificate.json"] = ArtifactReadObject{Key: "installation_closed/" + index.Backup + "/1/control/capture-certificate.json", Version: "fixed-certificate-DATA", Size: 10, SHA256: hash([]byte("certificate DATA"))}
	return index, objects
}

// Actual loopback TLS fixed-version reads of opaque transport DATA. These
// bodies deliberately are not valid certificate/bootstrap/C domain records.
func TestRemoteCaptureSetReadsAllFifteenNativeBodies(t *testing.T) {
	paths := []string{"artifact-index.json", "control/capture-certificate.json", "control/capture-bootstrap.json", "control/capture-description.json.enc", "control/capture-description.envelope.json", "control/evidence.json.enc", "control/evidence.envelope.json", "control/evidence-proofs.json.enc", "control/evidence-proofs.envelope.json"}
	for _, part := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
		paths = append(paths, "parts/"+part+"/container.enc")
	}
	modes := []string{"healthy", "safe-original-root", "wrong-version", "short-body", "withdrawn-read-credential", "deadline-during-body", "changed-selected-index", "wider-reader-budget"}
	for _, path := range paths {
		modes = append(modes, "corrupt/"+path)
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			store, state := newANativePublicationStore(t, time.Minute)
			if mode == "safe-original-root" {
				store.config.Root = "tenant/original-signed-scope/"
			}
			if err := os.Remove(store.config.WriteCredentialFile); err != nil {
				t.Fatal(err)
			}
			index, _ := remoteCaptureSetData(t)
			limits := ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20}
			base := store.config.Root + index.Backup + "/1/"
			objects := map[string]ArtifactReadObject{}
			add := func(path string, raw []byte) {
				objects[path] = ArtifactReadObject{Key: base + path, Version: "original-v1", SHA256: hash(raw), Size: int64(len(raw))}
				state.objects["/"+store.config.Bucket+"/"+base+path] = bytes.Clone(raw)
			}
			for i := range index.Entries {
				entry := &index.Entries[i]
				raw := []byte("named opaque native transport DATA:" + entry.Path)
				entry.SHA256, entry.Size = hash(raw), int64(len(raw))
				add(entry.Path, raw)
			}
			add("control/capture-certificate.json", []byte("opaque certificate transport DATA"))
			raw, err := ce.Canonical(index)
			if err != nil {
				t.Fatal(err)
			}
			add("artifact-index.json", raw)
			set, err := selectPublicationRemoteCaptureSet(store.config.InstallationID, index.Backup, 1, store.config.Root, index.CaptureContext, raw, hash(raw), objects, limits)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(store.config), limits)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			until := time.Now().Add(10 * time.Second)
			switch mode {
			case "wrong-version":
				state.wrongVersion = true
			case "short-body":
				state.onRead = func(out http.ResponseWriter, request *http.Request) bool {
					if request.Method != "GET" {
						return false
					}
					body := state.objects[request.URL.Path]
					out.Header().Set("x-amz-version-id", "original-v1")
					out.Header().Set("Content-Length", strconv.Itoa(len(body)))
					out.WriteHeader(200)
					_, _ = out.Write(body[:len(body)-1])
					return true
				}
			case "withdrawn-read-credential":
				state.onGet = func() {
					if err := os.Remove(store.config.ReadCredentialFile); err != nil {
						t.Error(err)
					}
				}
			case "deadline-during-body":
				state.delay = time.Second
				until = time.Now().Add(200 * time.Millisecond)
			case "changed-selected-index":
				set.index[0] ^= 1
			case "wider-reader-budget":
				reader.limits.MaxArtifactBytes *= 2
			default:
				if path, ok := strings.CutPrefix(mode, "corrupt/"); ok {
					body := state.objects["/"+store.config.Bucket+"/"+base+path]
					body[len(body)-1] ^= 1
				}
			}
			err = reader.inspectPublicationRemoteCaptureSetBytes(context.Background(), set, until)
			if mode == "healthy" || mode == "safe-original-root" {
				if err != nil || state.heads != 15 || state.gets != 15 {
					t.Fatal("all fixed native bodies required", err, state.heads, state.gets)
				}
			} else if err == nil {
				t.Fatal("changed or incomplete native bytes accepted", mode)
			}
			if (mode == "changed-selected-index" || mode == "wider-reader-budget") && state.heads+state.gets != 0 {
				t.Fatal("rebound selection issued native reads")
			}
			if state.puts != 0 {
				t.Fatal("read-only verification wrote artifacts")
			}
		})
	}
}

func TestRemoteCaptureSetRequiresExactNewFifteenObjects(t *testing.T) {
	for _, mode := range []string{"healthy", "old-ten-entry-index", "missing-description", "extra-object", "wrong-bootstrap-role", "wrong-bootstrap-framing", "unknown-entry", "duplicate-entry", "foreign-context", "foreign-attempt", "foreign-key", "mutable-version", "entry-checksum", "entry-size", "budget", "noncanonical"} {
		t.Run(mode, func(t *testing.T) {
			index, objects := remoteCaptureSetData(t)
			context := index.CaptureContext
			limits := ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20}
			switch mode {
			case "old-ten-entry-index":
				index.Entries = index.Entries[:10]
			case "missing-description":
				delete(objects, "control/capture-description.json.enc")
			case "extra-object":
				objects["foreign.json"] = ArtifactReadObject{Key: "installation_closed/" + index.Backup + "/1/foreign.json", Version: "fixed-DATA", SHA256: hash([]byte("foreign DATA")), Size: 1}
			case "wrong-bootstrap-role", "wrong-bootstrap-framing":
				for i := range index.Entries {
					if index.Entries[i].Path == "control/capture-bootstrap.json" {
						if mode == "wrong-bootstrap-role" {
							index.Entries[i].Role = "envelope"
						} else {
							index.Entries[i].Framing = w.FramingVersion
						}
					}
				}
			case "unknown-entry":
				index.Entries[0].Path = "control/unknown.enc"
			case "duplicate-entry":
				index.Entries[1] = index.Entries[0]
			case "foreign-context":
				index.CaptureContext = hash([]byte("foreign context DATA"))
			case "foreign-attempt":
				index.Attempt = 2
			case "foreign-key", "mutable-version", "entry-checksum", "entry-size", "budget":
				object := objects[index.Entries[0].Path]
				switch mode {
				case "foreign-key":
					object.Key = "installation_foreign/foreign/1/" + index.Entries[0].Path
				case "mutable-version":
					object.Version = "latest"
				case "entry-checksum":
					object.SHA256 = hash([]byte("changed object DATA"))
				case "entry-size":
					object.Size++
				case "budget":
					object.Size = limits.MaxArtifactBytes
				}
				objects[index.Entries[0].Path] = object
			}
			raw, err := ce.Canonical(index)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "noncanonical" {
				raw, err = json.MarshalIndent(index, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
			}
			objects["artifact-index.json"] = ArtifactReadObject{Key: "installation_closed/" + index.Backup + "/1/artifact-index.json", Version: "fixed-index-DATA", SHA256: hash(raw), Size: int64(len(raw))}
			set, err := selectPublicationRemoteCaptureSet("installation_closed", index.Backup, 1, "installation_closed/", context, raw, hash(raw), objects, limits)
			if mode == "healthy" {
				if err != nil || set == nil || len(set.objects) != 15 {
					t.Fatal("closed new transport set", err)
				}
				delete(objects, "control/capture-description.json.enc")
				if len(set.objects) != 15 {
					t.Fatal("caller map mutation changed selected content")
				}
			} else if err == nil || set != nil {
				t.Fatal("open/incomplete/foreign input set accepted", mode)
			}
		})
	}
}
