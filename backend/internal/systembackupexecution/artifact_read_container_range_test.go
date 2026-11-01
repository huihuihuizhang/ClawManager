package systembackupexecution

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	w "clawreef/internal/systembackupwire"
)

func TestArtifactContainerRangeBoundsFailBeforeNativeIO(t *testing.T) {
	for _, mode := range []string{"offset-overflow", "overlap", "unfixed-version", "foreign-key"} {
		t.Run(mode, func(t *testing.T) {
			store, state := newANativePublicationStore(t, time.Minute)
			reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(store.config), ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			scope, _, _, facts := artifactContainerReadData(t, store.config.InstallationID)
			member, location := facts.Header.Members[0], facts.Locations[0]
			location.ObjectVersion = "original-v1"
			object := ArtifactReadObject{Key: store.config.Root + scope.Backup + "/1/parts/workspace/container.enc", Version: "original-v1", Size: facts.Size, SHA256: facts.SHA256}
			switch mode {
			case "offset-overflow":
				location.CipherOffset = 1<<63 - 1
			case "overlap":
				location.EnvelopeOffset = location.CipherOffset
			case "unfixed-version":
				location.ObjectVersion, object.Version = "latest", "latest"
			case "foreign-key":
				object.Key = store.config.Root + "foreign/container.enc"
			}
			requests := 0
			state.onRead = func(http.ResponseWriter, *http.Request) bool { requests++; return false }
			if raw, err := reader.ReadContainerEnvelope(context.Background(), object, member, location, time.Now().Add(time.Second)); err == nil || len(raw) != 0 || requests != 0 {
				t.Fatal("invalid member range reached native I/O", mode, err, requests)
			}
		})
	}
}

// Named LOCAL DATA key, not a provider or original SQL/claim authority.
type artifactContainerDataUnwrapper struct {
	request w.KeyRequest
	calls   int
	revoked bool
}

func (k *artifactContainerDataUnwrapper) Unwrap(ctx context.Context, request w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	k.calls++
	if ctx.Err() != nil || request != k.request || wrapped.Request != request || use == nil {
		return errors.New("named local DATA key binding mismatch")
	}
	key := bytes.Repeat([]byte{3}, 32)
	defer clear(key)
	if err := use(key); err != nil {
		return err
	}
	if k.revoked {
		return errors.New("named local DATA post-use revocation")
	}
	return nil
}

func TestArtifactReadOnlyContainerMemberRangesAuthenticateCompleteC(t *testing.T) {
	for _, mode := range []string{"healthy", "cipher-corrupt-after-inspect", "envelope-corrupt", "wrong-content-range", "range-ignored", "wrong-total", "wrong-version", "short-envelope", "short-cipher", "post-use-revoked", "unread-domain-suffix", "domain-failure", "credential-withdrawn", "caller-envelope-mutation"} {
		t.Run(mode, func(t *testing.T) {
			store, state := newANativePublicationStore(t, time.Minute)
			if err := os.Remove(store.config.WriteCredentialFile); err != nil {
				t.Fatal(err)
			}
			reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(store.config), ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			scope, checkpoints, raw, original := artifactContainerReadData(t, store.config.InstallationID)
			key := store.config.Root + scope.Backup + "/1/parts/workspace/container.enc"
			object := ArtifactReadObject{Key: key, Version: "original-v1", SHA256: original.SHA256, Size: original.Size}
			state.objects["/"+store.config.Bucket+"/"+key] = raw
			until := time.Now().Add(5 * time.Second)
			facts, err := reader.InspectPartContainer(context.Background(), object, scope, checkpoints, until)
			if err != nil {
				t.Fatal(err)
			}
			member, location := facts.Header.Members[0], facts.Locations[0]
			keys := &artifactContainerDataUnwrapper{request: member.Stream.Request, revoked: mode == "post-use-revoked"}
			if mode == "cipher-corrupt-after-inspect" {
				raw[location.CipherOffset+20] ^= 1
			}
			if mode == "envelope-corrupt" {
				raw[location.EnvelopeOffset+20] ^= 1
			}
			ranges := 0
			var callerEnvelope []byte
			state.onRead = func(dst http.ResponseWriter, request *http.Request) bool {
				value := request.Header.Get("Range")
				if value == "" {
					return false
				}
				ranges++
				bounds, ok := strings.CutPrefix(value, "bytes=")
				left, right, cut := strings.Cut(bounds, "-")
				start, e1 := strconv.ParseInt(left, 10, 64)
				end, e2 := strconv.ParseInt(right, 10, 64)
				auth := request.Header.Get("Authorization")
				_, signed, signedOK := strings.Cut(auth, "SignedHeaders=")
				signed, _, _ = strings.Cut(signed, ",")
				if !ok || !cut || e1 != nil || e2 != nil || start < 0 || end < start || end >= int64(len(raw)) || request.Method != "GET" || request.URL.Query().Get("versionId") != "original-v1" || !signedOK || !strings.Contains(";"+signed+";", ";range;") {
					t.Error("range/version was not bound to the signed native GET")
					http.Error(dst, "denied", 403)
					return true
				}
				cipher := start == location.CipherOffset
				if mode == "caller-envelope-mutation" && cipher {
					callerEnvelope[0] ^= 1
				}
				if mode == "credential-withdrawn" && cipher {
					if err := os.Remove(store.config.ReadCredentialFile); err != nil {
						t.Error(err)
					}
				}
				total, returnedEnd, version := int64(len(raw)), end, "original-v1"
				if mode == "wrong-total" {
					total++
				}
				if mode == "wrong-content-range" {
					returnedEnd++
				}
				if mode == "wrong-version" {
					version = "substitute-v2"
				}
				dst.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
				dst.Header().Set("Content-Range", "bytes "+left+"-"+strconv.FormatInt(returnedEnd, 10)+"/"+strconv.FormatInt(total, 10))
				dst.Header().Set("x-amz-version-id", version)
				status := 206
				if mode == "range-ignored" {
					status = 200
				}
				dst.WriteHeader(status)
				body := raw[start : end+1]
				if mode == "short-envelope" && !cipher || mode == "short-cipher" && cipher {
					body = body[:len(body)-1]
				}
				_, _ = dst.Write(body)
				return true
			}
			callerEnvelope, err = reader.ReadContainerEnvelope(context.Background(), object, member, location, until)
			if err != nil {
				if mode == "envelope-corrupt" || mode == "wrong-content-range" || mode == "range-ignored" || mode == "wrong-total" || mode == "wrong-version" || mode == "short-envelope" {
					if keys.calls != 0 || len(callerEnvelope) != 0 || ranges != 1 || state.puts != 0 {
						t.Fatal("invalid envelope reached Unwrap or returned bytes")
					}
					return
				}
				t.Fatal(err)
			}
			defer clear(callerEnvelope)
			inspect := func(plain io.Reader) error {
				if mode == "unread-domain-suffix" {
					return nil
				}
				body, err := io.ReadAll(io.LimitReader(plain, w.ChunkSize+1))
				defer clear(body)
				if err != nil || !bytes.Equal(body, bytes.Repeat([]byte("nonempty local codec DATA"), 100)) {
					return errors.New("named plaintext DATA mismatch")
				}
				if mode == "domain-failure" {
					return errors.New("named inert domain DATA rejection")
				}
				return nil
			}
			verified, err := reader.InspectContainerCipher(context.Background(), object, member, location, callerEnvelope, keys, inspect, until)
			if mode == "healthy" || mode == "caller-envelope-mutation" {
				if err != nil || verified.CiphertextSHA256() != member.CipherSHA256 || verified.CiphertextBytes() != member.CipherBytes || verified.PlaintextBytes() == 0 || keys.calls != 1 || ranges != 2 || state.gets != 1 || state.puts != 0 {
					t.Fatal("complete fixed-version C inspection", err, keys.calls, ranges)
				}
			} else if err == nil || verified.CiphertextSHA256() != "" {
				t.Fatal("invalid member returned C verification", mode, err)
			}
		})
	}
}
