package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type aOriginalRemoteBodyFaultTransport struct {
	http.RoundTripper
	path  string
	fault func()
}

func (t aOriginalRemoteBodyFaultTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.RoundTripper.RoundTrip(request)
	if err == nil && request.Method == "GET" && request.URL.Path == t.path && response.StatusCode == 200 {
		response.Body = &aOriginalRemoteBodyFault{ReadCloser: response.Body, fault: t.fault}
	}
	return response, err
}

type aOriginalRemoteBodyFault struct {
	io.ReadCloser
	fault func()
	once  atomic.Bool
}

func (r *aOriginalRemoteBodyFault) Read(dst []byte) (int, error) {
	n, err := r.ReadCloser.Read(dst)
	if n > 0 && r.once.CompareAndSwap(false, true) {
		r.fault()
	}
	return n, err
}

// One ORIGINAL portable-workspace part, not a complete artifact/acceptance.
// Its real C is uploaded once, then its private local copies are deleted from
// this test-owned temporary root before the independent native C reader runs.
func TestAOriginalRemotePublicationReadbackNeedsNoPrivateCipherFiles(t *testing.T) {
	for _, mode := range []string{"unchanged", "remote-cipher-changed", "remote-envelope-changed", "wrong-native-version", "claim-release-during-remote-body"} {
		t.Run(mode, func(t *testing.T) {
			x, store, state := newAOriginalPublicationService(t)
			h, ctx := x.history, context.Background()
			h.service.staging = h.owner.Staging
			part, err := h.service.openPublicationCaptureFiles(ctx, h.token, h.original.AttemptNo, "workspace")
			if err != nil {
				t.Fatal(err)
			}
			invSHA, _ := part.record.Invocation.Hash()
			cipherPath, envelopePath := publicationPartPaths("workspace", part.record.Invocation.Request.Binding.PartIndex, invSHA)
			expected := publicationVerifiedPart{Part: "workspace", Index: part.record.Invocation.Request.Binding.PartIndex, InvocationSHA256: invSHA, CandidateSHA256: part.record.CandidateSHA256, CipherPath: cipherPath, EnvelopePath: envelopePath, CipherSHA256: part.candidate.Ciphertext.SHA256, EnvelopeSHA256: part.candidate.Envelope.SHA256, CipherBytes: part.candidate.Ciphertext.Size, EnvelopeBytes: part.candidate.Envelope.Size}
			resultRaw, _ := json.Marshal(part.record.PartResult)
			expected.ResultSHA256, expected.Operation = hash(resultRaw), part.record.Invocation.Request.Operation
			private := []string{part.files.Ciphertext.Name(), part.files.Envelope.Name()}
			for _, object := range []struct {
				path     string
				envelope bool
			}{{cipherPath, false}, {envelopePath, true}} {
				aRefreshPublicationPayloadCapacity(t, x)
				if _, err = h.service.publishOriginalPayload(ctx, h.token, h.original.AttemptNo, store, part, object.path, object.envelope); err != nil {
					part.Close()
					t.Fatal("actual original upload", err)
				}
			}
			part.Close()
			for _, name := range private {
				rel, err := filepath.Rel(h.owner.Staging.Name(), name)
				if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
					t.Fatal("private fixture path outside owned staging")
				}
				if err = os.Remove(name); err != nil {
					t.Fatal("remove closed test-owned private copy", err)
				}
			}
			h.service.staging = nil
			if mode == "remote-cipher-changed" || mode == "remote-envelope-changed" {
				path := cipherPath
				if mode == "remote-envelope-changed" {
					path = envelopePath
				}
				key := "/" + store.config.Bucket + "/" + store.config.Root + h.original.TaskPublicID + "/3/" + path
				state.mu.Lock()
				body := state.objects[key]
				body[len(body)-1] ^= 1
				state.objects[key] = body
				state.mu.Unlock()
			}
			state.wrongVersion = mode == "wrong-native-version"
			var faultApplied atomic.Bool
			if mode == "claim-release-during-remote-body" {
				store.client.Transport = aOriginalRemoteBodyFaultTransport{RoundTripper: store.client.Transport, path: "/" + store.config.Bucket + "/" + store.config.Root + h.original.TaskPublicID + "/3/" + cipherPath, fault: func() {
					faultCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					// A genuinely separate actor/connection withdraws the claim.
					// The publisher pool's transaction/IO instrumentation remains
					// enabled and still forbids workload IO across its own locks.
					if _, err := (c.ClaimCoordinator{Executor: h.admin, InstallationID: h.original.InstallationID}).Release(faultCtx, h.token, time.Second); err != nil {
						t.Error("actual Release blocked/failed during remote C body", err)
						return
					}
					var owner sql.NullString
					var rowVersion uint64
					if h.admin.QueryRowContext(faultCtx, `SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&owner, &rowVersion) != nil || owner.Valid || rowVersion <= h.token.RowVersion {
						t.Error("remote read fault did not actually release original SQL claim")
						return
					}
					faultApplied.Store(true)
				}}
			}
			before := x.decrypts.Load()
			plain, err := h.service.readRemotePublicationPart(ctx, h.token, h.original.AttemptNo, store, expected)
			if mode == "unchanged" {
				if err != nil || len(plain) != 0 || x.decrypts.Load() <= before {
					t.Fatal("independent original remote C/domain readback", err)
				}
			} else if err == nil || len(plain) != 0 {
				t.Fatal("changed native artifact accepted", mode)
			}
			if mode == "claim-release-during-remote-body" && !faultApplied.Load() {
				t.Fatal("negative returned without applying its real SQL claim withdrawal")
			}
			if state.puts != 2 {
				t.Fatal("readback retried an original PUT", state.puts)
			}
		})
	}
}
