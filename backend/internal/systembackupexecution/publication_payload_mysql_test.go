package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

func aRefreshPublicationPayloadCapacity(t *testing.T, x *aPublisherVerifierFixture) {
	t.Helper()
	h := x.history
	g := h.service.Forward.DeploymentBinding()
	var now time.Time
	if h.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("original capacity clock")
	}
	body, _ := json.Marshal(security.CapacityReport{ServerUUID: g.ServerUUID, Database: g.Database, ObservedAt: now, AvailableBytes: 4 << 30})
	if os.WriteFile(h.service.Config.CapacityFile, body, 0600) != nil {
		t.Fatal("named physical-capacity boundary sample")
	}
}

func TestAOriginalBinaryUnknownFreshProcessClaimObservesOnlyFrozenIntent(t *testing.T) {
	for _, status := range []string{"validating", "publishing", "finalization_unknown", "expired-old-intent"} {
		t.Run(status, func(t *testing.T) {
			x, store, state := newAOriginalPublicationService(t)
			h, ctx := x.history, context.Background()
			h.service.staging = h.owner.Staging
			part, err := h.service.openPublicationCaptureFiles(ctx, h.token, h.original.AttemptNo, "workspace")
			if err != nil {
				t.Fatal(err)
			}
			invSHA, _ := part.record.Invocation.Hash()
			path, envelopePath := publicationPartPaths("workspace", part.record.Invocation.Request.Binding.PartIndex, invSHA)
			state.lostACK, state.getUnavailable = true, true
			aRefreshPublicationPayloadCapacity(t, x)
			operationCtx := ctx
			cancelOperation := func() {}
			if status == "expired-old-intent" {
				operationCtx, cancelOperation = context.WithTimeout(ctx, 4*time.Second)
			}
			_, err = h.service.publishOriginalPayload(operationCtx, h.token, h.original.AttemptNo, store, part, path, false)
			cancelOperation()
			if err == nil || state.puts != 1 {
				t.Fatal("unknown PUT/GET incorrectly resolved", err, state.puts)
			}
			part.Close()
			var initial []byte
			id := (publicationPayloadIntent{Installation: h.original.InstallationID, Backup: h.original.TaskPublicID, Attempt: h.original.AttemptNo, Path: path}).id()
			if h.db.QueryRow(`SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&initial) != nil {
				t.Fatal("original binary intent unavailable")
			}
			var frozen publicationPayloadIntent
			if decodeProviderDeploymentJSON(initial, &frozen) != nil {
				t.Fatal("invalid frozen binary intent")
			}
			if status == "publishing" || status == "finalization_unknown" {
				access, err := h.service.publicationAccess(ctx, h.token, h.original.AttemptNo)
				if err != nil {
					t.Fatal(err)
				}
				aRefreshPublicationPayloadCapacity(t, x)
				action, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/" + strconv.FormatUint(h.original.AttemptNo, 10) + "/manifest.json", Payload: []byte(`{"named_fixture":"crash_before_manifest_send"}`), Deadline: access.ValidUntil().Add(-time.Second)})
				if err != nil || !send {
					t.Fatal("original phase transition", err)
				}
				if status == "finalization_unknown" {
					if err = h.service.recordPublicationObservation(ctx, h.token, h.original.AttemptNo, action, nativePublicationObject{}, errPublicationUnavailable); err != errPublicationUnavailable {
						t.Fatal("original unknown transition", err)
					}
				}
			}
			version, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
			time.Sleep(1100 * time.Millisecond)
			if status == "expired-old-intent" {
				timer := time.NewTimer(time.Until(frozen.Deadline.Add(100 * time.Millisecond)))
				<-timer.C
				if !time.Now().After(frozen.Deadline) {
					t.Fatal("old upload deadline did not expire")
				}
			}
			fresh, err := (c.SQLTaskClaimStore{DB: h.db, InstallationID: h.original.InstallationID}).AcquireWithReceipt(ctx, h.token.Target, h.token.Owner, version, policy)
			if err != nil {
				t.Fatal("fresh original claim receipt", err)
			}
			h.token = fresh
			// Reconstruct actual factory/transport and reopen original private FDs.
			// No sent state or old verifier survives this process-boundary model.
			if err = h.service.attachPublisherVerifier(ctx, h.db, h.owner.Client, h.owner.Gate.Records); err != nil {
				t.Fatal(err)
			}
			restarted, err := h.service.publicationStore(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			part, err = h.service.openPublicationCaptureFiles(ctx, h.token, h.original.AttemptNo, "workspace")
			if err != nil {
				t.Fatal(err)
			}
			defer part.Close()
			state.lostACK, state.getUnavailable = false, false
			aRefreshPublicationPayloadCapacity(t, x)
			object, err := h.service.publishOriginalPayload(ctx, h.token, h.original.AttemptNo, restarted, part, path, false)
			if err != nil || state.puts != 1 || object.Version != "original-v1" {
				t.Fatal("fresh process/claim resent original binary", err, state.puts)
			}
			var current []byte
			if h.db.QueryRow(`SELECT inline_payload FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&current) != nil || !bytes.Equal(initial, current) {
				t.Fatal("fresh claim extended/replaced frozen upload intent")
			}
			if status == "publishing" || status == "finalization_unknown" {
				if _, err = h.service.publishOriginalPayload(ctx, h.token, h.original.AttemptNo, restarted, part, envelopePath, true); err == nil || state.puts != 1 {
					t.Fatal("later phase introduced a new binary send", err, state.puts)
				}
			}
			state.mu.Lock()
			corrupt := bytes.Clone(state.objects["/"+store.config.Bucket+"/"+object.Key])
			corrupt[len(corrupt)-1] ^= 1
			state.objects["/"+store.config.Bucket+"/"+object.Key] = corrupt
			state.mu.Unlock()
			if _, err = h.service.publishOriginalPayload(ctx, h.token, h.original.AttemptNo, restarted, part, path, false); err == nil || state.puts != 1 {
				t.Fatal("changed bytes passed fixed-version full GET or retried PUT", err, state.puts)
			}
		})
	}
}

// One original portable-workspace part, not a complete six-part artifact or a
// terminal/eligibility test. Runtime stop/resume remain named local fixtures.
func TestAOriginalPublicationBinaryIntentSingleSendAndPinnedIndependentReadback(t *testing.T) {
	for _, mode := range []string{"confirmed", "lost-put-ack", "intent-already-sent-absent", "wrong-immutable-version", "claim-release-during-get", "read-credential-withdrawn-during-get"} {
		t.Run(mode, func(t *testing.T) {
			x, store, state := newAOriginalPublicationService(t)
			h, ctx := x.history, context.Background()
			h.service.staging = h.owner.Staging
			part, err := h.service.openPublicationCaptureFiles(ctx, h.token, h.original.AttemptNo, "workspace")
			if err != nil {
				t.Fatal(err)
			}
			defer part.Close()
			refresh := func() {
				g := h.service.Forward.DeploymentBinding()
				var now time.Time
				if h.db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
					t.Fatal("original capacity clock")
				}
				body, _ := json.Marshal(security.CapacityReport{ServerUUID: g.ServerUUID, Database: g.Database, ObservedAt: now, AvailableBytes: 4 << 30})
				if os.WriteFile(h.service.Config.CapacityFile, body, 0600) != nil {
					t.Fatal("named capacity boundary sample")
				}
			}
			invSHA, _ := part.record.Invocation.Hash()
			path, _ := publicationPartPaths("workspace", part.record.Invocation.Request.Binding.PartIndex, invSHA)
			if mode == "intent-already-sent-absent" {
				refresh()
				_, send, err := h.service.beginPublicationPayload(ctx, h.token, h.original.AttemptNo, store.config, publicationPayloadIntent{Version: "system-backup-original-binary-upload.v1", Installation: h.original.InstallationID, Backup: h.original.TaskPublicID, Attempt: h.original.AttemptNo, Part: "workspace", InvocationSHA256: invSHA, Path: path, Key: store.config.Root + h.original.TaskPublicID + "/" + strconv.FormatUint(h.original.AttemptNo, 10) + "/" + path, SHA256: h.candidate.Ciphertext.SHA256, Size: h.candidate.Ciphertext.Size})
				if err != nil || !send {
					t.Fatal("original first intent", err)
				}
			}
			state.lostACK = mode == "lost-put-ack"
			if mode == "claim-release-during-get" {
				state.onGet = func() {
					if _, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(ctx, h.token, time.Second); err != nil {
						t.Error("original claim withdrawal", err)
					}
				}
			}
			if mode == "read-credential-withdrawn-during-get" {
				state.onGet = func() {
					if os.WriteFile(store.config.ReadCredentialFile, []byte("independent read credential withdrawn"), 0600) != nil {
						t.Error("owned reader projection withdrawal")
					}
				}
			}
			refresh()
			first, err := h.service.publishOriginalPayload(ctx, h.token, h.original.AttemptNo, store, part, path, false)
			if mode == "intent-already-sent-absent" || mode == "claim-release-during-get" || mode == "read-credential-withdrawn-during-get" {
				if err == nil || mode == "intent-already-sent-absent" && state.puts != 0 {
					t.Fatal("unknown intent replayed or lost claim accepted", err, state.puts)
				}
				return
			}
			if err != nil || first.Version != "original-v1" || first.SHA256 != h.candidate.Ciphertext.SHA256 || first.Size != h.candidate.Ciphertext.Size || state.puts != 1 {
				t.Fatal("actual binary original upload/readback", err, state.puts)
			}
			if mode == "wrong-immutable-version" {
				state.wrongVersion = true
			}
			refresh()
			second, err := h.service.publishOriginalPayload(ctx, h.token, h.original.AttemptNo, store, part, path, false)
			if mode == "wrong-immutable-version" {
				if err == nil || state.puts != 1 {
					t.Fatal("immutable version changed or sent again", err, state.puts)
				}
				return
			}
			// The fresh independent read carries a fresh opaque receipt pointer;
			// every observed coordinate AND the full receipt contents must match.
			firstRead, secondRead := first.payloadRead, second.payloadRead
			first.payloadRead, second.payloadRead = nil, nil
			if err != nil || second != first || firstRead == nil || secondRead == nil || *firstRead != *secondRead || state.puts != 1 {
				t.Fatal("original intent resent or pinned readback changed", err, state.puts)
			}
			var actions int
			if h.db.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_type='backup' AND target_public_id=?`, h.original.TaskPublicID).Scan(&actions) != nil || actions != 0 {
				t.Fatal("binary bytes entered original JSON action journal")
			}
		})
	}
}
