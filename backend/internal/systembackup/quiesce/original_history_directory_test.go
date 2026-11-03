package quiesce

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// These private opaque fixtures exercise the local reader boundary. They do
// not claim a genuine field Node/CRI/gate or authenticated-client acquisition.
func originalHistoryDirectoryTestProof(t *testing.T, p observedPath, boot string, until time.Time) (*VerifiedNodeObservation, ObservationBinding) {
	t.Helper()
	now := time.Now().UTC()
	b := ObservationBinding{Kind: NodeObservationWholePodColdCut, InstallationID: "original-installation", OperationID: "original-operation", ReservationID: "original-reservation", InventorySHA256: strings.Repeat("a", 64), Namespace: "original", NamespaceUID: "ns-uid", Node: "node", NodeUID: "node-uid", Generation: 9, FenceEpoch: 0, ExpiresAt: now.Add(time.Minute)}
	a := nodeObservationAnchor{Binding: b, BootID: boot, PreparedAt: now.Add(-time.Second), Paths: []observedPath{p}}
	o := NodeObserver{key: []byte(strings.Repeat("k", 32))}
	token, e := o.seal(a)
	if e != nil {
		t.Fatal(e)
	}
	return &VerifiedNodeObservation{response: NodeObservationResponse{Version: "node-observation.v1", Action: "stopped", Anchor: token, RequestSHA256: strings.Repeat("b", 64), Binding: b, BootID: boot, StartedAt: now.Add(-100 * time.Millisecond), FinishedAt: now.Add(-50 * time.Millisecond), ValidUntil: until, TasksChecked: 1, Files: 1}}, b
}

func TestOriginalHistoryDirectoryExactOriginalPhaseAndPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	proof, b := originalHistoryDirectoryTestProof(t, observedPath{Path: "/original/history", Device: 1, Inode: 2, Mount: "original-mount"}, "boot", time.Now().Add(2*time.Second))
	p, until, err := originalHistoryDirectoryPath(ctx, proof, b, "boot", "/original/history")
	deadline, _ := ctx.Deadline()
	if err != nil || p.Inode != 2 || !until.Equal(deadline) {
		t.Fatal("original exact path/cap refused", err)
	}
	for _, requested := range []string{"/original", "/original/history/subdirectory", "/original/history/../history", "/new-empty", "/"} {
		if _, _, err := originalHistoryDirectoryPath(ctx, proof, b, "boot", requested); err == nil {
			t.Fatal("nonexact root accepted", requested)
		}
	}
	if _, _, err := originalHistoryDirectoryPath(context.Background(), proof, b, "boot", "/original/history"); err == nil {
		t.Fatal("unbounded context accepted")
	}
}

func TestOriginalHistoryDirectoryRejectsForeignRecoveryAndMalformedScope(t *testing.T) {
	cases := []struct {
		name   string
		change func(*VerifiedNodeObservation, *ObservationBinding)
	}{
		{"prepare", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.Action = "prepare" }},
		{"recovery-stopped", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.Action = "recovery-stopped" }},
		{"recovery-source-stopped", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.Action = "recovery-source-stopped" }},
		{"recovery-reconciled", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.Action = "recovery-reconciled" }},
		{"recovered", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.Action = "recovered" }},
		{"expired-original", func(v *VerifiedNodeObservation, _ *ObservationBinding) {
			v.response.ValidUntil = time.Now().Add(-time.Second)
		}},
		{"expired-binding", func(_ *VerifiedNodeObservation, b *ObservationBinding) { b.ExpiresAt = time.Now().Add(-time.Second) }},
		{"foreign-generation", func(_ *VerifiedNodeObservation, b *ObservationBinding) { b.Generation++ }},
		{"foreign-operation", func(_ *VerifiedNodeObservation, b *ObservationBinding) { b.OperationID = "different" }},
		{"foreign-node", func(_ *VerifiedNodeObservation, b *ObservationBinding) { b.NodeUID = "different" }},
		{"missing-request-proof", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.RequestSHA256 = "" }},
		{"invalid-token", func(v *VerifiedNodeObservation, _ *ObservationBinding) { v.response.Anchor = "untrusted" }},
		{"unknown-anchor-format", func(v *VerifiedNodeObservation, _ *ObservationBinding) {
			parts := strings.Split(v.response.Anchor, ".")
			raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
			raw = append([]byte(`{"Unknown":1,`), raw[1:]...)
			v.response.Anchor = base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1]
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			v, b := originalHistoryDirectoryTestProof(t, observedPath{Path: "/original", Device: 1, Inode: 2, Mount: "mount"}, "boot", time.Now().Add(time.Second))
			c.change(v, &b)
			if _, _, err := originalHistoryDirectoryPath(ctx, v, b, "boot", "/original"); err == nil {
				t.Fatal("invalid original scope accepted")
			}
		})
	}
	if _, err := json.Marshal(&OriginalNodeHistoryDirectory{}); err == nil {
		t.Fatal("opaque serialized")
	}
	if r, err := OpenOriginalNodeHistoryDirectory(context.Background(), nil, ObservationBinding{}, "", "/original"); err == nil || r != nil {
		t.Fatal("nil proof accepted")
	}
}
