package quiesce

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"strings"
)

// OriginalRestartSHA256 is the original CreateGatewayRequest wire digest read
// by the native Node from its actual private slot-assignment book at prepare.
// It is never Running.RestartSHA256, which pins the successor generation.
// This read-only DATA accessor neither refreshes the sample nor proves D's
// continuous hold; the caller must still Recheck this same opaque observation.
func (v *VerifiedGatewayNodeObservation) OriginalRestartSHA256() string {
	if v == nil || v.response.Binding.Kind != GatewayNodeRunning || !validObservationHash(v.originalRestartSHA256) {
		return ""
	}
	return v.originalRestartSHA256
}

// Called ONLY after the concrete client authenticates the native TLS response,
// nonce/request/body hashes, phase, source identity and freshness. The existing
// Node-signed anchor already carries OriginalDigest, so no wire field or native
// read is added. The client does not possess the Node's HMAC key; authenticity
// comes from the verified native Node transport, not from parsing caller DATA.
func gatewayOriginalRestartFromAnchor(in GatewayNodeObservationRequest, out GatewayNodeObservationResponse) (string, error) {
	if in.Binding.Kind != GatewayNodeRunning {
		return "", nil
	}
	p := strings.Split(out.Anchor, ".")
	if len(p) != 2 || len(out.Anchor) > 256<<10 {
		return "", ErrNodeObservation
	}
	signature, err := hex.DecodeString(p[1])
	if err != nil || len(signature) != 32 || hex.EncodeToString(signature) != p[1] {
		return "", ErrNodeObservation
	}
	raw, err := base64.RawURLEncoding.DecodeString(p[0])
	if err != nil || len(raw) > 192<<10 {
		return "", ErrNodeObservation
	}
	var a gatewayObservationAnchor
	if observationJSON(strings.NewReader(string(raw)), &a) != nil || a.Version != GatewayNodeObservationProtocol || observationDigest(a.Binding) != observationDigest(in.Binding) || observationDigest(a.Binding) != observationDigest(out.Binding) || !reflect.DeepEqual(a.AgentPod, in.AgentPod) || a.RequestSHA256 != gatewayRequestSHA(in) || a.OriginalStateSHA256 != in.OriginalStateSHA256 || a.OriginalStateSHA256 != out.OriginalStateSHA256 || a.Slot != in.Slot || a.WorkspaceRoot != in.WorkspaceRoot || a.AgentDataDir != in.AgentDataDir || a.BootID == "" || a.BootID != out.BootID || !validObservationHash(a.OriginalDigest) {
		return "", ErrNodeObservation
	}
	return a.OriginalDigest, nil
}
