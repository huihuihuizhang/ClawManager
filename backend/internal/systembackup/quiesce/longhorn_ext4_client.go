package quiesce

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

type VerifiedLonghornExt4Observation struct{ response LonghornExt4Response }

func (p *VerifiedLonghornExt4Observation) Response() LonghornExt4Response {
	if p == nil {
		return LonghornExt4Response{}
	}
	return p.response
}

// Reuses the existing controller's Node peer map, trust roots and certificate.
// No transport retry. After an unknown acquire/release, query the same source
// with state before the controller chooses its recovery action.
func (c *SharedRuntimeNodeClient) LonghornExt4Transition(ctx context.Context, in LonghornExt4Request) (*VerifiedLonghornExt4Observation, []byte, error) {
	if c == nil || c.proof == nil || ctx == nil || ctx.Err() != nil || !in.Claim.valid() {
		return nil, nil, ErrNodeObservation
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, nil, ErrNodeObservation
	}
	switch in.Action {
	case "register", "qualify", "acquire", "check-held", "state", "release", "register-client", "sync-client":
	default:
		return nil, nil, ErrNodeObservation
	}
	endpoint, ok := c.proof.Endpoints[in.Binding.Node]
	if !ok {
		return nil, nil, ErrNodeObservation
	}
	address, err := url.Parse(endpoint.URL)
	if err != nil || address.Path != SharedRuntimeNodeRoute || address.RawQuery != "" || address.Fragment != "" {
		return nil, nil, ErrNodeObservation
	}
	address.Path = LonghornExt4Route
	until := time.Now().Add(10 * time.Second)
	if deadline.Before(until) {
		until = deadline
	}
	forwardUntil := longhornExt4ForwardUntil(in.Binding, in.Claim)
	if in.Action != "state" && in.Action != "release" && !until.Before(forwardUntil) {
		until = forwardUntil.Add(-time.Nanosecond)
	}
	if !time.Now().Before(until) {
		return nil, nil, ErrNodeObservation
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	in.Version, in.Nonce, in.Deadline = LonghornExt4Protocol, hex.EncodeToString(nonce), until
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > 64<<10 {
		return nil, nil, ErrNodeObservation
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.proof.Roots,
			Certificates: []tls.Certificate{c.proof.Certificate}, VerifyConnection: func(s tls.ConnectionState) error {
				if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 ||
					s.PeerCertificates[0].URIs[0].String() != endpoint.ServerURI {
					return ErrNodeObservation
				}
				return nil
			}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(bounded, http.MethodPost, address.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, ErrNodeObservation
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	var out LonghornExt4Response
	if err != nil || res.StatusCode != http.StatusOK || len(body) > 64<<10 || sharedRuntimeNodeJSON(body, &out) != nil ||
		out.Version != in.Version || out.Action != in.Action || out.Nonce != in.Nonce ||
		out.RequestSHA256 != observationDigest(in) || out.SourceIdentity != in.SourceIdentity ||
		out.Attempt != in.Attempt || observationDigest(out.Binding) != observationDigest(in.Binding) ||
		observationDigest(out.Claim) != observationDigest(in.Claim) ||
		out.ProviderObservedAt.IsZero() || out.ClientPodUID != in.ClientPodUID || out.ClientContainerID != in.ClientContainerID ||
		!out.ExpiresAt.Equal(forwardUntil) || bounded.Err() != nil {
		return nil, nil, ErrNodeObservation
	}
	switch out.Phase {
	case "prepared", "ro-intent", "ro-applied", "freeze-intent", "freeze-acknowledged", "thaw-intent", "held", "rw-intent", "released", "client-prepared", "client-synced":
	default:
		return nil, nil, ErrNodeObservation
	}
	clientAction := in.Action == "register-client" || in.Action == "sync-client"
	if clientAction {
		want := "client-prepared"
		if in.Action == "sync-client" {
			want = "client-synced"
		}
		if in.ClientPodUID == "" || in.ClientContainerID == "" || out.NativeState != "nfs-client" || out.Phase != want || out.Sequence != 0 || out.JournalSHA256 != "" || !out.ProviderObservedAt.Before(out.ExpiresAt) {
			return nil, nil, ErrNodeObservation
		}
	} else if out.Sequence == 0 || !validObservationHash(out.JournalSHA256) || (out.NativeState != "ro" && out.NativeState != "rw" && out.NativeState != "freeze-stable" && out.NativeState != "thaw-acknowledged" && !(in.Action == "state" && out.NativeState == "unconfirmed")) {
		return nil, nil, ErrNodeObservation
	}
	if in.Action == "acquire" || in.Action == "check-held" {
		if out.Phase != "held" || (out.NativeState != "ro" && out.NativeState != "freeze-stable") || out.StartedAt.IsZero() ||
			out.HeldObservedAt.Before(out.StartedAt) || out.HeldObservedAt.IsZero() ||
			!out.HeldObservedAt.Before(out.ExpiresAt) || out.ProviderObservedAt.Before(out.HeldObservedAt) {
			return nil, nil, ErrNodeObservation
		}
	} else if !out.HeldObservedAt.IsZero() {
		return nil, nil, ErrNodeObservation
	}
	if in.Action == "release" && (out.Phase != "released" || (out.NativeState != "rw" && out.NativeState != "thaw-acknowledged")) {
		return nil, nil, ErrNodeObservation
	}
	return &VerifiedLonghornExt4Observation{response: out}, body, nil
}
