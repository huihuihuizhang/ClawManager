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
	"path"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/services"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const sharedRuntimeNodeWireLimit = 4 << 20

func sharedRuntimeNodeJSON(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > sharedRuntimeNodeWireLimit {
		return ErrNodeObservation
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return ErrNodeObservation
	}
	if !sharedRuntimeNodeExactNames(raw, reflect.TypeOf(out), 0) {
		return ErrNodeObservation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrNodeObservation
	}
	return nil
}

func sharedRuntimeNodeExactNames(raw []byte, t reflect.Type, depth int) bool {
	if t == nil || depth > 64 {
		return false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		return true
	}
	if t.Kind() == reflect.Struct {
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for name, value := range members {
			field, ok := fields[name]
			if !ok || !sharedRuntimeNodeExactNames(value, field, depth+1) {
				return false
			}
		}
	} else if t.Kind() == reflect.Slice && t.Elem().Kind() != reflect.Uint8 {
		var members []json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			return false
		}
		for _, value := range members {
			if !sharedRuntimeNodeExactNames(value, t.Elem(), depth+1) {
				return false
			}
		}
	}
	return true
}

// Root's distinct authenticated lifecycle handler can use this bounded strict
// decoder. It does not perform native work or authorize a physical operation.
func DecodeSharedRuntimeNodeRequest(reader io.Reader) (SharedRuntimeNodeRequest, error) {
	var r SharedRuntimeNodeRequest
	raw, err := io.ReadAll(io.LimitReader(reader, sharedRuntimeNodeWireLimit+1))
	if err != nil || sharedRuntimeNodeJSON(raw, &r) != nil {
		return r, ErrNodeObservation
	}
	return r, nil
}

func sharedRuntimeNodeRecovery(action string) bool {
	return action == "thaw" || action == "recovered" || action == "complete" || action == "orphan-thawed"
}

// Only data/schema checks. Root MUST additionally authenticate original durable
// native ownership and actual kernel/GoAgent/FLOCK/mount/writer state.
func ValidateSharedRuntimeNodeRequest(r SharedRuntimeNodeRequest, now time.Time) error {
	b, o := r.Binding, r.Original
	if r.Version != SharedRuntimeNodeProtocol || SharedRuntimeNodeFacts(r.Action) == nil || !validObservationHash(r.Nonce) || now.IsZero() || !now.Before(r.Deadline) || r.Deadline.After(now.Add(15*time.Second)) || b.Kind != SharedRuntimeNodeKind || b.InstallationID == "" || b.OperationID == "" || b.Namespace == "" || b.NamespaceUID == "" || b.Node == "" || b.NodeUID == "" || b.Generation == 0 || b.ExpiresAt.IsZero() || !validObservationHash(b.InventorySHA256) || !validObservationPods([]PodIdentity{r.AgentPod}, b.Node) || len(r.AgentPod.Containers) != 1 {
		return ErrNodeObservation
	}
	if !sharedRuntimeNodeRecovery(r.Action) && r.Action != "state" && !r.Deadline.Before(b.ExpiresAt) {
		return ErrNodeObservation
	}
	if sharedRuntimeNodeRecovery(r.Action) && !validObservationHash(r.RecoveryBoundarySHA256) || !sharedRuntimeNodeRecovery(r.Action) && r.RecoveryBoundarySHA256 != "" {
		return ErrNodeObservation
	}
	if o.Version != "shared-runtime-native-state.v1" || o.Phase != "reserved" || o.Identity.Protocol != services.RuntimeSharedBackupProtocol || o.Identity.Namespace != b.Namespace || o.Identity.PodUID != r.AgentPod.UID || o.Identity.Deployment == "" || o.Identity.OperationID != b.ReservationID || o.Identity.InventorySHA256 != b.InventorySHA256 || !sharedRuntimeNodeHex(o.Identity.AgentEpoch, 16) || !sharedRuntimeNodeHex(o.Identity.OperationID, 16) || o.AgentPID <= 0 || !sharedRuntimeNodeDecimal(o.AgentStartTicks) || o.PIDNamespace == "" || o.MountNamespace == "" || o.BootID == "" || o.Entries == nil || o.Sequence != 1 || o.PreparedAt.IsZero() || o.UpdatedAt.Before(o.PreparedAt) || !validObservationHash(o.JournalSHA256) || o.OriginalSHA256 != services.SharedRuntimeOriginalSHA(o) {
		return ErrNodeObservation
	}
	if !absoluteObservationPath(r.WorkspaceRoot) || !absoluteObservationPath(r.AgentDataDir) || r.WorkspaceRoot == "/" || r.AgentDataDir == "/" || r.AgentDataDir == r.WorkspaceRoot || strings.HasPrefix(r.AgentDataDir, r.WorkspaceRoot+"/") || o.GuardPath != path.Join(r.AgentDataDir, "shared-backup.guard") || o.JournalPath != path.Join(r.AgentDataDir, "shared-backup/current.json") {
		return ErrNodeObservation
	}
	var decoded services.RuntimeSharedNativeState
	if len(r.OriginalRaw) > 1<<20 || sharedRuntimeNodeJSON(r.OriginalRaw, &decoded) != nil || observationDigest(decoded) != observationDigest(o) {
		return ErrNodeObservation
	}
	seen := map[int]bool{}
	for _, e := range o.Entries {
		if e.InstanceID <= 0 || seen[e.InstanceID] || e.UserID <= 0 || e.Generation <= 0 || e.GatewayID == "" || e.RuntimeType == "" || e.Port <= 0 || e.Port > 65535 || e.PID < 0 || e.OriginalState != "running" && e.OriginalState != "stopped" && e.OriginalState != "error" || !validObservationHash(e.RequestSHA256) || e.PID > 0 && !sharedRuntimeNodeDecimal(e.PIDStartTicks) || e.PID == 0 && (e.PIDStartTicks != "" || e.OriginalState == "running") {
			return ErrNodeObservation
		}
		seen[e.InstanceID] = true
	}
	if len(r.SourcePaths) == 0 || len(r.SourcePaths) > 128 || !sort.StringsAreSorted(r.SourcePaths) {
		return ErrNodeObservation
	}
	for i, p := range r.SourcePaths {
		if !absoluteObservationPath(p) || p == "/" || i > 0 && (p == r.SourcePaths[i-1] || strings.HasPrefix(p, r.SourcePaths[i-1]+"/")) {
			return ErrNodeObservation
		}
	}
	if r.Action == "prepare" {
		if r.Anchor != "" || len(r.Peers) != 0 {
			return ErrNodeObservation
		}
	} else if r.Action != "state" || r.Anchor != "" {
		if r.Anchor == "" || len(r.Anchor) > 512<<10 || len(r.Peers) == 0 || len(r.Peers) > 128 {
			return ErrNodeObservation
		}
		self := 0
		for i, p := range r.Peers {
			if p.PodUID == "" || p.Anchor == "" || len(p.Anchor) > 512<<10 || !validObservationHash(p.OriginalSHA256) || i > 0 && p.PodUID <= r.Peers[i-1].PodUID {
				return ErrNodeObservation
			}
			if p.PodUID == r.AgentPod.UID {
				if p.Anchor != r.Anchor || p.OriginalSHA256 != o.OriginalSHA256 {
					return ErrNodeObservation
				}
				self++
			}
		}
		if self != 1 {
			return ErrNodeObservation
		}
	}
	want := ""
	if r.Action == "recovered" {
		want = "resumed"
	}
	if r.Action == "complete" {
		want = "completed"
	}
	if want == "" {
		if r.Current != nil || len(r.CurrentRaw) != 0 {
			return ErrNodeObservation
		}
	} else {
		if r.Current == nil || len(r.CurrentRaw) > 1<<20 || sharedRuntimeNodeJSON(r.CurrentRaw, &decoded) != nil || observationDigest(decoded) != observationDigest(r.Current) || r.Current.Identity != o.Identity || r.Current.OriginalSHA256 != o.OriginalSHA256 || r.Current.OriginalSHA256 != services.SharedRuntimeOriginalSHA(*r.Current) || r.Current.Phase != want || r.Current.GuardPath != o.GuardPath || r.Current.JournalPath != o.JournalPath || r.Current.Sequence < 2 || r.Current.PreparedAt != o.PreparedAt || r.Current.UpdatedAt.Before(o.UpdatedAt) || !validObservationHash(r.Current.JournalSHA256) {
			return ErrNodeObservation
		}
	}
	return nil
}

func sharedRuntimeNodeHex(value string, n int) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == n && hex.EncodeToString(raw) == value
}
func sharedRuntimeNodeDecimal(value string) bool {
	if value == "" || value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func SharedRuntimeNodeRequestSHA256(r SharedRuntimeNodeRequest) string { return observationDigest(r) }

type SharedRuntimeNodeClient struct{ proof *ProofClient }

func NewSharedRuntimeNodeClient(endpoints map[string]ProofEndpoint, caFile, certFile, keyFile string) (*SharedRuntimeNodeClient, error) {
	p, err := NewProofClient(endpoints, caFile, certFile, keyFile)
	if err != nil {
		return nil, ErrNodeObservation
	}
	for _, e := range p.Endpoints {
		u, err := url.Parse(e.URL)
		if err != nil || u.Path != SharedRuntimeNodeRoute {
			return nil, ErrNodeObservation
		}
	}
	return &SharedRuntimeNodeClient{proof: p}, nil
}

// EXACTLY one authenticated request; no retry on response loss. Caller first
// journals send-unknown. state queries the ORIGINAL durable native operation.
func (c *SharedRuntimeNodeClient) Transition(ctx context.Context, in SharedRuntimeNodeRequest) (*VerifiedSharedRuntimeNodeObservation, []byte, error) {
	if c == nil || c.proof == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrNodeObservation
	}
	d, ok := ctx.Deadline()
	if !ok {
		return nil, nil, ErrNodeObservation
	}
	endpoint, ok := c.proof.Endpoints[in.Binding.Node]
	if !ok {
		return nil, nil, ErrNodeObservation
	}
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	if d.Before(until) {
		until = d
	}
	if !sharedRuntimeNodeRecovery(in.Action) && in.Action != "state" && !until.Before(in.Binding.ExpiresAt) {
		until = in.Binding.ExpiresAt.Add(-time.Nanosecond)
	}
	if !now.Before(until) {
		return nil, nil, ErrNodeObservation
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, ErrNodeObservation
	}
	in.Version, in.Nonce, in.Deadline = SharedRuntimeNodeProtocol, hex.EncodeToString(nonce), until
	if ValidateSharedRuntimeNodeRequest(in, now) != nil {
		return nil, nil, ErrNodeObservation
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > sharedRuntimeNodeWireLimit {
		return nil, nil, ErrNodeObservation
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.proof.Roots, Certificates: []tls.Certificate{c.proof.Certificate}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || len(s.PeerCertificates[0].URIs) != 1 || s.PeerCertificates[0].URIs[0].String() != endpoint.ServerURI {
			return ErrNodeObservation
		}
		return nil
	}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(bounded, http.MethodPost, endpoint.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, nil, ErrNodeObservation
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, ErrNodeObservation
	}
	defer res.Body.Close()
	responseRaw, err := io.ReadAll(io.LimitReader(res.Body, sharedRuntimeNodeWireLimit+1))
	if err != nil || res.StatusCode != http.StatusOK {
		return nil, nil, ErrNodeObservation
	}
	var out SharedRuntimeNodeResponse
	if sharedRuntimeNodeJSON(responseRaw, &out) != nil || out.Version != in.Version || out.Action != in.Action || out.Nonce != in.Nonce || out.RequestSHA256 != observationDigest(in) || observationDigest(out.Binding) != observationDigest(in.Binding) || out.OriginalSHA256 != in.Original.OriginalSHA256 || out.OriginalRawSHA256 != observationRawDigest(in.OriginalRaw) || out.CurrentRawSHA256 != observationRawDigest(in.CurrentRaw) || out.CohortSHA256 != SharedRuntimeNodeCohortSHA(in) || out.SourcePathsSHA256 != SharedRuntimeNodeSourcePathsSHA(in) || !validObservationHash(out.NativeJournalSHA256) || out.Anchor == "" || out.BootID == "" || in.Anchor != "" && out.Anchor != in.Anchor || out.StartedAt.Before(now.Add(-2*time.Second)) || out.FinishedAt.Before(out.StartedAt) || out.FinishedAt.After(time.Now().Add(2*time.Second)) || !out.FinishedAt.Before(until) || !out.ValidUntil.Equal(until) || bounded.Err() != nil {
		return nil, nil, ErrNodeObservation
	}
	want := map[string]string{"prepare": "prepared", "freeze": "frozen", "check-frozen": "frozen", "thaw": "thawed", "recovered": "recovered", "complete": "completed", "orphan-thawed": "orphan-thawed"}[in.Action]
	facts := SharedRuntimeNodeFacts(in.Action)
	if in.Action == "thaw" && out.Phase == "orphan-thawed" {
		want = "orphan-thawed"
		facts = SharedRuntimeNodeFacts("orphan-thawed")
	}
	if in.Action == "state" {
		if out.Phase != "prepared" && out.Phase != "frozen" && out.Phase != "thawed" && out.Phase != "recovered" && out.Phase != "completed" && out.Phase != "orphan-thawed" && out.Phase != "uncertain" {
			return nil, nil, ErrNodeObservation
		}
	} else if out.Phase != want || out.TasksChecked <= 0 || out.Files <= 0 {
		return nil, nil, ErrNodeObservation
	}
	if !reflect.DeepEqual(out.Facts, facts) {
		return nil, nil, ErrNodeObservation
	}
	var original SharedRuntimeNodeRequest
	if sharedRuntimeNodeJSON(raw, &original) != nil {
		return nil, nil, ErrNodeObservation
	}
	return &VerifiedSharedRuntimeNodeObservation{response: out, originalRequest: original}, responseRaw, nil
}
