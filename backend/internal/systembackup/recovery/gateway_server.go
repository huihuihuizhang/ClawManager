package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"
)

// NativeGatewayBackend must verify native provider evidence. In particular,
// Create enforces request expiry at STORAGE, not only at this HTTP proxy.
// Begin/Page must use an immutable snapshot, never live LIST pagination. Page
// verifies every supplied snapshot field and cursor against its frozen native
// state. All methods must honor cancellation and use bounded provider calls.
type NativeGatewayBackend interface {
	AppendProvider
	Discovery
	Capabilities(context.Context) ([]Capability, error)
}

// GatewayDispatchJournal durably claims an immutable provider/root/key before
// any send. Only the first committed claim returns true. An uncertain commit
// returns an error; repeats return false and may only Observe, never Create.
type GatewayDispatchJournal interface {
	Reserve(context.Context, Locator, Request) (bool, error)
}

type GatewayServerConfig struct {
	Identity      Reference
	Location      Locator
	DiscoveryMode string
	AllowAppend   bool
	// SHA256 of the verified client leaf certificate -> explicit operations.
	Clients   map[string][]string
	TimeoutMS int64
}

func (c GatewayServerConfig) Validate() error {
	if c.Identity.Validate() != nil || c.Location.Validate() != nil || c.TimeoutMS < 1000 || c.TimeoutMS > 60000 || len(c.Clients) == 0 || len(c.Clients) > 256 {
		return ErrContract
	}
	if c.DiscoveryMode != "known_record_only" && c.DiscoveryMode != "inventory_manifest" && c.DiscoveryMode != "provider_snapshot" {
		return ErrContract
	}
	for fingerprint, ops := range c.Clients {
		if !digest(fingerprint) || len(ops) == 0 || len(ops) > 6 {
			return ErrContract
		}
		seen := map[string]bool{}
		for _, op := range ops {
			if seen[op] {
				return ErrContract
			}
			seen[op] = true
			switch op {
			case "capabilities", "observe", "open":
			case "conditional_create":
				if !c.AllowAppend {
					return ErrContract
				}
			case "begin_snapshot", "snapshot_page":
				if c.DiscoveryMode == "known_record_only" {
					return ErrContract
				}
			default:
				return ErrContract
			}
		}
	}
	return nil
}

type GatewayServer struct {
	config  GatewayServerConfig
	backend NativeGatewayBackend
	journal GatewayDispatchJournal
	now     func() int64
}

func NewGatewayServer(c GatewayServerConfig, backend NativeGatewayBackend, journal GatewayDispatchJournal) (*GatewayServer, error) {
	if c.Validate() != nil || backend == nil || backend.Identity() != c.Identity || backend.Location() != c.Location || c.AllowAppend && journal == nil {
		return nil, ErrContract
	}
	// Copy authorization policy; the caller cannot widen it after construction.
	clients := map[string][]string{}
	for k, v := range c.Clients {
		clients[k] = append([]string(nil), v...)
	}
	c.Clients = clients
	return &GatewayServer{c, backend, journal, func() int64 { return time.Now().UnixMilli() }}, nil
}

func (s *GatewayServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fail := func(status int) { http.Error(w, "recovery request unavailable", status) }
	if r.Method != http.MethodPost || r.URL.Path != "/recovery/v1" || r.URL.RawQuery != "" {
		fail(http.StatusNotFound)
		return
	}
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		fail(http.StatusForbidden)
		return
	}
	ops, ok := s.config.Clients[Hash(r.TLS.PeerCertificates[0].Raw)]
	if !ok {
		fail(http.StatusForbidden)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		fail(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.config.TimeoutMS)*time.Millisecond)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, MaxDocument)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		fail(http.StatusRequestEntityTooLarge)
		return
	}
	var q GatewayRequest
	if CanonicalGatewayRequest(raw) != nil || decode(raw, &q) != nil || q.Schema != GatewayProtocol || !digest(q.Nonce) || q.Identity != s.config.Identity || q.Location != s.config.Location || s.backend.Identity() != q.Identity || s.backend.Location() != q.Location {
		fail(http.StatusBadRequest)
		return
	}
	allowed := false
	for _, op := range ops {
		allowed = allowed || op == q.Operation
	}
	if !allowed {
		fail(http.StatusForbidden)
		return
	}
	write := q.Operation == "conditional_create"
	discovery := q.Operation == "begin_snapshot" || q.Operation == "snapshot_page"
	if write && !s.config.AllowAppend || discovery && s.config.DiscoveryMode == "known_record_only" {
		fail(http.StatusForbidden)
		return
	}
	caps, err := s.backend.Capabilities(ctx)
	if err != nil || len(caps) > 128 || RequireCapabilities(caps, q.Identity, s.now(), write, discovery) != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	if discovery {
		code := "provider_snapshot_listing"
		if s.config.DiscoveryMode == "inventory_manifest" {
			code = "inventory_manifest_listing"
		}
		found := false
		for _, c := range caps {
			found = found || c.Identity == q.Identity && c.Role == "catalog" && c.Code == code && c.Status == "supported"
		}
		if !found {
			fail(http.StatusServiceUnavailable)
			return
		}
	}
	var payload any
	switch q.Operation {
	case "capabilities":
		var args struct{}
		if gatewayArguments(q.Arguments, &args) != nil {
			fail(400)
			return
		}
		payload = caps
	case "observe":
		var args struct{ Key string }
		if gatewayArguments(q.Arguments, &args) != nil || !safeKey(args.Key) {
			fail(400)
			return
		}
		o, e := s.backend.Observe(ctx, args.Key)
		if e != nil || !o.decisive(args.Key, s.now()) {
			fail(503)
			return
		}
		payload = o
	case "conditional_create":
		var request Request
		if gatewayArguments(q.Arguments, &request) != nil || request.Validate() != nil || request.Target != q.Identity || request.Deadline <= s.now() || request.Deadline > s.now()+int64((24*time.Hour)/time.Millisecond) {
			fail(400)
			return
		}
		work, stop := context.WithDeadline(ctx, time.UnixMilli(request.Deadline))
		defer stop()
		first, e := s.journal.Reserve(work, q.Location, request)
		if e != nil {
			fail(503)
			return
		}
		var o Observation
		if first {
			if work.Err() != nil || s.now() >= request.Deadline {
				fail(503)
				return
			}
			o, e = s.backend.Create(work, request)
		} else {
			o, e = s.backend.Observe(work, request.Key)
		}
		if e != nil || !o.decisive(request.Key, s.now()) {
			fail(503)
			return
		}
		payload = o
	case "open":
		var o Object
		if gatewayArguments(q.Arguments, &o) != nil || !o.valid() {
			fail(400)
			return
		}
		stream, e := s.backend.Open(ctx, o)
		if e != nil || stream == nil {
			fail(503)
			return
		}
		defer stream.Close()
		receipt, e := s.receipt(q, raw, o)
		if e != nil {
			fail(503)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(o.Size, 10))
		w.Header().Set("X-Recovery-Receipt", string(receipt))
		h := sha256.New()
		n, e := io.CopyN(io.MultiWriter(w, h), stream, o.Size)
		var extra [1]byte
		_, end := io.ReadFull(stream, extra[:])
		if e != nil || n != o.Size || end != io.EOF || hex.EncodeToString(h.Sum(nil)) != o.SHA256 {
			panic(http.ErrAbortHandler)
		}
		return
	case "begin_snapshot":
		var args struct {
			Deadline int64
			Mode     string
		}
		if gatewayArguments(q.Arguments, &args) != nil || args.Mode != s.config.DiscoveryMode || args.Deadline <= s.now() || args.Deadline > s.now()+int64((24*time.Hour)/time.Millisecond) {
			fail(400)
			return
		}
		snapshot, e := s.backend.Begin(ctx, args.Deadline)
		if e != nil || !s.validSnapshot(snapshot) || snapshot.ExpiresAt < args.Deadline {
			fail(503)
			return
		}
		payload = snapshot
	case "snapshot_page":
		var args struct {
			Snapshot Snapshot
			Cursor   string
			Number   int64
		}
		if gatewayArguments(q.Arguments, &args) != nil || !s.validSnapshot(args.Snapshot) || len(args.Cursor) > 4096 || args.Number < 0 || args.Number > 100000 || (args.Number == 0) != (args.Cursor == "") {
			fail(400)
			return
		}
		page, e := s.backend.Page(ctx, args.Snapshot, args.Cursor, args.Number)
		if e != nil || page.SnapshotID != args.Snapshot.ID || page.Number != args.Number || page.Cursor != args.Cursor || len(page.Next) > 4096 || len(page.Objects) > 1000 || int64(len(page.Objects)) > args.Snapshot.Count || page.Next != "" && (page.Next == page.Cursor || len(page.Objects) == 0) {
			fail(503)
			return
		}
		last := ""
		for _, o := range page.Objects {
			if !o.valid() || o.Key <= last {
				fail(503)
				return
			}
			last = o.Key
		}
		payload = page
	default:
		fail(400)
		return
	}
	response, e := s.receipt(q, raw, payload)
	if e != nil || ctx.Err() != nil {
		fail(503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(response)
}

func (s *GatewayServer) validSnapshot(v Snapshot) bool {
	return validID(v.ID) && v.Root == s.config.Identity && v.Mode == s.config.DiscoveryMode && v.Count >= 0 && v.Count <= 100000 && digest(v.RecordsSHA256) && v.ExpiresAt > s.now()
}
func (s *GatewayServer) receipt(q GatewayRequest, raw []byte, payload any) ([]byte, error) {
	p, e := Marshal(payload)
	if e != nil {
		return nil, e
	}
	return Marshal(GatewayResponse{GatewayProtocol, q.Nonce, Hash(raw), s.config.Identity, s.now() + 10000, p})
}

// CanonicalGatewayRequest rejects duplicate/unknown fields without reflecting
// sensitive payloads in errors. Also useful to adapter conformance tests.
func CanonicalGatewayRequest(raw []byte) error {
	var q GatewayRequest
	return gatewayArguments(raw, &q)
}

func gatewayArguments(raw []byte, out any) error {
	if decode(raw, out) != nil {
		return ErrContract
	}
	b, e := Marshal(out)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrContract
	}
	return nil
}
