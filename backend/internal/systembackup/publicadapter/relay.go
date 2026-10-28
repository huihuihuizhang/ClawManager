package publicadapter

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"

	"clawreef/internal/systembackup/relaywire"
	d "clawreef/internal/systembackupdispatch"
	"k8s.io/apimachinery/pkg/util/validation"
)

const RelayVersion = relaywire.RelayVersion

// RelayMessage retains the same closed JSON payload. Shared data aliases break
// the A message-binding -> B runner -> A peer-auth dependency cycle; they grant
// no authority. B still owns decoding/validation and A owns authenticated proof.
type RelayMessage = relaywire.RelayMessage
type RelayEvidence = relaywire.RelayEvidence

func positiveDecimal(s string) (uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && n > 0 && strconv.FormatUint(n, 10) == s
}

func validRelayMessage(m RelayMessage) bool {
	_, attempt := positiveDecimal(m.AttemptNo)
	_, generation := positiveDecimal(m.JobGeneration)
	_, seq := positiveDecimal(m.Sequence)
	if m.SchemaVersion != RelayVersion || !installation.MatchString(m.InstallationID) || !taskID.MatchString(m.TaskPublicID) || !attempt || !generation || !seq || !unit.MatchString(m.JobUnitKey) || !uuid.MatchString(m.JobUID) || len(validation.IsDNS1123Label(m.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(m.JobName)) != 0 || m.RelayIdentityRef == "" || len(m.RelayIdentityRef) > 256 || m.RelayIdentityVersion == "" || len(m.RelayIdentityVersion) > 128 {
		return false
	}
	if (m.TaskType != "backup" || m.TaskPublicID[:4] != "sbk_" || m.Phase != "capture") && (m.TaskType != "preflight" || m.TaskPublicID[:4] != "spf_" || m.Phase != "preflight") {
		return false
	}
	switch m.Status {
	case "ready", "running", "failed", "canceled":
		return m.ResultEvidence == nil
	case "completed":
		return m.ResultEvidence != nil && evidenceID.MatchString(m.ResultEvidence.PublicID) && hexHash.MatchString(m.ResultEvidence.SHA256)
	default:
		return false
	}
}

type RelayDecision string

const (
	RelayAdvance RelayDecision = "advance"
	RelayReplay  RelayDecision = "replay"
)

// RelaySequence is evaluated by D INSIDE its authoritative cursor transaction,
// after A peer/revocation/expiry and public claim/fence/Job checks. Initial cursor
// is (0, ""); exact latest replay is idempotent; gaps/stale/conflicting bodies
// reject. No receipt or history is synthesized here.
func RelaySequence(last uint64, lastBody string, next uint64, body string) (RelayDecision, error) {
	if !hexHash.MatchString(body) || next == 0 || (last == 0 && lastBody != "") || (last > 0 && !hexHash.MatchString(lastBody)) {
		return "", &Failure{"control_evidence_invalid"}
	}
	if next == last {
		if body == lastBody {
			return RelayReplay, nil
		}
		return "", &Failure{"coordination_invalid"}
	}
	if last == math.MaxUint64 || next != last+1 {
		return "", &Failure{"coordination_invalid"}
	}
	return RelayAdvance, nil
}

// RelayProgress is B's proposed worker-status transition rule. D evaluates it
// with RelaySequence under the SAME locked cursor, after A/current authority
// checks. Exact-body replay may acknowledge an existing terminal observation;
// a new sequence can never reopen or replace terminal worker facts. This is
// worker progress only, never a public task/attempt status transition.
func RelayProgress(previous string, next RelayMessage, decision RelayDecision) error {
	if !validRelayMessage(next) {
		return &Failure{"control_evidence_invalid"}
	}
	if decision == RelayReplay && previous == next.Status && previous != "" {
		return nil
	}
	if decision != RelayAdvance {
		return &Failure{"coordination_invalid"}
	}
	switch previous {
	case "":
		if next.Status == "ready" && next.Sequence == "1" {
			return nil
		}
	case "ready":
		return nil // ready heartbeat or started/terminal observation
	case "running":
		if next.Status != "ready" {
			return nil
		}
	}
	return &Failure{"coordination_invalid"}
}

// relayAcceptor is the private transport decoder seam. Production construction
// goes through NewAuthenticatedRelayHandler and A's original peer proof; there
// is no exported unauthenticated handler constructor or fallback route.
type relayAcceptor interface {
	AcceptRelay(context.Context, *http.Request, RelayMessage, []byte, string) (RelayDecision, error)
}
type relayHandler struct{ acceptor relayAcceptor }

func newRelayHandler(a relayAcceptor) (http.Handler, error) {
	if nilValue(a) {
		return nil, d.ErrNotReady
	}
	return relayHandler{a}, nil
}

func (h relayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].Scheme != "spiffe" || r.TLS.PeerCertificates[0].URIs[0].Host == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.URL.RawQuery != "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(raw) > 65536 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var message RelayMessage
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	_, hasResult := fields["result_evidence"]
	if decodeRequiredObject(raw, &message) != nil || !hasResult || !validRelayMessage(message) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if message.ResultEvidence != nil {
		var evidence RelayEvidence
		if decodeRequiredObject(fields["result_evidence"], &evidence) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	decision, err := h.acceptor.AcceptRelay(r.Context(), r, message, raw, digest(raw))
	if err != nil || r.Context().Err() != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if decision != RelayAdvance && decision != RelayReplay {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Decision RelayDecision `json:"decision"`
	}{decision})
}
