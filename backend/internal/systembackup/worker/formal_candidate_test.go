package worker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	k "clawreef/internal/systembackupkms"
)

func TestFormalCandidateReportUsesOriginalKeyWindowAndRetriesOnlyMetadata(t *testing.T) {
	for _, fault := range []string{"", "wrong-ack", "key-in-use", "changed-pod", "denied", "unexpected-dek"} {
		t.Run(fault, func(t *testing.T) {
			i, env, key := formalInvocationFixture(t)
			result, err := runFormalCapture(context.Background(), i, key, env)
			if err != nil {
				t.Fatal(err)
			}
			hash, _ := i.Hash()
			lease := KeyUseLease{Identity: k.JobIdentity{Namespace: "ns", PodUID: "pod", ServiceAccountUID: "sa", JobUID: "job", InvocationSHA256: hash, ExecutionGrantSHA256: strings.Repeat("a", 64)}, Access: *i.ProviderKey, AuthoritySHA256: strings.Repeat("b", 64), Nonce: strings.Repeat("c", 32), Until: i.Request.Deadline.Add(-time.Second).UTC(), State: "finished"}
			var original []byte
			calls := 0
			h := ControlHandler{Authorizer: authorizeFunc(func(_ context.Context, _ string, r ControlRequest) (Lease, error) {
				calls++
				if r.Action != "candidate" || r.Point != lease.Nonce || r.InvocationSHA256 != hash || r.Result != nil {
					t.Fatal("candidate borrowed another operation")
				}
				raw, _ := json.Marshal(r)
				if original == nil {
					original = raw
				} else if string(original) != string(raw) {
					t.Fatal("retry changed original candidate")
				}
				if calls == 1 {
					return Lease{}, ErrNotReady
				} // commit/ACK unknown
				if fault == "denied" {
					return Lease{}, ErrExecution
				}
				out := Lease{InvocationSHA256: hash, ExpiresAt: lease.Until, KeyUse: &lease, CandidateSHA256: FormalCandidateSHA256(i, r.Candidate)}
				switch fault {
				case "wrong-ack":
					out.CandidateSHA256 = strings.Repeat("d", 64)
				case "key-in-use":
					lease.State = "using"
				case "changed-pod":
					lease.Identity.PodUID = "replacement"
				case "unexpected-dek":
					out.DEK = make([]byte, 32)
				}
				return out, nil
			})}
			client, _ := mutualTLSFixture(t, h)
			originalLease := lease
			// OriginalKeyAuthority records its immutable identity before any ACK.
			a := &OriginalKeyAuthority{client: client, invocation: i, lease: originalLease, used: true}
			job := &CaptureKeyJob{original: a, until: lease.Until, access: *i.ProviderKey}
			err = job.ReportCandidate(context.Background(), i, result)
			if (err == nil) != (fault == "") {
				t.Fatal("wrong candidate outcome", err)
			}
			if calls != 2 || key.calls != 1 {
				t.Fatal("candidate retry regenerated data/key", calls, key.calls)
			}
		})
	}
}

func TestFormalCandidateCannotBorrowOtherInvocationOrLegacyComplete(t *testing.T) {
	i, env, key := formalInvocationFixture(t)
	result, err := runFormalCapture(context.Background(), i, key, env)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"", "invocation", "cipher-name", "envelope-name", "negative-count", "oversize", "missing-formal", "functional", "legacy-complete", "extra-candidate", "nonce"} {
		t.Run(fault, func(t *testing.T) {
			inv := i
			r := result
			hash, _ := inv.Hash()
			req := ControlRequest{Invocation: inv, InvocationSHA256: hash, Action: "candidate", Point: strings.Repeat("c", 32), Candidate: &r}
			switch fault {
			case "invocation":
				r.InvocationSHA256 = strings.Repeat("f", 64)
			case "cipher-name":
				r.Ciphertext.Name = "other.enc"
			case "envelope-name":
				r.Envelope.Name = "other.json"
			case "negative-count":
				r.Files = -1
			case "oversize":
				r.Ciphertext.Size = 1 << 50
			case "missing-formal":
				req.Invocation.FormalCapture = nil
			case "functional":
				req.Invocation.ProviderKey = nil
				req.Invocation.FormalCapture = nil
			case "legacy-complete":
				req.Action = "complete"
			case "extra-candidate":
				req.Action = "key-check"
			case "nonce":
				req.Point = "wrong"
			}
			if ValidateControl(req) != (fault == "") {
				t.Fatal("changed candidate admitted", fault)
			}
		})
	}
}
