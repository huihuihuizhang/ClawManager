package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
)

func TestOriginalJobKeyUseIsBoundedAndNonReplayable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	current := worker.KeyUseLease{Identity: k.JobIdentity{Namespace: "ns", PodUID: "pod", JobUID: "job", ServiceAccountUID: "sa", InvocationSHA256: strings.Repeat("a", 64), ExecutionGrantSHA256: strings.Repeat("b", 64)}, AuthoritySHA256: strings.Repeat("c", 64), Nonce: strings.Repeat("d", 32), Until: now.Add(time.Minute)}
	state, changed, e := advanceKeyUse(nil, current, "key-reserve", now)
	if e != nil || !changed || state.State != "reserved" {
		t.Fatal(e)
	}
	encode := func() []byte { b, _ := json.Marshal(state); return b }
	if _, _, e = advanceKeyUse(encode(), current, "key-reserve", now); e == nil {
		t.Fatal("repeated reserve")
	}
	if _, _, e = advanceKeyUse(encode(), current, "key-end", now); e == nil {
		t.Fatal("end before use")
	}
	if _, _, e = advanceKeyUse(encode(), current, "candidate", now); e == nil {
		t.Fatal("candidate before use")
	}
	for _, mode := range []string{"pod", "job", "sa", "installation", "version", "purpose", "claim", "nonce", "grant", "expired", "shorter"} {
		t.Run(mode, func(t *testing.T) {
			bad := current
			clock := now
			switch mode {
			case "pod":
				bad.Identity.PodUID = "other"
			case "job":
				bad.Identity.JobUID = "other"
			case "sa":
				bad.Identity.ServiceAccountUID = "other"
			case "installation":
				bad.Access.Request.Context.InstallationID = "other"
			case "version":
				bad.Access.Request.Key.ProviderVersion = "2"
			case "purpose":
				bad.Access.Operation = k.Unwrap
			case "claim":
				bad.AuthoritySHA256 = strings.Repeat("f", 64)
			case "nonce":
				bad.Nonce = strings.Repeat("f", 32)
			case "grant":
				bad.Identity.ExecutionGrantSHA256 = strings.Repeat("f", 64)
			case "expired":
				clock = current.Until
			case "shorter":
				bad.Until = now.Add(time.Second)
			}
			if _, _, e := advanceKeyUse(encode(), bad, "key-begin", clock); e == nil {
				t.Fatal("changed original accepted")
			}
		})
	}
	longer := current
	longer.Until = now.Add(time.Hour)
	state, changed, e = advanceKeyUse(encode(), longer, "key-begin", now)
	if e != nil || !changed || state.State != "using" || !state.Until.Equal(current.Until) {
		t.Fatal("renewed original window", e)
	}
	if _, _, e = advanceKeyUse(encode(), current, "key-begin", now); e == nil {
		t.Fatal("replayed use")
	}
	if _, _, e = advanceKeyUse(encode(), current, "candidate", now); e == nil {
		t.Fatal("candidate during use")
	}
	state, changed, e = advanceKeyUse(encode(), current, "key-end", now)
	if e != nil || !changed || state.State != "finished" {
		t.Fatal(e)
	}
	if _, _, e = advanceKeyUse(encode(), current, "key-end", now); e == nil {
		t.Fatal("replayed completion")
	}
	if _, changed, e = advanceKeyUse(encode(), current, "key-check", now); e != nil || changed {
		t.Fatal("final check", e)
	}
	for tries := 0; tries < 2; tries++ {
		if _, changed, e = advanceKeyUse(encode(), current, "candidate", now); e != nil || changed {
			t.Fatal("candidate ACK retry altered key-use", e)
		}
	}
}
