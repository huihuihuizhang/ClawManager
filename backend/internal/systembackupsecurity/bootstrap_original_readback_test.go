package systembackupsecurity

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestOriginalBootstrapReadbackDoesNotReplayWrites(t *testing.T) {
	for _, fault := range []string{"none", "wrong_request_hash", "operation_absent", "config_changed"} {
		t.Run(fault, func(t *testing.T) {
			svc, g, raw, state := bootstrapServiceFixture(t)
			config, err := DecodeBootstrapConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			state.canonical = config.CanonicalJSON()
			svc.CanonicalSnapshot = true
			first, err := svc.Bootstrap(context.Background(), g, raw)
			if err != nil {
				t.Fatal(err)
			}
			digest := state.hash
			switch fault {
			case "wrong_request_hash":
				digest = registrationHash("foreign")
			case "operation_absent":
				state.op = ""
			case "config_changed":
				state.config["enabled"] = true
			}
			before := append([]string(nil), state.committed...)
			authorized, validated := state.authorized, state.validated
			queryFloor := len(state.queries)
			got, err := ReadbackOriginalBootstrapCommit(context.Background(), svc.DB, g, config, digest)
			if fault == "none" {
				if err != nil || got.OperationPublicID != first.OperationPublicID || got.Version != 1 {
					t.Fatal("original commit not observed", err)
				}
			} else if err == nil {
				t.Fatal("unknown or changed original state accepted")
			}
			for _, q := range state.queries[queryFloor:] {
				if strings.Contains(q, "FOR UPDATE") {
					t.Fatal("readback requires unnecessary write privilege")
				}
			}
			if !reflect.DeepEqual(before, state.committed) || len(state.pending) != 0 || state.authorized != authorized || state.validated != validated {
				t.Fatal("readback replayed admission or writes")
			}
		})
	}
}
