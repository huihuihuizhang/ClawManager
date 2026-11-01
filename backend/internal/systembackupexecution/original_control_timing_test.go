package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Actual dependency/authority failures remain failures; telemetry cannot
// fabricate a passed Bind, Kube observation, SQL fact or execution lease.
func TestOriginalControlTimingCannotChangeAuthorityRejection(t *testing.T) {
	request := worker.ControlRequest{Action: "key-check", InvocationSHA256: "public-diagnostic-data"}
	registry := &originalControlTimingRegistry{}
	observer := &originalControlTimingObserver{}
	registry.entries.Store(request.InvocationSHA256, observer)
	ctx := context.WithValue(context.Background(), originalControlTimingContextKey{}, registry)
	owner := &PublicJobOwner{}
	lease, err := owner.Authorize(ctx, "", request)
	lease.Clear()
	if err != worker.ErrExecution {
		t.Fatal("observer changed real missing-dependency rejection", err)
	}
	guard, err := bindOriginalControlWorker(ctx, nil, c.SQLExecutionAuthority{}, d.Authority{}, request)
	if guard != nil || err != c.ErrExecutionAuthority {
		t.Fatal("observer changed real Bind rejection", err)
	}
	data := observer.data()
	if data.KeyCheck.Authorize.Calls != 1 || data.KeyCheck.Authorize.Failures != 1 || data.KeyCheck.SQLBind.Calls != 1 || data.KeyCheck.SQLBind.Failures != 1 || data.KeyCheck.KeyStateSQL.Calls != 0 {
		t.Fatal("wrong actual rejected-stage accounting", data)
	}
	unknown := request
	unknown.InvocationSHA256 = "unregistered-public-data"
	if startOriginalControlStage(ctx, unknown, originalControlAuthorize) != nil || startOriginalControlStage(context.Background(), request, originalControlAuthorize) != nil {
		t.Fatal("unknown/unobserved execution had timing observer")
	}
	if observer.data() != data {
		t.Fatal("reading DATA changed execution or timing")
	}
}
