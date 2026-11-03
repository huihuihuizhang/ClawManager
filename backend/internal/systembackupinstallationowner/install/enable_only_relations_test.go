package install

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"testing"
	"time"
)

func TestEnableOnlyRelationsRejectDetachedAndUnboundSources(t *testing.T) {
	if _, e := NewOriginalRelationEnableOnlyMutation(nil, EnableOnlyRelationFiles{}); e == nil {
		t.Fatal("detached original sources accepted")
	}
	r := &OriginalRelationEnableOnlyMutation{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, e := r.Prepare(ctx, sec.ConfigMutationResourceInput{}); e == nil {
		t.Fatal("unbound candidate accepted")
	}
	o := &enableOnlyRelationObservation{ctx: ctx, until: time.Now().Add(time.Second)}
	if !o.ValidUntil().IsZero() || o.Recheck(ctx, nil, time.Now()) == nil {
		t.Fatal("detached observation accepted")
	}
	if _, e := o.MarshalJSON(); e == nil {
		t.Fatal("observation serialized into receipt")
	}
}
