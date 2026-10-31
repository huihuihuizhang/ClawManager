package publicadapter

import (
	"bytes"
	"reflect"
	"testing"
)

func TestDescribePlanTransfersOnlyDetachedDecodedValues(t *testing.T) {
	f, _, plan := setup(t)
	canonical := bytes.Clone(plan.CanonicalJSON)
	original, err := DescribePlan(f.in, plan)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := DescribePlan(f.in, plan)
	if err != nil {
		t.Fatal(err)
	}
	changed.Source[0] = '!'
	changed.Writers[0].Original.Checkpoint = "caller-changed"
	changed.Parts[0].Intent.SpecJSON[0] = '!'
	changed.Parts[0].InvocationJSON[0] = '!'
	changed.Parts[0].InvocationConfigMap = "caller-changed"
	again, err := DescribePlan(f.in, plan)
	if err != nil || !reflect.DeepEqual(again, original) || !bytes.Equal(plan.CanonicalJSON, canonical) {
		t.Fatal("caller mutation changed original plan or another detached observation", err)
	}
}
