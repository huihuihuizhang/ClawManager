package install

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestLonghornSuccessorPreservesOriginalSelection(t *testing.T) {
	before := OriginalWriterSetSelection{Version: OriginalWriterSetSelectionVersion, ApplicationScope: "original-scope"}
	after := before
	after.LonghornHostDefinition = BootstrapSourceFilePin{File: "/private/original.json", SHA256: "pin"}
	after.LonghornKeeperImage = "image@sha256:pin"
	if !originalLonghornOnlySuccessor(before, after) {
		t.Fatal("exact two-field successor refused")
	}
	after.ApplicationScope = "changed"
	if originalLonghornOnlySuccessor(before, after) {
		t.Fatal("scope drift admitted")
	}
	after = before
	if originalLonghornOnlySuccessor(before, after) {
		t.Fatal("missing signed host input admitted")
	}
}
func TestLonghornContinuationCannotArriveInJSON(t *testing.T) {
	v := OriginalFirstAdoptionProductionInputs{}
	before, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	v.LonghornPreCold = func(context.Context, OriginalC1Head1Receipt) (BootstrapSourceFilePin, error) {
		return BootstrapSourceFilePin{}, nil
	}
	after, e := json.Marshal(v)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("callback changed original DATA wire", e)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(`{"LonghornPreCold":true}`))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&v) == nil {
		t.Fatal("caller JSON provided executable continuation")
	}
}
