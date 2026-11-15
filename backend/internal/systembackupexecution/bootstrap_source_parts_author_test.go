package systembackupexecution

import (
	"reflect"
	"testing"

	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

func TestBootstrapPartsPreSigningMatchesOperationalSuccessor(t *testing.T) {
	_, source, _, _, operations := productionModuleFixture(t)
	source.Instances = nil
	source.TeamFacts.Teams = nil
	source.Teams = nil
	delete(operations, ce.Operation)
	delete(operations, cd.Operation)
	x := &bootstrapSourceRegistryReader{access: &install.BootstrapSourceRegistryAuthoring{}, materials: productionCaptureMaterials{Operations: operations}}
	facts := &bootstrapSourceSQLFacts{inventory: source}
	before, err := x.deriveParts(facts, nil)
	if err != nil {
		t.Fatal("pre-signing facts rejected", err)
	}
	counts := map[string]int{}
	for _, part := range before {
		counts[part.Part]++
	}
	for _, part := range []string{ce.Part, ce.ProofPart, cd.Part} {
		if counts[part] != 1 {
			t.Fatalf("missing or duplicate reserved part %s", part)
		}
	}
	// A normal enrolled reader cannot use the unsigned authoring exception.
	x.access = nil
	if _, err := x.deriveParts(facts, nil); err == nil {
		t.Fatal("missing control operation accepted by enrolled reader")
	}
	operations[ce.Operation] = productionCaptureOperation{}
	operations[cd.Operation] = productionCaptureOperation{}
	after, err := x.deriveParts(facts, nil)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("operational successor changed registered parts", err)
	}
	// The authoring exception is finite: business capture operations remain required.
	x.access = &install.BootstrapSourceRegistryAuthoring{}
	delete(operations, "capture-database")
	if _, err := x.deriveParts(facts, nil); err == nil {
		t.Fatal("author accepted missing business capture operation")
	}
}
