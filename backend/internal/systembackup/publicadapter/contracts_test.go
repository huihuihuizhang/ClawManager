package publicadapter

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestPublicAdapterHasNoPrivateControlOrPublicationImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, forbidden := range []string{"/systembackup/control", "/systembackup/host", "/systembackup/profile", "/systembackup/recovery", "/systembackup/artifact"} {
				if strings.Contains(p, forbidden) {
					t.Fatalf("%s imports private control/publication path %s", path, p)
				}
			}
		}
	}
}

func TestAllMandatoryOwnerInputsRejectIndividuallyWhenMissing(t *testing.T) {
	_, r, _ := setup(t)
	base := r.(*runner).deps
	for _, name := range []string{"profiles", "results", "recovery", "admission", "inventory", "timeout"} {
		t.Run(name, func(t *testing.T) {
			deps := base
			switch name {
			case "profiles":
				deps.Profiles = nil
			case "results":
				deps.Results = nil
			case "recovery":
				deps.Recovery = nil
			case "admission":
				deps.Admission = nil
			case "inventory":
				deps.ValidateInventory = nil
			case "timeout":
				deps.RecoveryTimeout = 0
			}
			if _, err := NewPublicRunner(deps); err == nil {
				t.Fatal("missing owner input accepted")
			}
		})
	}
}

func TestCheckpointAndTargetCandidatesDescribeActualFields(t *testing.T) {
	for _, which := range []struct {
		name string
		typ  reflect.Type
	}{{"checkpoint", reflect.TypeOf(Checkpoint{})}, {"restore-target", reflect.TypeOf(RestoreTarget{})}} {
		raw, err := os.ReadFile("../../../../contracts/system-backup/b-candidates/" + which.name + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		}
		if json.Unmarshal(raw, &schema) != nil {
			t.Fatal("bad schema")
		}
		if len(schema.Required) != which.typ.NumField() || len(schema.Properties) != which.typ.NumField() {
			t.Fatal("candidate fields drifted", which.name)
		}
		for i := 0; i < which.typ.NumField(); i++ {
			if schema.Properties[which.typ.Field(i).Tag.Get("json")] == nil {
				t.Fatal("missing candidate field", which.typ.Field(i).Name)
			}
		}
	}
}

func TestBErrorCategoriesRemainInPublicV12Enum(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/system-backup/v12/status-failure-enums.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid public enum")
	}
	defs := doc["$defs"].(map[string]any)
	values := defs["FailureCategory"].(map[string]any)["enum"].([]any)
	known := map[string]bool{}
	for _, v := range values {
		known[v.(string)] = true
	}
	for category := range failureCategories {
		if !known[category] {
			t.Fatalf("invented public failure category %s", category)
		}
	}
}

func TestRelayCandidateSchemaMatchesActualWireProperties(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/system-backup/b-candidates/status-relay.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid candidate schema")
	}
	wire := reflect.TypeOf(RelayMessage{})
	fields := map[string]bool{}
	for i := 0; i < wire.NumField(); i++ {
		fields[wire.Field(i).Tag.Get("json")] = true
	}
	if len(fields) != len(doc.Properties) || len(fields) != len(doc.Required) {
		t.Fatal("candidate wire properties drifted")
	}
	for _, k := range doc.Required {
		if !fields[k] || doc.Properties[k] == nil {
			t.Fatal("candidate schema does not describe encoder", k)
		}
	}
}
