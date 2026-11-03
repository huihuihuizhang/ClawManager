package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	sec "clawreef/internal/systembackupsecurity"
)

func TestEnrolledSignerPreflightNeverCountsPendingOwners(t *testing.T) {
	owners := sec.BootstrapOwnerAdapters{}
	before := sec.MissingBootstrapOwnerAdapters(owners)
	remaining := missingBeforeOriginalSigningResources(missingBeforeOriginalMinIO(owners))
	if len(before) != 30 || len(remaining) != 23 || len(sec.MissingBootstrapOwnerAdapters(owners)) != 30 || len(missingBeforeOriginalMinIOAfterSigning(owners)) != 25 {
		t.Fatal("unopened signers counted as concrete or late gate ignored them")
	}
	for _, key := range missingBeforeOriginalMinIOAfterSigning(owners) {
		if key == "reference:acceptance_signing" || key == "reference:catalog_signing" {
			return
		}
	}
	t.Fatal("post-construction gate lost absent signer aliases")
}

// The actual linker is positively exercised after authenticated Export->Load
// in install's component regression. Here inspect the executable main call,
// proving the actual original KEK bridge precedes signer/C use and survives
// the complete-owner gate before original native host candidate composition.
func TestEnrolledMainPreservesOriginalKEKBeforeSignerAndC(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "production.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"LinkOriginalStatusRelayOwners", "NewEnrolledTerminalInstallationOwners", "LinkOriginalWindowSQLBootstrapKEK", "missingBeforeOriginalSigningResources", "LinkSigningResourceConsumerOwners", "missingBeforeOriginalMinIOAfterSigning", "OpenTerminalKubernetes", "NewMinIOBootstrapTerminalResource", "addOriginalMinIOTerminal", "NativeHostDeploymentCandidates"}
	positions := map[string][]token.Pos{}
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			positions[name] = append(positions[name], call.Pos())
		}
		return true
	})
	var previous token.Pos
	for _, name := range names {
		if len(positions[name]) != 1 || positions[name][0] <= previous {
			t.Fatal("actual main signer/C/KEK/host call missing or reordered", name)
		}
		previous = positions[name][0]
	}
}
