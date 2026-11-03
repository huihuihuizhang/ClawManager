package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

func TestOriginalMinIOPreflightKeepsUnconstructedOwnersMissing(t *testing.T) {
	owners := sec.BootstrapOwnerAdapters{}
	if len(sec.MissingBootstrapOwnerAdapters(owners)) != 30 || len(missingBeforeOriginalMinIO(owners)) != 25 || len(sec.MissingBootstrapOwnerAdapters(owners)) != 30 {
		t.Fatal("preliminary filter manufactured installed owners")
	}
	if linked, original, err := addOriginalMinIOTerminal(owners, nil, install.BootstrapTerminalFiles{}, nil); err == nil || original != nil || linked.Candidates != nil {
		t.Fatal("absent original C owner became a terminal")
	}
}

func TestEnrolledProductionSelectsOriginalOwnersBeforeNativeCandidates(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "production.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"LinkFunctionalClassificationOwners", "NewEnrolledTerminalInstallationOwners", "LinkOriginalWindowSQLBootstrapKEK", "missingBeforeOriginalMinIO", "LinkSigningResourceConsumerOwners", "OpenTerminalKubernetes", "NewMinIOBootstrapTerminalResource", "addOriginalMinIOTerminal", "NativeHostDeploymentCandidates"}
	positions := map[string][]token.Pos{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		positions[name] = append(positions[name], call.Pos())
		return true
	})
	var previous token.Pos
	if len(positions["LinkOriginalSQLBootstrapKEK"]) != 0 {
		t.Fatal("old late KEK preparation remains in actual executable main")
	}
	for _, name := range names {
		if len(positions[name]) != 1 || positions[name][0] <= previous {
			t.Fatal("actual original composition missing, duplicated or reordered", name)
		}
		previous = positions[name][0]
	}
}
