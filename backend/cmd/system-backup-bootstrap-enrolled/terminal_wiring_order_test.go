package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// Structural regression for the actual production route and A's actual
// callback bodies. This guards the lock-prefix inversion that a generic
// capture/Materials wrapper introduced. It is not a native locking test.
func TestEnrolledProductionPassesDirectTerminalAndPreservesCapturePrefixOrder(t *testing.T) {
	parse := func(file string) *ast.File {
		t.Helper()
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	production := parse("production.go")
	direct := 0
	ast.Inspect(production, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if selector.Sel.Name == "CandidateAuthority" {
			t.Fatal("production installed legacy capture wrapper")
		}
		if selector.Sel.Name == "NativeHostDeploymentCandidates" {
			if len(call.Args) != 2 {
				t.Fatal("candidate constructor shape")
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || receiver.Name != "original" {
				t.Fatal("actual native candidates do not use the same concrete terminal")
			}
			input, ok := call.Args[1].(*ast.SelectorExpr)
			if !ok || input.Sel.Name != "NativeHost" {
				t.Fatal("actual candidate branch omitted mandatory signed native host source")
			}
			composition, ok := input.X.(*ast.Ident)
			if !ok || composition.Name != "d" {
				t.Fatal("native host source is not the independently pinned composition input")
			}
			direct++
		}
		return true
	})
	if direct != 1 {
		t.Fatal("actual production direct candidate route missing/duplicated")
	}
	assembly := parse(filepath.Join("..", "..", "internal", "systembackupbootstrapmaterials", "installation_terminal.go"))
	ast.Inspect(assembly, func(node ast.Node) bool {
		switch v := node.(type) {
		case *ast.CallExpr:
			if selector, ok := v.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "CandidateAuthority" {
				t.Fatal("terminal assembly reintroduced capture wrapper")
			}
		case *ast.CompositeLit:
			if name, ok := v.Type.(*ast.Ident); ok && name.Name == "Materials" {
				t.Fatal("terminal assembly reintroduced Materials candidate route")
			}
		}
		return true
	})
	terminal := parse(filepath.Join("..", "..", "internal", "systembackupinstallationowner", "install", "terminal_original.go"))
	checkOrder := func(function, prefix, resource string) {
		t.Helper()
		found := false
		for _, declaration := range terminal.Decls {
			f, ok := declaration.(*ast.FuncDecl)
			if !ok || f.Name.Name != function {
				continue
			}
			found = true
			var first, later token.Pos
			prefixCount, resourceCount := 0, 0
			ast.Inspect(f.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if selector.Sel.Name == prefix {
					first = call.Pos()
					prefixCount++
				}
				if selector.Sel.Name == resource {
					later = call.Pos()
					resourceCount++
				}
				return true
			})
			if prefixCount != 1 || resourceCount != 1 || first >= later {
				t.Fatalf("%s must enter capture once before concrete resource loop", function)
			}
		}
		if !found {
			t.Fatal("actual terminal callback missing", function)
		}
	}
	checkOrder("PrepareBootstrapCandidates", "PrepareCandidateAttempt", "PrepareTerminalResource")
	checkOrder("Authorize", "AuthorizeCandidate", "AuthorizeIdentity")
}
