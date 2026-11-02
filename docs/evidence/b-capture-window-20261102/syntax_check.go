// Syntax verification only. This does not replace Go package type checking.
package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
)

func main() {
	var files []string
	for _, name := range os.Args[1:] {
		if name == "--" {
			continue
		}
		if _, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.AllErrors|parser.ParseComments); err != nil {
			panic(err)
		}
		files = append(files, name)
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		SyntaxOnly bool     `json:"syntax_only"`
		Files      []string `json:"files"`
	}{true, files})
}
