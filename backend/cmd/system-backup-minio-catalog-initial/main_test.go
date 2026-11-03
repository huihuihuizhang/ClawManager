package main

import (
	"context"
	"io"
	"testing"
)

func TestCatalogInitialInventoryCommandRequiresOriginalInputs(t *testing.T) {
	for _, a := range [][]string{nil, {"capture"}, {"publish"}, {"capture", "--insecure"}, {"current"}} {
		if run(context.Background(), a, io.Discard) != 2 {
			t.Fatal("invalid initial inventory input admitted")
		}
	}
}
