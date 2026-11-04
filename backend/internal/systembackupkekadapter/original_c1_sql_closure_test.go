package systembackupkekadapter

import (
	"context"
	"testing"
)

func TestOriginalC1SQLClosureRejectsMissingProducerAndOriginalTransaction(t *testing.T) {
	if c, e := PrepareOriginalC1SQLClosure(context.Background(), nil, nil); e == nil || c != nil {
		t.Fatal("no original producer/tx accepted")
	}
	for _, c := range []*OriginalC1SQLClosure{nil, {}} {
		if _, e := c.ReadCurrent(context.Background(), nil); e == nil {
			t.Fatal("unminted closure accepted")
		}
	}
}
