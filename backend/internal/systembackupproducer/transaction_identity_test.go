package systembackupproducer

import (
	"database/sql"
	"testing"
)

func TestSameGuardedTransactionRejectsCopiesAndOtherTransactions(t *testing.T) {
	a, b := new(sql.Tx), new(sql.Tx)
	w := &Transaction{tx: a}
	w.identity = w
	var fault error
	if !SameGuardedTransaction(w, readSQL{tx: a, fault: &fault}) {
		t.Fatal("original read view rejected after work closes")
	}
	if SameGuardedTransaction(w, readSQL{tx: b, fault: &fault}) || SameGuardedTransaction(w, nil) || SameGuardedTransaction(nil, readSQL{tx: a, fault: &fault}) {
		t.Fatal("other transaction/view accepted")
	}
	copy := *w
	if SameGuardedTransaction(&copy, readSQL{tx: a, fault: &fault}) {
		t.Fatal("copied write capability accepted")
	}
	if SameGuardedTransaction(w, readSQL{tx: a, fault: &fault}) {
		t.Fatal("copy misuse did not latch original failure")
	}
}
