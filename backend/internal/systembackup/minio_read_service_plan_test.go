package systembackup

import (
	"fmt"
	"testing"
)

func TestMinIOReadServicePlanReservesWholeOriginalRestore(t *testing.T) {
	g := &MinIOReadServiceGate{credentials: [3]MinIOGateCredential{{AccessKey: "root"}, {AccessKey: "keeper"}, {AccessKey: "reader"}}, in: MinIOReadGateInput{OutputAccounts: []string{"publication"}}}
	original := &minioGateOriginal{RootAccess: "on", BucketPolicies: map[string]string{"business": "original-anonymous-policy"}}
	for i := 0; i < 498; i++ {
		original.Users = append(original.Users, minioGateUser{Name: fmt.Sprintf("old-%d", i), Status: "enabled"})
	}
	if !g.planFits(original) {
		t.Fatal("exactly500 acquire plus500 restore slots must fit")
	}
	original.Users = append(original.Users, minioGateUser{Name: "overflow", Status: "enabled"})
	if g.planFits(original) {
		t.Fatal("partial acquisition could strand original recovery beyond1000 journal slots")
	}
	original.Users[len(original.Users)-1].Status = "disabled"
	for _, name := range []string{"keeper", "reader", "publication"} {
		original.Users = append(original.Users, minioGateUser{Name: name, Status: "enabled"})
	}
	if !g.planFits(original) {
		t.Fatal("unchanged/kept identities consumed mutation slots")
	}
	if g.planFits(nil) {
		t.Fatal("missing original state supplied a plan")
	}
}
