package artifact

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCatalogRequiresAuthenticatedObjectsAndSignedPolicy(t *testing.T) {
	d, b, key, source := bundleFixture(t)
	b.Contract = &DomainContract{Version: "users-instances-contribution.v1", PolicySHA256: strings.Repeat("a", 64), RuntimePolicies: map[string]string{"instance-7": strings.Repeat("b", 64)}, Dependencies: []string{"ai_gateway", "skill_hub", "teams"}}
	publishFixture(t, d, b, key, source)
	source.Close()
	page, e := d.Scan(context.Background(), "", 10)
	if e != nil || len(page.Entries) != 1 || page.Entries[0].Contract.PolicySHA256 != b.Contract.PolicySHA256 {
		t.Fatal(e)
	}
	page, e = d.Scan(context.Background(), b.ID, 10)
	if e != nil || len(page.Entries) != 0 {
		t.Fatal("catalog cursor replay")
	}
	d.Root.Chmod(objectName(b.ID, "database"), 0600)
	f, e := d.Root.OpenFile(objectName(b.ID, "database"), os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.WriteAt([]byte("bad"), 0)
	f.Close()
	if _, e = d.Scan(context.Background(), "", 10); e == nil {
		t.Fatal("corrupt committed backup skipped")
	}
}
func TestContributionRejectsMissingRuntimeOrAssetsPart(t *testing.T) {
	_, b, _, _ := bundleFixture(t)
	b.Contract = &DomainContract{Version: "users-instances-contribution.v1", PolicySHA256: strings.Repeat("a", 64), RuntimePolicies: map[string]string{"instance-8": strings.Repeat("b", 64)}, Dependencies: []string{"ai_gateway", "skill_hub", "teams"}}
	if validBundle(b) {
		t.Fatal("substituted instance policy")
	}
	b.Contract.RuntimePolicies = map[string]string{"instance-7": strings.Repeat("b", 64)}
	b.Contract.Assets = true
	if validBundle(b) {
		t.Fatal("missing secret/object contribution")
	}
}
