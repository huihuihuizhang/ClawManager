package systembackup

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// Pure native-ACL rule semantics models, not Redis execution or source proof.
func TestRedisReadGateACLIntersectionPreservesDeniesAndSubcommands(t *testing.T) {
	all := map[string]bool{"get": true, "set": true, "del": true, "eval": true, "eval_ro": true, "acl": true, "acl|getuser": true, "acl|setuser": true}
	categories := map[string][]string{"read": {"get"}, "write": {"set", "del"}, "admin": {"acl|getuser", "acl|setuser"}}
	safe := map[string]bool{"get": true, "eval_ro": true}
	for _, tc := range []struct{ rules, want string }{{"+@all -get", "-@all +eval_ro"}, {"-@all +get -get +set", "-@all"}, {"-@all +get +eval_ro", "-@all +eval_ro +get"}, {"+@all -@write -@admin -eval -eval_ro", "-@all +get"}} {
		a, err := redisGateAllowed(tc.rules, all, categories)
		if err != nil {
			t.Fatal(err)
		}
		if result := redisGateReadCommands(a, safe); result != tc.want {
			t.Fatalf("intersection %q: got %q", tc.rules, result)
		}
	}
	a, err := redisGateAllowed("-@all +acl -acl|setuser", all, categories)
	if err != nil || !a["acl|getuser"] || a["acl|setuser"] {
		t.Fatal("parent/subcommand ACL semantics", err)
	}
	if _, err := redisGateAllowed("+@unknown", all, categories); err == nil {
		t.Fatal("unknown category granted")
	}
}

func TestRedisReadGateCannotMintFromEmptyCopyOrJSON(t *testing.T) {
	g := &RedisReadServiceGate{}
	if g.Recheck(context.Background()) == nil {
		t.Fatal("empty native handle")
	}
	if _, err := json.Marshal(g); err == nil {
		t.Fatal("native gate serialized as a caller proof")
	}
}

func TestRedisReadGateReadbackRejectsUnexpectedWriteAndSelectorGrants(t *testing.T) {
	g := &RedisReadServiceGate{commandNames: map[string]bool{"get": true, "set": true}, categories: map[string][]string{}}
	want := redisGateUser{Name: "original", Flags: []string{"on"}, redisGateSelector: redisGateSelector{Commands: "-@all +get", Keys: "~app:*"}}
	actual := want
	actual.Commands = "+get -set"
	if g.expectedUser(actual, want) != nil {
		t.Fatal("equivalent bounded read rule")
	}
	actual.Commands = "+get +set"
	if g.expectedUser(actual, want) == nil {
		t.Fatal("new hash with write grant accepted")
	}
	actual = want
	actual.Selectors = []redisGateSelector{{Commands: "+set", Keys: "~app:*"}}
	if g.expectedUser(actual, want) == nil {
		t.Fatal("selector OR bypass accepted")
	}
	args := redisGateSetUser(want, want.redisGateSelector, nil)
	if !reflect.DeepEqual(args[:5], [][]byte{[]byte("ACL"), []byte("SETUSER"), []byte("original"), []byte("resetcommands"), []byte("clearselectors")}) {
		t.Fatal("old selectors remained active")
	}
}
