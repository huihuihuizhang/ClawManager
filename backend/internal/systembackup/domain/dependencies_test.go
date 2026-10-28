package domain

import (
	"context"
	"testing"
)

func TestDependencyRowsSurviveNormalizationAndDanglingLinksFail(t *testing.T) {
	s, target, p := fixture()
	model := table("llm_models", Row{"id": Text("1"), "is_active": Text("1"), "api_key": Text("original-secret"), "base_url": Text("https://source.invalid"), "api_key_secret_ref": Text("ns/model:key")})
	session := table("chat_sessions", Row{"id": Text("1"), "session_id": Text("session"), "user_id": Text("4"), "instance_id": Text("7"), "title": Text("history")})
	message := table("chat_messages", Row{"id": Text("1"), "session_id": Text("session"), "content": Text("original conversation"), "role": Text("user"), "invocation_id": Text("991")})
	s.Tables = append(s.Tables, model, session, message)
	target = append(target, model, session, message)
	plan, e := Normalize(context.Background(), s, target, p)
	if e != nil {
		t.Fatal(e)
	}
	if find(plan.Data, "chat_messages").Rows[0]["content"].String() != "original conversation" || find(plan.Data, "llm_models").Rows[0]["is_active"].String() != "0" || find(s, "llm_models").Rows[0]["api_key"].String() != "original-secret" {
		t.Fatal("source changed or dependency lost")
	}
	message.Rows[0]["session_id"] = Text("missing")
	if _, e := Normalize(context.Background(), s, target, p); e == nil {
		t.Fatal("dangling session accepted")
	}
}
func TestWorkBuddyIdentityRequiresExactSchemaAndStableOwnership(t *testing.T) {
	s, target, p := fixture()
	for i := range s.Tables {
		if s.Tables[i].Name == "instances" {
			s.Tables[i].Rows[0]["type"] = Text("workbuddy")
			s.Tables[i].Rows[0]["workbuddy_storage_identity"] = Text("stable-storage")
			s.Tables[i].Columns = append(s.Tables[i].Columns, Column{Name: "workbuddy_storage_identity", Type: "varchar(255)", Nullable: true})
			target[i] = s.Tables[i]
		}
	}
	w := table("workbuddy_linux_identities", Row{"id": Text("3"), "instance_id": Text("7"), "storage_identity": Text("stable-storage"), "linux_uid": Text("4001"), "linux_gid": Text("4001")})
	s.Tables = append(s.Tables, w)
	target = append(target, w)
	if _, e := Normalize(context.Background(), s, target, p); e == nil {
		t.Fatal("guessed unknown WorkBuddy schema")
	}
	p.WorkBuddy = &WorkBuddySchema{Version: "fixture-branch-v1", SHA256: SchemaDigest(w), Instance: "instance_id", StorageIdentity: "storage_identity", UID: "linux_uid", GID: "linux_gid"}
	plan, e := Normalize(context.Background(), s, target, p)
	if e != nil {
		t.Fatal(e)
	}
	if find(plan.Data, w.Name).Rows[0]["linux_uid"].String() != "4001" {
		t.Fatal("reallocated Linux identity")
	}
	w.Rows[0]["linux_uid"] = Text("0")
	if _, e = Normalize(context.Background(), s, target, p); e == nil {
		t.Fatal("privileged ownership accepted")
	}
}

func TestWorkBuddyWithoutIdentityLayoutDoesNotPretendToBeLegacy(t *testing.T) {
	s, target, p := fixture()
	s.Tables[2].Rows[0]["type"] = Text("workbuddy")
	if _, e := Normalize(context.Background(), s, target, p); e == nil {
		t.Fatal("missing WorkBuddy identity schema was accepted")
	}
}
func TestDependencyAdapterRejectsSchemaDrift(t *testing.T) {
	table := table("teams", Row{"id": Text("1"), "status": Text("running")})
	a := TableAdapter{SchemaSHA256: SchemaDigest(table), Columns: map[string]string{"id": "preserve", "status": "fixed:stopped"}}
	if a.validate(table) != nil {
		t.Fatal("valid adapter rejected")
	}
	table.Columns = append(table.Columns, Column{Name: "new_execution_field"})
	if a.validate(table) == nil {
		t.Fatal("uncovered execution column accepted")
	}
}
