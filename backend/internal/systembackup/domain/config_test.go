package domain

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigRegistryStubsSecretsDisablesTasksAndPreservesDefinitions(t *testing.T) {
	r := JSONRegistry{"workbuddy.config": {{Path: []string{"model"}, Action: "preserve", Required: true}, {Path: []string{"apiKey"}, Action: "stub", Required: true}, {Path: []string{"tasks", "*", "enabled"}, Action: "disable", Required: true}, {Path: []string{"tasks", "*", "prompt"}, Action: "preserve", Required: true}}}
	source := Text(`{"model":"fixture-model","apiKey":"source-private-key","tasks":[{"enabled":true,"prompt":"keep this definition"}]}`)
	n, e := r.NormalizeJSON(context.Background(), "workbuddy.config", source)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(n.String(), "source-private-key") || !strings.Contains(n.String(), "keep this definition") {
		t.Fatal("credentials or definitions mishandled")
	}
	var data map[string]any
	json.Unmarshal(n.Bytes, &data)
	if data["tasks"].([]any)[0].(map[string]any)["enabled"].(bool) {
		t.Fatal("task enabled")
	}
	for _, s := range []string{`{"model":"x","apiKey":"x","newSecret":"secret"}`, `{"model":"x","apiKey":"x","tasks":[]}`, `{"model":"x","apiKey":5,"tasks":[{"enabled":true,"prompt":"x"}]}`} {
		if _, e = r.NormalizeJSON(context.Background(), "workbuddy.config", Text(s)); e == nil {
			t.Fatal("unknown or incomplete config accepted")
		}
	}
	if _, e = r.NormalizeJSON(context.Background(), "workbuddy.config", Text(`{"model":"x","model":"y","apiKey":"x","tasks":[{"enabled":true,"prompt":"x"}]}`)); e == nil {
		t.Fatal("duplicate JSON key accepted")
	}
}
