package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const minimalInput = `{"orchestrator":"kubernetes","profile":"cluster","total_users":1,"total_instances":0,"users":[{"id":1,"role":"admin","has_password_hash":true}],"instances":[]}`

func TestOfflineInventoryProducesUsableJSON(t *testing.T) {
	var output bytes.Buffer
	if err := run(nil, strings.NewReader(minimalInput), &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Fingerprint string `json:"fingerprint"`
		Inventory   struct {
			UserIDs          []int  `json:"user_ids"`
			TargetPowerState string `json:"target_power_state"`
		} `json:"inventory"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Fingerprint) != 64 || len(result.Inventory.UserIDs) != 1 || result.Inventory.TargetPowerState != "stopped" {
		t.Fatalf("incomplete inventory output: %s", output.String())
	}
}

func TestOfflineInventoryRejectsSecretInputAndAdditionalDocuments(t *testing.T) {
	for _, input := range []string{
		strings.Replace(minimalInput, `"has_password_hash":true`, `"has_password_hash":true,"password_hash":"private-password-hash"`, 1),
		minimalInput + `{}`,
		minimalInput + strings.Repeat(" ", maxInputBytes),
		`null`,
	} {
		var output bytes.Buffer
		err := run(nil, strings.NewReader(input), &output)
		if err == nil || output.Len() != 0 {
			t.Fatal("invalid input produced a successful partial inventory")
		}
		if strings.Contains(err.Error(), "private-password-hash") {
			t.Fatal("input secret leaked into diagnostic")
		}
	}
}
