package systembackupexecution

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSourceSecretSelectionAdmitsOnlyExactNames(t *testing.T) {
	s := productionResourceType{Part: "secret_bundle", Version: "v1", Resource: "secrets", FieldSelector: "metadata.name=clawmanager-secrets"}
	if !sourceMetadataFieldSelectorValid(s) {
		t.Fatal("approved exact Secret name rejected")
	}
	for _, field := range []string{"metadata.name!=foreign", "metadata.name=one,metadata.name=two", "metadata.name=", "metadata.namespace=foreign", "metadata.name=../foreign", "metadata.name=*", "metadata.name=one\n"} {
		v := s
		v.FieldSelector = field
		if sourceMetadataFieldSelectorValid(v) {
			t.Fatalf("unbounded selector accepted: %q", field)
		}
	}
	for _, fault := range []string{"part", "group", "version", "resource", "label"} {
		v := s
		switch fault {
		case "part":
			v.Part = "deployment_resources"
		case "group":
			v.Group = "apps"
		case "version":
			v.Version = "v2"
		case "resource":
			v.Resource = "configmaps"
		case "label":
			v.LabelSelector = "app=unrelated"
		}
		if sourceMetadataFieldSelectorValid(v) {
			t.Fatal("selector extended beyond exact Secret scope", fault)
		}
	}
	s.FieldSelector = ""
	raw, err := json.Marshal(s)
	if err != nil || strings.Contains(string(raw), "FieldSelector") {
		t.Fatal("legacy material encoding changed", err)
	}
}
