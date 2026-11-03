package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestEnrolledCrossResourceBindingComesFromActualConstructor(t *testing.T) {
	var output bytes.Buffer
	if code := runEnrolled(context.Background(), []string{"--cross-resource-binding"}, &output); code != 0 {
		t.Fatal("actual constructor binding", code)
	}
	var actual install.BootstrapOriginalOwnerBinding
	if json.Unmarshal(output.Bytes(), &actual) != nil || actual.Key != "cross_resources" {
		t.Fatal("binding wire")
	}
	resource, e := install.NewOriginalCrossResourceRelations(install.NewCaptureSigningConsumer(enrolledCaptureSource, enrolledCapturePin))
	if e != nil {
		t.Fatal(e)
	}
	expected, e := resource.BindingSHA256()
	if e != nil || actual.SHA256 != expected {
		t.Fatal("caller-provided binding replaced concrete source")
	}
	output.Reset()
	if code := runEnrolled(context.Background(), []string{"--cross-resource-binding", "--apply"}, &output); code == 0 {
		t.Fatal("binding output became mutation authority")
	}
}
