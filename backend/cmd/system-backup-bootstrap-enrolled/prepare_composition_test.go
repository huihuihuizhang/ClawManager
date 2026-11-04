package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"clawreef/internal/systembackupinstallationowner/install"
)

func TestPrepareCompositionRequiresOriginalInputsBeforeOutputs(t *testing.T) {
	directory := t.TempDir()
	var output bytes.Buffer
	if runPrepareComposition(context.Background(), []string{"--output-directory", directory}, &output) != 2 {
		t.Fatal("missing original producer inputs accepted")
	}
	entries, e := os.ReadDir(directory)
	if e != nil || len(entries) != 0 || output.Len() != 0 {
		t.Fatal("missing source created an output or native result")
	}
}

func TestCompositionProducerReaderAcceptsExactPinnedNativeStdout(t *testing.T) {
	file := filepath.Join(t.TempDir(), "producer.json")
	raw := []byte("{\"Version\":\"native-result\"}\n")
	if os.WriteFile(file, raw, 0600) != nil {
		t.Fatal("write")
	}
	var value struct{ Version string }
	actual, e := readCompositionProducer(install.BootstrapSourceFilePin{File: file, SHA256: assemblySHA(raw)}, &value)
	if e != nil || !bytes.Equal(actual, raw) || value.Version != "native-result" {
		t.Fatal("native stdout receipt newline or exact bytes were changed")
	}
}

func TestCompositionProducerReaderRejectsDuplicateOrUnknownFields(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"Version":"first","Version":"replacement"}`), []byte(`{"Version":"native","Passed":true}`)} {
		file := filepath.Join(t.TempDir(), "producer.json")
		if os.WriteFile(file, raw, 0600) != nil {
			t.Fatal("write")
		}
		var value struct{ Version string }
		if _, e := readCompositionProducer(install.BootstrapSourceFilePin{File: file, SHA256: assemblySHA(raw)}, &value); e == nil {
			t.Fatal("ambiguous or foreign source field accepted")
		}
	}
}

func TestCompositionProducerReaderRejectsChangedOriginalPin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "producer.json")
	before, after := []byte(`{"Version":"first"}`), []byte(`{"Version":"changed"}`)
	if os.WriteFile(file, after, 0600) != nil {
		t.Fatal("write")
	}
	if _, e := readCompositionProducer(install.BootstrapSourceFilePin{File: file, SHA256: assemblySHA(before)}, nil); e == nil {
		t.Fatal("changed retained producer bytes accepted")
	}
}

func TestCompositionPrepareOutputIsCreateOnly(t *testing.T) {
	file := filepath.Join(t.TempDir(), "composition.json")
	first := []byte(`{"state":"original"}`)
	if compositionWriteNew(file, first) != nil || compositionWriteNew(file, []byte(`{"state":"replacement"}`)) == nil {
		t.Fatal("composition output was not create-only")
	}
	actual, e := os.ReadFile(file)
	if e != nil || !bytes.Equal(actual, first) {
		t.Fatal("original partial output was overwritten")
	}
}
