package install

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"encoding/json"
	"testing"
)

func TestEnableOnlyOriginalMappingCannotUseBootstrapTransportAsWriteAuthority(t *testing.T) {
	capture, files, _ := terminalSevenConcreteSources(t)
	files.SignatureFile += ".signature"
	source, e := NewEnableOnlyOriginalMapping(capture, files)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := source.PrepareEnableOnly(context.Background(), sec.ConfigMutationResourceInput{}, []BootstrapOriginalOwnerBinding{{Key: "reference:artifact_ca", SHA256: files.MappingSHA256}}); e == nil {
		t.Fatal("missing actual mutation input accepted")
	}
	if _, e := source.PrepareEnableOnly(context.Background(), sec.ConfigMutationResourceInput{}, nil); e == nil {
		t.Fatal("missing concrete bindings accepted")
	}
	if _, e := json.Marshal(&PreparedEnableOnlyOriginalMapping{}); e == nil {
		t.Fatal("mapping check serialized into approval")
	}
}
