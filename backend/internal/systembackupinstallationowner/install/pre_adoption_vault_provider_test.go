package install

import "testing"

func TestPreAdoptionVaultSelectionRejectsFutureAuthorityFields(t *testing.T) {
	for _, member := range []string{"ConfigRef", "Binding", "SourceMetadataGrant"} {
		t.Run(member, func(t *testing.T) {
			raw, e := canonical(map[string]any{"Workload": VaultProviderWorkloadSelection{}, "InstalledObserver": BootstrapSourceFilePin{}, member: map[string]string{"IdentityHash": "future"}})
			if e != nil {
				t.Fatal(e)
			}
			var input PreAdoptionVaultDependencySelection
			if decodeExact(raw, &input) == nil {
				t.Fatal("future authority field accepted as installed source input")
			}
		})
	}
}
