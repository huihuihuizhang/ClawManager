package quiesce

import (
	"testing"
	"time"
)

func TestOriginalTenantNamespaceBindingCannotChangeDuringRecovery(t *testing.T) {
	for _, action := range []string{"recovery-source-stopped", "recovery-reconciled"} {
		t.Run(action, func(t *testing.T) {
			o, request, anchor := scopedRecoveryData(t, action)
			request.Binding.AdditionalNamespaces = []ObservationNamespace{{Name: "tenant", UID: "tenant-uid"}}
			anchor.Binding = request.Binding
			token, err := o.seal(anchor)
			if err != nil {
				t.Fatal(err)
			}
			request.Anchor = token
			if _, err := o.originalNodeObservationAnchor(request, time.Now()); err != nil {
				t.Fatal(err)
			}
			if !observationNamespaceAllowed(request.Binding, "tenant") || observationNamespaceAllowed(request.Binding, "foreign") {
				t.Fatal("namespace scope lost")
			}
			request.Binding.AdditionalNamespaces[0].UID = "recreated-tenant"
			if _, err := o.originalNodeObservationAnchor(request, time.Now()); err == nil {
				t.Fatal("namespace recreation accepted against original seal")
			}
		})
	}
}

func TestOriginalNamespaceBindingRejectsAmbiguousScope(t *testing.T) {
	b := ObservationBinding{Namespace: "system", NamespaceUID: "system-uid"}
	for _, scopes := range [][]ObservationNamespace{
		{{Name: "tenant", UID: ""}},
		{{Name: "system", UID: "other"}},
		{{Name: "tenant", UID: "system-uid"}},
		{{Name: "tenant", UID: "one"}, {Name: "tenant", UID: "two"}},
		{{Name: "b", UID: "b"}, {Name: "a", UID: "a"}},
		{{Name: "a", UID: "same"}, {Name: "b", UID: "same"}},
	} {
		b.AdditionalNamespaces = scopes
		if validObservationNamespaces(b) {
			t.Fatal("ambiguous namespace binding accepted", scopes)
		}
	}
}

func TestNodeObservationResponseDoesNotExposeNamespaceProofStorage(t *testing.T) {
	b := ObservationBinding{AdditionalNamespaces: []ObservationNamespace{{Name: "tenant", UID: "original"}}}
	v := &VerifiedNodeObservation{response: NodeObservationResponse{Binding: b}}
	response := v.Response()
	response.Binding.AdditionalNamespaces[0].UID = "changed"
	if v.Response().Binding.AdditionalNamespaces[0].UID != "original" {
		t.Fatal("opaque proof mutated through response")
	}
}
