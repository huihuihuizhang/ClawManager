package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestNetworkCaptureDecoderAcceptsOriginalResourceInvocationWithoutWorkspace(t *testing.T) {
	for _, secret := range []bool{false, true} {
		invocation, _, _ := resourceInvocationFixture(t, secret)
		raw, _ := json.Marshal(invocation)
		decoded, err := ReadInvocation(bytes.NewReader(raw))
		if err != nil || decoded.WorkspacePath != "" || !ValidateRecordedInvocation(decoded) {
			t.Fatal("production resource CLI decoder contradicted network capture contract", err)
		}
	}
}

func TestLegacyWorkspaceCannotBorrowSkillSourceSpec(t *testing.T) {
	r, env, _ := fixture(t)
	r.SkillObjects = &SkillObjectCaptureSpec{}
	if _, err := Run(context.Background(), r, env); err == nil {
		t.Fatal("mixed Skill source admitted through functional workspace path")
	}
}
