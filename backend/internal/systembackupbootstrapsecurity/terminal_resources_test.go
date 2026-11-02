package systembackupbootstrapsecurity

import (
	"context"
	"testing"
)

func TestTerminalRegistryCopyAndWrongContextCannotReviveOriginal(t *testing.T) {
	for _, mode := range []string{"copy", "foreign_context", "nil"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, nil, nil)
			ctx := context.Background()
			prepared, err := f.validator.PrepareTerminalResource(ctx, f.grant, f.config)
			if err != nil {
				t.Fatal(err)
			}
			original := prepared.(*registryTerminalCheck)
			switch mode {
			case "copy":
				copy := *original
				if _, err := copy.AuthorizeIdentity(ctx, nil); err == nil {
					t.Fatal("copied registry owner accepted")
				}
			case "foreign_context":
				if _, err := original.AuthorizeIdentity(context.WithValue(ctx, struct{}{}, true), nil); err == nil {
					t.Fatal("foreign context accepted")
				}
			case "nil":
				if _, err := original.AuthorizeIdentity(nil, nil); err == nil {
					t.Fatal("nil context accepted")
				}
			}
			if !original.failed || original.DependencyDeadline() != nil || original.RecheckIdentity(ctx, nil) == nil {
				t.Fatal("restored input revived failed original registry owner")
			}
		})
	}
}
