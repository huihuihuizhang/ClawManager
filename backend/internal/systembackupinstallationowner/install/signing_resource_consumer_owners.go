package install

import (
	"context"
	"reflect"

	sec "clawreef/internal/systembackupsecurity"
)

// Actual main composition: base must be original's same concrete pointer map.
// Preserve independent KEK preparation, reject an already attached candidate,
// and retain one real A owner under both aliases. Keep the handle open through
// the entire attempt. No resource preparation/provider probe occurs here.
func LinkSigningResourceConsumerOwners(ctx context.Context, base sec.BootstrapOwnerAdapters, original *BootstrapTerminalOriginal, sourceFile, sourcePinFile, expectedSHA string) (sec.BootstrapOwnerAdapters, *BootstrapTerminalOriginal, *SigningResourceConsumer, error) {
	bad := func() (sec.BootstrapOwnerAdapters, *BootstrapTerminalOriginal, *SigningResourceConsumer, error) {
		return sec.BootstrapOwnerAdapters{}, nil, nil, ErrInstall
	}
	if original == nil || base.Candidates != nil {
		return bad()
	}
	expected, err := original.Owners()
	if err != nil || len(base.Registries) != len(expected.Registries) || len(base.References) != len(expected.References) {
		return bad()
	}
	same := func(a, b any) bool {
		if a == nil || b == nil {
			return a == nil && b == nil
		}
		return reflect.TypeOf(a) == reflect.TypeOf(b) && reflect.TypeOf(a).Kind() == reflect.Pointer && reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer() && !reflect.ValueOf(a).IsNil()
	}
	for key, resource := range expected.Registries {
		if !same(base.Registries[key], resource) {
			return bad()
		}
	}
	for key, resource := range expected.References {
		if !same(base.References[key], resource) {
			return bad()
		}
	}
	if !same(base.CrossResources, expected.CrossResources) {
		return bad()
	}
	consumer, err := OpenPinnedSigningResourceConsumer(ctx, sourceFile, sourcePinFile, expectedSHA)
	if err != nil {
		return bad()
	}
	terminal, signers, err := original.WithSigningResourceConsumer(consumer)
	if err != nil {
		consumer.Close()
		return bad()
	}
	linked, err := terminal.Owners()
	if err != nil || linked.References["acceptance_signing"] != signers || linked.References["catalog_signing"] != signers {
		consumer.Close()
		return bad()
	}
	linked.KEK = base.KEK
	return linked, terminal, consumer, nil
}
