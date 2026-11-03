package install

import (
	"testing"
	"time"
)

// Bounded time arithmetic DATA models only; this does not construct a genuine
// holder, provider observation, history source or adoption capability.
func TestOriginalHistoryProviderLifetimeUsesShortestOriginalObservation(t *testing.T) {
	now := time.Now()
	for _, name := range []string{"native_shortest", "source_shortest", "missing_native", "missing_source", "expired_native", "nil_dependency"} {
		t.Run(name, func(t *testing.T) {
			dependency := &originalVaultProviderDependency{nativeUntil: now.Add(5 * time.Minute), sourceUntil: now.Add(10 * time.Minute)}
			set := &PreparedOriginalWriterSet{owner: &OriginalWriterMaintenance{until: now.Add(30 * time.Minute)}, providerDependencies: []*originalVaultProviderDependency{dependency}}
			want := dependency.nativeUntil
			switch name {
			case "source_shortest":
				dependency.sourceUntil = now.Add(time.Minute)
				want = dependency.sourceUntil
			case "missing_native":
				dependency.nativeUntil = time.Time{}
			case "missing_source":
				dependency.sourceUntil = time.Time{}
			case "expired_native":
				dependency.nativeUntil = now.Add(-time.Minute)
			case "nil_dependency":
				set.providerDependencies[0] = nil
			}
			got, err := originalAdoptionNativeUntil(&originalHeldReadiness{set: set, digest: "comparison-not-authority"})
			if name == "native_shortest" || name == "source_shortest" {
				if err != nil || !got.Equal(want) {
					t.Fatal("provider original cap omitted", got, err)
				}
			} else if err == nil {
				t.Fatal("missing/expired original dependency admitted")
			}
		})
	}
}
