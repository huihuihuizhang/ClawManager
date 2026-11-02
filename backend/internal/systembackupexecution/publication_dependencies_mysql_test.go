//go:build systembackup_mysql

package systembackupexecution

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync/atomic"
	"testing"

	kubefake "k8s.io/client-go/kubernetes/fake"
)

// The existing real SQL/original-owner fixture supplies actual deployment
// authority. Its already-existing task is not an input to this checker. This
// uses the old acceptance fixture so the known acceptance-only A task signing
// guard cannot be mistaken for proof that functional_test signing works.
// Kube/provider transports remain fixtures; no native/page success is claimed.
func TestPublicationDependenciesOriginalSourcesAndMissingProviderObservationMySQL(t *testing.T) {
	runPublicationDecisionOriginalRegistered(t, nil, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, _ *atomic.Int64) {
		s := f.service
		before := terminalFixtureSQL(t, ctx, f)
		network := terminalFixtureNetworkSnapshot(signer, artifact, catalog)
		client := s.Runtime.Owner.Client.(*kubefake.Clientset)
		checkUnchanged := func(t *testing.T, actionStart int) {
			t.Helper()
			if !reflect.DeepEqual(before, terminalFixtureSQL(t, ctx, f)) || network != terminalFixtureNetworkSnapshot(signer, artifact, catalog) {
				t.Fatal("taskless check changed original task or performed artifact/signing work")
			}
			for _, action := range client.Actions()[actionStart:] {
				if action.GetResource().Resource == "jobs" && action.GetVerb() != "get" && action.GetVerb() != "list" && action.GetVerb() != "watch" {
					t.Fatal("taskless checker sent or changed a Job")
				}
			}
		}
		t.Run("authenticated-sources-still-do-not-prove-provider-permission", func(t *testing.T) {
			start := len(client.Actions())
			observed, err := s.CheckPublicationDependencies(ctx)
			var dependency *PublicationDependencyError
			if !errors.Is(err, ErrPublicationProviderPermissionObservationMissing) || !errors.As(err, &dependency) || dependency.Dependency != "object-provider-permission-observation-unavailable" || observed.CheckedAt().IsZero() || !observed.CheckedAt().Before(observed.ValidUntil()) || observed.ValidUntil().After(s.Forward.DeploymentBinding().ExpiresAt) || len(observed.VerifiedSources()) != 7 || len(observed.RemainingChecks()) == 0 {
				t.Fatal("actual original dependencies or specific missing authority were lost", err)
			}
			checkUnchanged(t, start)
		})
		var materials PublicationSignerMaterials
		raw, err := pinnedDeploymentFile(s.publicationInput.File, s.publicationInput.SHA256, 1<<20)
		if err != nil || decodeProviderDeploymentJSON(raw, &materials) != nil {
			t.Fatal("actual original signer files", err)
		}
		for _, fault := range []struct{ name, path string }{
			{"original-signed-record-removed", materials.Record.RecordFile},
			{"projected-jwt-removed", materials.Mounts[1].JWTFile},
			{"independent-catalog-material-removed", s.publicationTarget.CatalogMaterialsFile},
			{"artifact-read-credential-removed", s.publicationTarget.ReadCredentialFile},
			{"candidate-delete-credential-removed", s.publicationTarget.DeleteCredentialFile},
		} {
			t.Run(fault.name, func(t *testing.T) {
				if fault.path == "" {
					t.Fatal("fixture missing actual dependency path")
				}
				held := fault.path + ".taskless-test-held"
				if err := os.Rename(fault.path, held); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Rename(held, fault.path); err != nil {
						t.Error(err)
					}
				}()
				start := len(client.Actions())
				observed, err := s.CheckPublicationDependencies(ctx)
				var dependency *PublicationDependencyError
				if err == nil || errors.Is(err, ErrPublicationProviderPermissionObservationMissing) || !errors.As(err, &dependency) || !observed.CheckedAt().IsZero() || !observed.ValidUntil().IsZero() {
					t.Fatal("removed real source was excused by later missing permission", err)
				}
				checkUnchanged(t, start)
			})
		}
		_ = registered // No original task proof is passed into the taskless entry.
	})
}
