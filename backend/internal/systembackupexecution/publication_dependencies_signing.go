package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

type publicationDependencySigning struct {
	publicationDependencyWindow
	recordSHA string
}

func (s *DeploymentService) checkPublicationDependencySigning(ctx context.Context, now time.Time) (publicationDependencySigning, error) {
	var zero publicationDependencySigning
	fail := func(stage string, err error) (publicationDependencySigning, error) {
		return zero, publicationDependencyFailure(stage, err)
	}
	g, r := s.Forward.DeploymentBinding(), s.publicationRuntime
	a := s.controllerActor
	if s.publisherVerifier == nil || r.InstallationID != g.InstallationID || r.ServerUUID != g.ServerUUID || r.Database != g.Database || r.PublisherOwner != s.PublisherOwner || r.Namespace != s.Config.Namespace || r.NamespaceUID != s.Config.NamespaceUID || r.PodName != a.PodName || r.PodUID != a.PodUID || r.ServiceAccountName != a.ServiceAccountName || r.ServiceAccountUID != s.publisherVerifier.Workload.ServiceAccountUID {
		return fail("current-signing-runtime-binding", nil)
	}
	// A's real constructor reauthenticates the original signed permissions,
	// actual SQL identity and actual Namespace/Pod/SA, without ForTask or login.
	factory, err := NewDeploymentPublicationSignerFactory(ctx, s.publicationDB, s.Runtime.Owner.Client, r, *s.publicationInput)
	if err != nil {
		return fail("current-signing-owner-and-workload", err)
	}
	if _, err = factory.History(ctx); err != nil {
		return fail("current-signing-public-history", err)
	}
	raw, err := pinnedDeploymentFile(s.publicationInput.File, s.publicationInput.SHA256, 1<<20)
	var materials PublicationSignerMaterials
	if err != nil || decodeProviderDeploymentJSON(raw, &materials) != nil || materials.Version != PublicationSignerMaterialsVersion {
		return fail("original-signing-material-binding", err)
	}
	return publicationDependencySigningFacts(ctx, materials, r, g, now)
}

// This consumes exact original-owner bytes and independently installed pins,
// never an imported observation DTO. It yields inert expiry facts only. The
// concrete constructor above owns transport/Kube/SQL validation; key history
// alone would deliberately allow expired SIGN permission and is insufficient.
func publicationDependencySigningFacts(ctx context.Context, materials PublicationSignerMaterials, runtime PublicationSignerRuntime, deployment c.ExecutionGrant, now time.Time) (publicationDependencySigning, error) {
	var out publicationDependencySigning
	fail := func(stage string, err error) (publicationDependencySigning, error) {
		return publicationDependencySigning{}, publicationDependencyFailure(stage, err)
	}
	history, err := security.LoadInstallationSigningHistory(ctx, materials.Record, materials.Pin)
	if err != nil {
		return fail("authenticated-original-signing-record", err)
	}
	raw, sig, err := materials.Record.ReadSigningRecord(ctx)
	if err != nil || hash(raw) != materials.Pin.RecordSHA256 || !ed25519.Verify(materials.Pin.Issuer, append([]byte(security.InstallationSigningDomain), raw...), sig) {
		return fail("current-original-signing-record", err)
	}
	var record security.InstallationSigningRecord
	if decodeProviderDeploymentJSON(raw, &record) != nil || record.InstallationID != deployment.InstallationID || record.InstallationID != runtime.InstallationID || record.Revision != materials.Pin.Revision || len(record.Permissions) != 3 || len(materials.Mounts) != 3 {
		return fail("original-signing-record-shape", nil)
	}
	if err = out.include(now, record.NotBefore, record.Until); err != nil {
		return fail("original-signing-permission-window", err)
	}
	permissions := map[string]security.InstallationSigningPermission{}
	for _, permission := range record.Permissions {
		purpose := permission.Binding.Purpose
		if !manifestOneOf(purpose, "capture_certificate", "acceptance_record", "catalog_record") || permissions[purpose].Binding.Purpose != "" {
			return fail("original-signing-purpose-set", nil)
		}
		permissions[purpose] = permission
	}
	seen := map[string]bool{}
	for _, mount := range materials.Mounts {
		purpose := mount.Binding.Purpose
		p, found := permissions[purpose]
		expected := security.SQLSigningOwnerGrant{ServerUUID: deployment.ServerUUID, Database: deployment.Database, DatabaseAccount: deployment.DatabaseAccount, ControllerOwner: runtime.PublisherOwner, ConfigVersion: deployment.ConfigVersion, ConfigSHA256: deployment.ConfigSHA256, Workload: security.SigningWorkloadIdentity{Namespace: runtime.Namespace, PodUID: runtime.PodUID, ServiceAccountUID: runtime.ServiceAccountUID}}
		if !found || seen[purpose] || mount.Binding.InstallationID != deployment.InstallationID || p.Binding != mount.Binding || p.AuthMount != mount.AuthMount || p.Role != mount.Role || p.Policy != mount.Policy || p.CASHA256 != mount.CASHA256 || p.SQLOwner == nil || !reflect.DeepEqual(*p.SQLOwner, expected) {
			return fail("original-signing-sql-owner-permission", nil)
		}
		seen[purpose] = true
		var key *security.ArtifactSigningPublicKey
		for _, k := range history.PurposeKeys(purpose) {
			if k.KeyID == mount.Binding.KeyID && k.KeyVersion == mount.Binding.KeyVersion {
				copy := k
				key = &copy
			}
		}
		if key == nil || key.Revoked {
			return fail("current-signing-key", nil)
		}
		if err = out.include(now, key.NotBefore, key.NotAfter); err != nil {
			return fail("original-signing-key-window", err)
		}
		if _, err = pinnedDeploymentFile(mount.CAFile, mount.CASHA256, 65536); err != nil {
			return fail("original-signing-ca", err)
		}
		jwt, err := readPrivate(mount.JWTFile, 16384)
		valid := err == nil && len(bytes.TrimSpace(jwt)) >= 16
		clear(jwt)
		if !valid {
			return fail("projected-signing-jwt-file", err)
		}
	}
	out.recordSHA = hash(raw)
	return out, nil
}
