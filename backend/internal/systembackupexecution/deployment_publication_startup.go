package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"time"

	c "clawreef/internal/systembackupcontroller"
	s "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Only path/protocol are in the parent core hash. The derived material's hash
// is delivered separately at startup after core/Forward records are frozen.
type PublicationSignerReference struct {
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}
type DeploymentStartupInputs struct {
	FormalVerifier     []FormalVerifierInput
	PublicationSigners []PublicationSignerInput
	PublisherVerifier  []PublisherVerifierInput
	ControllerPodName  string
	CaptureModules     []ProductionCaptureInput
}

func (r PublicationSignerReference) validate() error {
	if r.Protocol != PublicationSignerMaterialsVersion || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (d *DeploymentService) publicationBinding() error {
	if d == nil || !d.ForwardEnabled || d.Forward == nil {
		return c.ErrExecutionAuthority
	}
	loaded, err := LoadDeploymentConfig(d.ConfigPath, d.ConfigDigest)
	if err != nil || !reflect.DeepEqual(loaded, d.Config) {
		return c.ErrExecutionAuthority
	}
	g := d.Forward.DeploymentBinding()
	if g.InstallationID != d.Config.InstallationID || g.ControllerOwner != d.Config.ControllerOwner || g.DeploymentConfigSHA256 != d.ConfigDigest || (d.profileHash != "" && g.ProfileSHA256 != d.profileHash) {
		return c.ErrExecutionAuthority
	}
	return nil
}

// Same pure file-binding stage used by the real Linux service and Windows
// tests. It does not create/claim a task or perform provider/Kubernetes I/O.
func (d *DeploymentService) loadPublicationSignerInput(inputs []PublicationSignerInput) error {
	ref := d.Config.PublicationSigners
	if ref == nil {
		if len(inputs) != 0 {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	if d.publicationBinding() != nil || ref.validate() != nil || len(inputs) != 1 || inputs[0].File != ref.Path {
		return c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(inputs[0].File, inputs[0].SHA256, 1<<20)
	if err != nil {
		return err
	}
	var materials PublicationSignerMaterials
	if decodeProviderDeploymentJSON(raw, &materials) != nil || materials.Version != PublicationSignerMaterialsVersion || materials.Pin.InstallationID != d.Config.InstallationID || len(materials.Mounts) != 3 {
		return c.ErrExecutionAuthority
	}
	if _, err = s.LoadPublicationSignerHistory(context.Background(), inputs[0]); err != nil {
		return c.ErrExecutionAuthority
	}
	recordRaw, _, err := materials.Record.ReadSigningRecord(context.Background())
	if err != nil || hash(recordRaw) != materials.Pin.RecordSHA256 {
		return c.ErrExecutionAuthority
	}
	var original s.InstallationSigningRecord
	if decodeProviderDeploymentJSON(recordRaw, &original) != nil {
		return c.ErrExecutionAuthority
	}
	g := d.Forward.DeploymentBinding()
	if len(original.Permissions) != 3 {
		return c.ErrExecutionAuthority
	}
	for _, permission := range original.Permissions {
		owner := permission.SQLOwner
		if owner == nil || owner.Database != g.Database || owner.ServerUUID != g.ServerUUID || owner.DatabaseAccount != g.DatabaseAccount || owner.ConfigVersion != g.ConfigVersion || owner.ConfigSHA256 != g.ConfigSHA256 || owner.Workload.Namespace != d.Config.Namespace {
			return c.ErrExecutionAuthority
		}
	}
	input := inputs[0]
	d.publicationInput = &input
	return nil
}

// Called by NewDeploymentService before source/staging connections and before
// readiness/election. Recovery never reads or authenticates signer materials.
func (d *DeploymentService) attachPublicationSigners(ctx context.Context, db *sql.DB, k kubernetes.Interface, podName string) error {
	if d == nil {
		return c.ErrExecutionAuthority
	}
	if podName == "" {
		if d.ForwardEnabled && (d.Config.PublicationSigners != nil || d.Config.FormalVerifier != nil || d.Config.PublisherVerifier != nil) {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	if ctx == nil || ctx.Err() != nil || k == nil {
		return c.ErrExecutionAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pod, err := k.CoreV1().Pods(d.Config.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || pod.UID == "" || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" {
		return c.ErrExecutionAuthority
	}
	d.PublisherOwner = "public:" + string(pod.UID)
	d.controllerActor = controllerObservedActor{PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: pod.Spec.ServiceAccountName}
	if !d.ForwardEnabled {
		return nil
	}
	if d.Config.PublicationSigners == nil {
		return nil
	}
	if d.publicationInput == nil || d.publicationBinding() != nil || d.Forward.CheckDeployment(ctx, db) != nil || k == nil {
		return c.ErrExecutionAuthority
	}
	ns, err := k.CoreV1().Namespaces().Get(ctx, d.Config.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != d.Config.NamespaceUID || ns.DeletionTimestamp != nil {
		return c.ErrExecutionAuthority
	}
	sa, err := k.CoreV1().ServiceAccounts(d.Config.Namespace).Get(ctx, pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if err != nil || sa.UID == "" || sa.DeletionTimestamp != nil || string(sa.UID) == d.Config.Security.ServiceAccountUID {
		return c.ErrExecutionAuthority
	}
	g := d.Forward.DeploymentBinding()
	runtime := PublicationSignerRuntime{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, PublisherOwner: d.PublisherOwner, Namespace: d.Config.Namespace, NamespaceUID: d.Config.NamespaceUID, PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: sa.Name, ServiceAccountUID: string(sa.UID)}
	// Fail Forward startup on absent/invalid private projected JWT files without
	// logging or contacting the provider. Their live content may rotate later.
	raw, err := pinnedDeploymentFile(d.publicationInput.File, d.publicationInput.SHA256, 1<<20)
	if err != nil {
		return err
	}
	var materials PublicationSignerMaterials
	if decodeProviderDeploymentJSON(raw, &materials) != nil {
		return c.ErrExecutionAuthority
	}
	for _, mount := range materials.Mounts {
		jwt, e := readPrivate(mount.JWTFile, 16384)
		if e != nil {
			return c.ErrExecutionAuthority
		}
		valid := len(bytes.TrimSpace(jwt)) >= 16
		clear(jwt)
		if !valid {
			return c.ErrExecutionAuthority
		}
	}
	factory, err := NewDeploymentPublicationSignerFactory(ctx, db, k, runtime, *d.publicationInput)
	if err != nil {
		return err
	}
	d.publicationFactory, d.publicationDB, d.publicationRuntime = factory, db, runtime
	return nil
}

// PublicationSignersForTask is the actual service consumer entry for D's
// original publisher. It preserves the exact acquired/renewed token; it never
// creates one or advances the backup state on the publisher's behalf.
func (d *DeploymentService) PublicationSignersForTask(ctx context.Context, claim c.ClaimToken) (*s.SQLPublicationTaskSigners, error) {
	if ctx == nil || ctx.Err() != nil || d == nil || d.publicationFactory == nil || d.publicationDB == nil || d.publicationBinding() != nil || d.PublisherOwner != d.publicationRuntime.PublisherOwner || claim.Owner != d.PublisherOwner || d.Forward.CheckDeployment(ctx, d.publicationDB) != nil {
		return nil, c.ErrExecutionAuthority
	}
	return d.publicationFactory.ForTask(ctx, claim)
}

func (d *DeploymentService) PublicationSigningHistory(ctx context.Context) (*s.ArtifactSigningKeyHistory, error) {
	if d == nil || d.publicationInput == nil {
		return nil, c.ErrExecutionAuthority
	}
	return s.LoadPublicationSignerHistory(ctx, *d.publicationInput)
}
