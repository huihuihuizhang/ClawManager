package install

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const originalSharedAgentServerName = "lite-agent.clawmanager.internal"

type OriginalSharedAgentTLSDefinition struct {
	Version, SecretPrefix string
	ValiditySeconds       int64
}

type originalSharedAgentTLSSource struct {
	RuntimeType, Deployment, DeploymentUID, SpecSHA256 string
	Generation                                         int64
}

type OriginalSharedAgentTLSTarget struct {
	RuntimeType, Deployment, DeploymentUID, DeploymentSpecSHA256 string
	DeploymentGeneration                                         int64
	SecretName, ServerURI, ServerCertificateDERSHA256            string
	Certificate, PrivateKey, SecretManifest                      BootstrapSourceFilePin
}

// Transport material only. Never a reservation, source proof, capture task,
// stop acknowledgement, release authorization, or installed-runtime receipt.
type OriginalSharedAgentTLSReceipt struct {
	Version, Status, PlanSHA256, DefinitionSHA256 string
	Namespace, NamespaceUID, ServerName           string
	AuthorityHead                                 HeadCAS
	CA                                            BootstrapSourceFilePin
	Targets                                       []OriginalSharedAgentTLSTarget
	NotBefore, NotAfter, AuthorityCheckedAt       time.Time
}

func (s *authenticatedOperator) readOriginalSharedAgentTLSSources(ctx context.Context) ([]originalSharedAgentTLSSource, error) {
	access, err := s.installer.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: s.installer.plan.Target.Namespace, Verb: "list", Resource: "deployments", Group: "apps"}}}, metav1.CreateOptions{})
	if err != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return nil, ErrInstall
	}
	list, err := s.installer.kube.AppsV1().Deployments(s.installer.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, ErrInstall
	}
	result := []originalSharedAgentTLSSource{}
	for _, deployment := range list.Items {
		runtime := deployment.Labels["clawmanager.io/runtime-type"]
		if runtime == "" {
			continue
		}
		if runtime != "openclaw" && runtime != "hermes" || deployment.UID == "" || deployment.DeletionTimestamp != nil || deployment.Spec.Paused || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 1 || *deployment.Spec.Replicas > 32 || len(deployment.Spec.Template.Spec.Containers) != 1 || deployment.Spec.Template.Spec.Containers[0].Name != "runtime" || len(deployment.Spec.Template.Spec.InitContainers) != 0 || len(deployment.Spec.Template.Spec.EphemeralContainers) != 0 || deployment.Spec.Template.Spec.HostNetwork {
			return nil, ErrInstall
		}
		for _, entry := range deployment.Spec.Template.Spec.Containers[0].Env {
			if entry.Name == "RUNTIME_AGENT_ROLE" && (entry.ValueFrom != nil || entry.Value != "") {
				return nil, ErrInstall
			}
		}
		result = append(result, originalSharedAgentTLSSource{runtime, deployment.Name, string(deployment.UID), originalObjectSHA(deployment.Spec), deployment.Generation})
	}
	if len(result) == 0 || len(result) > 64 {
		return nil, ErrInstall
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Deployment < result[j].Deployment })
	return result, nil
}

func originalSharedAgentTLSFiles(now, until time.Time, installation, namespace, namespaceUID, secretPrefix string, sources []originalSharedAgentTLSSource) (map[string][]byte, []OriginalSharedAgentTLSTarget, error) {
	if installation == "" || namespace == "" || namespaceUID == "" || len(validation.IsDNS1123Label(secretPrefix)) != 0 || len(secretPrefix) > 40 || len(sources) == 0 || len(sources) > 64 {
		return nil, nil, ErrInstall
	}
	identities := map[string]originalObserverCertificateIdentity{}
	targets := []OriginalSharedAgentTLSTarget{}
	seen := map[string]bool{}
	for _, source := range sources {
		if source.Deployment == "" || source.DeploymentUID == "" || source.Generation <= 0 || !digestPattern.MatchString(source.SpecSHA256) || source.RuntimeType != "openclaw" && source.RuntimeType != "hermes" || seen[source.DeploymentUID] {
			return nil, nil, ErrInstall
		}
		seen[source.DeploymentUID] = true
		prefix := "agent-" + hash([]byte(source.DeploymentUID))[:24]
		uri := observerPKIURI("clawmanager.local", installation, namespaceUID, "shared-agent-deployment", source.DeploymentUID)
		identities[prefix] = originalObserverCertificateIdentity{URI: uri, Host: originalSharedAgentServerName}
		targets = append(targets, OriginalSharedAgentTLSTarget{RuntimeType: source.RuntimeType, Deployment: source.Deployment, DeploymentUID: source.DeploymentUID, DeploymentSpecSHA256: source.SpecSHA256, DeploymentGeneration: source.Generation, SecretName: secretPrefix + "-" + hash([]byte(source.DeploymentUID))[:16], ServerURI: uri})
	}
	// Reuse the audited certificate primitive; discard its unused client leaf
	// and all node-anchor material before writing any output. CA key is never
	// returned by that primitive and cannot be retained or delivered to a Pod.
	files, err := originalObserverCertificates(now, until, observerPKIURI("clawmanager.local", installation, namespaceUID, "transport-material-producer", "uninstalled-shared-agent"), identities)
	if err != nil {
		return nil, nil, err
	}
	clear(files["observer-client-key.pem"])
	delete(files, "observer-client-key.pem")
	delete(files, "observer-client.pem")
	for index := range targets {
		target := &targets[index]
		prefix := "agent-" + hash([]byte(target.DeploymentUID))[:24]
		clear(files[prefix+"-anchor.key"])
		delete(files, prefix+"-anchor.key")
		block, rest := pem.Decode(files[prefix+".pem"])
		if block == nil || len(rest) != 0 {
			return nil, nil, ErrInstall
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || leaf.VerifyHostname(originalSharedAgentServerName) != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != target.ServerURI {
			return nil, nil, ErrInstall
		}
		target.ServerCertificateDERSHA256 = hash(leaf.Raw)
		immutable := true
		secret := corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: metav1.ObjectMeta{Name: target.SecretName, Namespace: namespace, Annotations: map[string]string{"backup.clawreef.io/original-deployment-uid": target.DeploymentUID}}, Immutable: &immutable, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": files[prefix+".pem"], "tls.key": files[prefix+"-key.pem"], "ca.crt": files["observer-ca.pem"]}}
		raw, err := json.Marshal(secret)
		if err != nil {
			return nil, nil, ErrInstall
		}
		files[prefix+"-secret.private.json"] = raw
	}
	return files, targets, nil
}

func (i *Installer) ProduceOriginalSharedAgentTLSMaterials(ctx context.Context, password []byte, pin EnrollmentPin, file, digest, directory string) (OriginalSharedAgentTLSReceipt, error) {
	var zero OriginalSharedAgentTLSReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
	var definition OriginalSharedAgentTLSDefinition
	if err != nil || decodeExact(raw, &definition) != nil || definition.Version != "original-shared-agent-tls-definition.v1" || definition.ValiditySeconds < 3600 || definition.ValiditySeconds > 86400 {
		return zero, ErrInstall
	}
	operator, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	before, now, err := operator.observerPKIOwner(ctx, pin)
	if err != nil {
		return zero, ErrInstall
	}
	sources, err := operator.readOriginalSharedAgentTLSSources(ctx)
	if err != nil {
		return zero, ErrInstall
	}
	issued := now.UTC().Truncate(time.Second)
	until := issued.Add(time.Duration(definition.ValiditySeconds) * time.Second)
	files, targets, err := originalSharedAgentTLSFiles(issued, until, i.plan.Target.InstallationID, i.plan.Target.Namespace, i.plan.Target.NamespaceUID, definition.SecretPrefix, sources)
	if err != nil {
		return zero, ErrInstall
	}
	defer func() {
		for _, value := range files {
			clear(value)
		}
	}()
	check := func() (time.Time, error) {
		currentRaw, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
		if err != nil || !bytes.Equal(raw, currentRaw) {
			return time.Time{}, ErrInstall
		}
		current, err := operator.readOriginalSharedAgentTLSSources(ctx)
		if err != nil || !reflect.DeepEqual(current, sources) {
			return time.Time{}, ErrInstall
		}
		authority, clock, err := operator.observerPKIOwner(ctx, pin)
		if err != nil || authority.cas != before.cas || clock.Before(now) || !clock.Before(until) {
			return time.Time{}, ErrInstall
		}
		return clock, nil
	}
	if _, err := check(); err != nil || writeNewFiles(directory, files) != nil {
		return zero, ErrInstall
	}
	for name, expected := range files {
		actual, err := ReadPrivateFile(filepath.Join(directory, name), int64(len(expected)+1))
		equal := err == nil && bytes.Equal(actual, expected)
		clear(actual)
		if !equal {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
	}
	checked, err := check()
	if err != nil {
		return zero, ErrOriginalObserverPKIUnconfirmed
	}
	output := func(name string) BootstrapSourceFilePin {
		return BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(files[name])}
	}
	for index := range targets {
		target := &targets[index]
		prefix := "agent-" + hash([]byte(target.DeploymentUID))[:24]
		target.Certificate, target.PrivateKey, target.SecretManifest = output(prefix+".pem"), output(prefix+"-key.pem"), output(prefix+"-secret.private.json")
	}
	return OriginalSharedAgentTLSReceipt{Version: "original-shared-agent-tls-materials.v1", Status: "materialized_uninstalled_no_native_source_proof", PlanSHA256: i.planHash, DefinitionSHA256: digest, Namespace: i.plan.Target.Namespace, NamespaceUID: i.plan.Target.NamespaceUID, ServerName: originalSharedAgentServerName, AuthorityHead: before.cas, CA: output("observer-ca.pem"), Targets: targets, NotBefore: issued.Add(-time.Minute), NotAfter: until, AuthorityCheckedAt: checked}, nil
}
