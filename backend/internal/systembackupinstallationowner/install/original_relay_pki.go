package install

import (
	owner "clawreef/internal/systembackupinstallationowner"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"path/filepath"
	"reflect"
	"time"
)

const originalRelayPKIDomain = "original-enrolled-relay-pki.v1\x00"

type OriginalRelayPKIInputs struct {
	Version, ControllerDeployment, ControllerPod, Service, OutputDirectory string
	Until                                                                  time.Time
}
type OriginalRelayPKIReceipt struct {
	Version, State                                                                                 string
	Manifest, Signature, CA, IssuerKey, ServerCertificate, ServerKey, ClientCertificate, ClientKey BootstrapSourceFilePin
	Controller                                                                                     owner.Binding
	DeploymentUID, ServiceUID, Endpoint                                                            string
	Until                                                                                          time.Time
}
type originalRelayPKIManifest struct {
	EnrollmentConfigMapUID                string
	Version, PlanSHA256, EnrollmentSHA256 string
	Source                                OriginalRelayPKIInputs
	Controller                            owner.Binding
	DeploymentUID, ServiceUID, Endpoint   string
	Files                                 map[string]BootstrapSourceFilePin
	ObservedAt, Until                     time.Time
}

// An actual original installer action creates a dedicated issuer, not a backup
// grant. Original observer CA keys are never reused or recovered. The real
// controller must mount this issuer/server pair and serve its actual authenticated
// relay before any StatusRelayReference or C1 source may be accepted.
func (i *Installer) IssueOriginalRelayPKI(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalRelayPKIInputs, issuerPrivate []byte) (OriginalRelayPKIReceipt, error) {
	var zero OriginalRelayPKIReceipt
	in.Until = in.Until.UTC().Truncate(time.Second)
	if i == nil || ctx == nil || in.Version != "original-relay-pki-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	state, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || state.cas != (HeadCAS{}) || !now.Before(in.Until) || in.Until.Sub(now) > 24*time.Hour {
		return zero, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPod)
	if e != nil {
		return zero, ErrInstall
	}
	dep, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, in.ControllerDeployment, metav1.GetOptions{})
	if e != nil || dep.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	service, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).Get(ctx, in.Service, metav1.GetOptions{})
	if e != nil || service.UID == "" || service.DeletionTimestamp != nil || len(service.Spec.Selector) == 0 {
		return zero, ErrInstall
	}
	pod, e := i.kube.CoreV1().Pods(i.plan.Target.Namespace).Get(ctx, in.ControllerPod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != actor.PodUID {
		return zero, ErrInstall
	}
	for k, v := range service.Spec.Selector {
		if pod.Labels[k] != v {
			return zero, ErrInstall
		}
	}
	host := in.Service + "." + i.plan.Target.Namespace + ".svc"
	endpoint := "https://" + host + ":9443/relay"
	portOK := false
	for _, p := range service.Spec.Ports {
		portOK = portOK || p.Port == 9443 && string(p.Protocol) == "TCP"
	}
	if !portOK {
		return zero, ErrInstall
	}
	key, e := op.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	prefix := "spiffe://clawmanager.invalid/original-relay/" + i.plan.Target.InstallationID + "/" + actor.NamespaceUID + "/" + string(dep.UID) + "/" + actor.ServiceAccountUID + "/" + string(service.UID)
	files, e := originalRelayCertificates(now, in.Until, prefix+"/metadata-client", map[string]originalRelayCertificateIdentity{"relay-server": {URI: prefix + "/server", Host: host}})
	if e != nil {
		return zero, ErrInstall
	}
	defer func() {
		for _, v := range files {
			clear(v)
		}
	}()
	pins := map[string]BootstrapSourceFilePin{}
	for name, raw := range files {
		pins[name] = BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, name), SHA256: hash(raw)}
	}
	m := originalRelayPKIManifest{Version: "original-relay-pki-material.v1", PlanSHA256: i.planHash, EnrollmentSHA256: enrollment.DocumentSHA256, EnrollmentConfigMapUID: enrollment.ConfigMapUID, Source: in, Controller: actor, DeploymentUID: string(dep.UID), ServiceUID: string(service.UID), Endpoint: endpoint, Files: pins, ObservedAt: now, Until: in.Until}
	intent, e := canonical(m)
	if e != nil || op.authority(ctx, enrollment) != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"relay-pki.intent.json": intent}) != nil {
		return zero, ErrInstall
	}
	current, _, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || current.cas != state.cas {
		return zero, ErrInstall
	}
	again, e := i.originalPublicationActor(ctx, in.ControllerDeployment, in.ControllerPod)
	if e != nil || again != actor {
		return zero, ErrInstall
	}
	live, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).Get(ctx, in.Service, metav1.GetOptions{})
	if e != nil || live.UID != service.UID || !reflect.DeepEqual(live.Spec, service.Spec) {
		return zero, ErrInstall
	}
	if writeNewFiles(in.OutputDirectory, files) != nil {
		return zero, ErrCommitUnknown
	}
	sig := ed25519.Sign(key, append([]byte(originalRelayPKIDomain), intent...))
	if writeNewFiles(in.OutputDirectory, map[string][]byte{"relay-pki.material.json": intent, "relay-pki.material.signature": sig}) != nil {
		return zero, ErrCommitUnknown
	}
	return i.QueryOriginalRelayPKI(ctx, password, enrollment, in.OutputDirectory)
}
func (i *Installer) QueryOriginalRelayPKI(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string) (OriginalRelayPKIReceipt, error) {
	var zero OriginalRelayPKIReceipt
	if i == nil || ctx == nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	raw, e := ReadPrivateFile(filepath.Join(directory, "relay-pki.material.json"), 262144)
	if e != nil {
		return zero, ErrInstall
	}
	sig, e := ReadPrivateFile(filepath.Join(directory, "relay-pki.material.signature"), 64)
	var m originalRelayPKIManifest
	if e != nil || !ed25519.Verify(i.public, append([]byte(originalRelayPKIDomain), raw...), sig) || decodeExact(raw, &m) != nil || m.Version != "original-relay-pki-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 || m.EnrollmentConfigMapUID != enrollment.ConfigMapUID || m.Source.OutputDirectory != directory || m.Until != m.Source.Until || !time.Now().Before(m.Until) {
		return zero, ErrInstall
	}
	var actor owner.Binding
	dep, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, m.Source.ControllerDeployment, metav1.GetOptions{})
	if e != nil || string(dep.UID) != m.DeploymentUID {
		return zero, ErrInstall
	}
	svc, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).Get(ctx, m.Source.Service, metav1.GetOptions{})
	if e != nil || string(svc.UID) != m.ServiceUID {
		return zero, ErrInstall
	}
	pods, e := i.kube.CoreV1().Pods(i.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
	if e != nil {
		return zero, ErrInstall
	}
	count := 0
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" {
			continue
		}
		match := true
		for k, v := range svc.Spec.Selector {
			match = match && pod.Labels[k] == v
		}
		if !match {
			continue
		}
		actual, e := i.originalPublicationActor(ctx, m.Source.ControllerDeployment, pod.Name)
		if e != nil {
			return zero, ErrInstall
		}
		if actual.ServiceAccountName != m.Controller.ServiceAccountName || actual.ServiceAccountUID != m.Controller.ServiceAccountUID {
			return zero, ErrInstall
		}
		count++
		actor = actual
	}
	if count != 1 || len(svc.Spec.Selector) == 0 || len(m.Files) != 6 {
		return zero, ErrInstall
	}
	for name, p := range m.Files {
		if filepath.Base(name) != name || p.File != filepath.Join(directory, name) {
			return zero, ErrInstall
		}
		b, e := readBootstrapSourcePin(p, 65536)
		clear(b)
		if e != nil {
			return zero, ErrInstall
		}
	}
	ca, e := readBootstrapSourcePin(m.Files["relay-ca.pem"], 65536)
	if e != nil {
		return zero, ErrInstall
	}
	b, _ := pem.Decode(ca)
	if b == nil {
		return zero, ErrInstall
	}
	cert, e := x509.ParseCertificate(b.Bytes)
	if e != nil || !cert.IsCA || !cert.NotAfter.Equal(m.Until) || time.Now().Before(cert.NotBefore) {
		return zero, ErrInstall
	}
	return OriginalRelayPKIReceipt{Version: "original-relay-pki-result.v1", State: "original_relay_pki_material_issued_service_tls_not_yet_verified", Manifest: BootstrapSourceFilePin{File: filepath.Join(directory, "relay-pki.material.json"), SHA256: hash(raw)}, Signature: BootstrapSourceFilePin{File: filepath.Join(directory, "relay-pki.material.signature"), SHA256: hash(sig)}, CA: m.Files["relay-ca.pem"], IssuerKey: m.Files["relay-issuer-key.pem"], ServerCertificate: m.Files["relay-server.pem"], ServerKey: m.Files["relay-server-key.pem"], ClientCertificate: m.Files["relay-client.pem"], ClientKey: m.Files["relay-client-key.pem"], Controller: actor, DeploymentUID: m.DeploymentUID, ServiceUID: m.ServiceUID, Endpoint: m.Endpoint, Until: m.Until}, nil
}
