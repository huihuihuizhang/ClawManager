package systembackupexecution

import (
	"bytes"
	d "clawreef/internal/systembackupdispatch"
	install "clawreef/internal/systembackupinstallationowner/install"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"time"
)

// This reference is part of the administrator-pinned original deployment core,
// bound by the actual Forward grant's DeploymentConfigSHA256. A handover packet
// cannot nominate its own verification root or alias a runtime purpose signer.
type OriginalRelayEnrollmentReference struct {
	Plan, IssuerPublic install.BootstrapSourceFilePin
	Enrollment         install.EnrollmentPin
}

type originalRelayRuntimeHandoverInputs struct {
	Version                                                              string
	Stop, StopSignature, PKI, PKISignature, ClientCertificate, ClientKey install.BootstrapSourceFilePin
}
type originalRelayRuntimeHandoverReceipt struct {
	Version, State, InstallationID, ConfigSHA256, ServiceUID, PodUID, StopSHA256, Endpoint, ClientCertificateSHA256 string
	ConfigVersion                                                                                                   uint64
	RuntimeStarted                                                                                                  bool
	ObservedAt                                                                                                      time.Time
}

// Called ONLY by the actual prepared DeploymentService after real exclusive
// bind and authenticated handler start, BEFORE the capture/publication loop.
// This receipt does not grant a task or assert backup/readiness success.
func (s *DeploymentService) verifyOriginalRelayRuntimeHandover(ctx context.Context) (*originalRelayRuntimeHandoverReceipt, error) {
	file, sum := os.Getenv("SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_FILE"), os.Getenv("SYSTEM_BACKUP_ORIGINAL_RELAY_HANDOVER_SHA256")
	if file == "" && sum == "" && s.Config.OriginalRelayEnrollment == nil {
		return nil, nil
	}
	if file == "" || sum == "" || !s.ForwardEnabled || s.Runtime == nil || s.Runtime.Owner == nil || s.Config.OriginalRelayEnrollment == nil || s.Config.RuntimeSources == nil || s.tlsConfig == nil || s.controllerActor.PodUID == "" {
		return nil, d.ErrNotReady
	}
	raw, e := install.ReadPrivateFile(file, 262144)
	var in originalRelayRuntimeHandoverInputs
	if e != nil || hash(raw) != sum {
		return nil, d.ErrNotReady
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Version != "original-relay-runtime-handover-inputs.v1" {
		return nil, d.ErrNotReady
	}
	read := func(p install.BootstrapSourceFilePin, n int64) ([]byte, error) {
		b, e := install.ReadPrivateFile(p.File, n)
		if e != nil || hash(b) != p.SHA256 {
			return nil, d.ErrNotReady
		}
		return b, nil
	}
	trusted := s.Config.OriginalRelayEnrollment
	planRaw, e := read(trusted.Plan, 262144)
	if e != nil {
		return nil, d.ErrNotReady
	}
	plan, e := install.DecodePlan(planRaw, trusted.Plan.SHA256)
	if e != nil || plan.Target.InstallationID != s.Config.InstallationID || plan.Target.Namespace != s.Config.Namespace || plan.Target.NamespaceUID != s.Config.NamespaceUID || plan.Target.Database != s.Config.SourceDatabase || plan.Target.ServerUUID != s.Config.SourceServerUUID {
		return nil, d.ErrNotReady
	}
	issuer, e := read(trusted.IssuerPublic, ed25519.PublicKeySize)
	if e != nil || len(issuer) != ed25519.PublicKeySize || trusted.IssuerPublic.SHA256 != plan.IssuerPublicKeySHA256 {
		return nil, d.ErrNotReady
	}
	cm, e := s.Runtime.Owner.Client.CoreV1().ConfigMaps(s.Config.Namespace).Get(ctx, plan.EnrollmentName, metav1.GetOptions{})
	if e != nil || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || string(cm.UID) != trusted.Enrollment.ConfigMapUID || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || hash([]byte(cm.Data["enrollment.json"])) != trusted.Enrollment.DocumentSHA256 {
		return nil, d.ErrNotReady
	}
	var enrolled struct {
		SchemaVersion string
		Plan          install.Plan
		AdminUserID   int64
		Issuer        ed25519.PublicKey
	}
	decoder = json.NewDecoder(bytes.NewReader([]byte(cm.Data["enrollment.json"])))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&enrolled) != nil || decoder.Decode(new(any)) != io.EOF || enrolled.SchemaVersion != install.EnrollmentVersion || enrolled.AdminUserID < 1 || !reflect.DeepEqual(enrolled.Plan, plan) || !bytes.Equal(enrolled.Issuer, issuer) {
		return nil, d.ErrNotReady
	}
	ns, e := s.Runtime.Owner.Client.CoreV1().Namespaces().Get(ctx, s.Config.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != plan.Target.NamespaceUID || ns.DeletionTimestamp != nil {
		return nil, d.ErrNotReady
	}
	cluster, e := s.Runtime.Owner.Client.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil || string(cluster.UID) != plan.Target.ClusterID || cluster.DeletionTimestamp != nil {
		return nil, d.ErrNotReady
	}
	stopRaw, e := read(in.Stop, 262144)
	if e != nil {
		return nil, e
	}
	stopSig, e := read(in.StopSignature, 64)
	var stopped install.OriginalRelayHandoverReceipt
	if e != nil || !ed25519.Verify(ed25519.PublicKey(issuer), append([]byte("original-readonly-relay-stop.v1\x00"), stopRaw...), stopSig) || json.Unmarshal(stopRaw, &stopped) != nil || !stopped.OriginalListenerAbsent || stopped.RuntimeStarted || stopped.ConfigVersion != 2 || stopped.PlanSHA256 != trusted.Plan.SHA256 || stopped.Source.PKIMaterial != in.PKI || stopped.Source.PKISignature != in.PKISignature {
		return nil, d.ErrNotReady
	}
	grant := s.Forward.DeploymentBinding()
	if stopped.InstallationID != s.Config.InstallationID || stopped.ConfigSHA256 != grant.ConfigSHA256 || grant.ConfigVersion != 2 || !time.Now().Before(grant.ExpiresAt) {
		return nil, d.ErrNotReady
	}
	pkiRaw, e := read(in.PKI, 262144)
	if e != nil {
		return nil, e
	}
	pkiSig, e := read(in.PKISignature, 64)
	var pki struct {
		Version, PlanSHA256, DeploymentUID, ServiceUID, Endpoint string
		EnrollmentConfigMapUID, EnrollmentSHA256                 string
		Source                                                   struct{ Service string }
		Controller                                               struct{ Namespace, NamespaceUID, Deployment, ServiceAccountName, ServiceAccountUID string }
		Files                                                    map[string]install.BootstrapSourceFilePin
		Until                                                    time.Time
	}
	if e != nil || !ed25519.Verify(ed25519.PublicKey(issuer), append([]byte("original-enrolled-relay-pki.v1\x00"), pkiRaw...), pkiSig) || json.Unmarshal(pkiRaw, &pki) != nil || pki.Version != "original-relay-pki-material.v1" || pki.PlanSHA256 != stopped.PlanSHA256 || pki.EnrollmentConfigMapUID != trusted.Enrollment.ConfigMapUID || pki.EnrollmentSHA256 != trusted.Enrollment.DocumentSHA256 || pki.ServiceUID != stopped.ServiceUID || pki.Controller.Namespace != s.Config.Namespace || pki.Controller.NamespaceUID != s.Config.NamespaceUID || !time.Now().Before(pki.Until) {
		return nil, d.ErrNotReady
	}
	actualCert, e := os.ReadFile(s.Config.ServerCertificate)
	if e != nil || hash(actualCert) != pki.Files["relay-server.pem"].SHA256 || hash(actualCert) != stopped.ServerCertificateSHA256 {
		return nil, d.ErrNotReady
	}
	ca, e := os.ReadFile(s.Config.IssuerCertificate)
	if e != nil || hash(ca) != pki.Files["relay-ca.pem"].SHA256 {
		return nil, d.ErrNotReady
	}
	current, e := s.Runtime.Owner.Client.CoreV1().Pods(s.Config.Namespace).Get(ctx, s.controllerActor.PodName, metav1.GetOptions{})
	if e != nil || string(current.UID) != s.controllerActor.PodUID || current.DeletionTimestamp != nil {
		return nil, d.ErrNotReady
	}
	if current.Spec.ServiceAccountName != pki.Controller.ServiceAccountName {
		return nil, d.ErrNotReady
	}
	sa, e := s.Runtime.Owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Get(ctx, current.Spec.ServiceAccountName, metav1.GetOptions{})
	if e != nil || string(sa.UID) != pki.Controller.ServiceAccountUID {
		return nil, d.ErrNotReady
	}
	if len(current.OwnerReferences) != 1 || current.OwnerReferences[0].Kind != "ReplicaSet" {
		return nil, d.ErrNotReady
	}
	rs, e := s.Runtime.Owner.Client.AppsV1().ReplicaSets(s.Config.Namespace).Get(ctx, current.OwnerReferences[0].Name, metav1.GetOptions{})
	if e != nil || string(rs.UID) != string(current.OwnerReferences[0].UID) || len(rs.OwnerReferences) != 1 || string(rs.OwnerReferences[0].UID) != pki.DeploymentUID {
		return nil, d.ErrNotReady
	}
	svc, e := s.Runtime.Owner.Client.CoreV1().Services(s.Config.Namespace).Get(ctx, pki.Source.Service, metav1.GetOptions{})
	if e != nil || string(svc.UID) != pki.ServiceUID || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) == 0 {
		return nil, d.ErrNotReady
	}
	for k, v := range svc.Spec.Selector {
		if current.Labels[k] != v {
			return nil, d.ErrNotReady
		}
	}
	own, e := url.Parse(s.Config.ControlURL)
	if e != nil {
		return nil, d.ErrNotReady
	}
	expected, e := url.Parse(pki.Endpoint)
	if e != nil || own.Host != expected.Host {
		return nil, d.ErrNotReady
	}
	if in.ClientCertificate != pki.Files["relay-client.pem"] || in.ClientKey != pki.Files["relay-client-key.pem"] {
		return nil, d.ErrNotReady
	}
	cert, e := read(in.ClientCertificate, 65536)
	if e != nil {
		return nil, e
	}
	key, e := read(in.ClientKey, 16384)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, d.ErrNotReady
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, d.ErrNotReady
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}}, DisableCompression: true}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, "GET", pki.Endpoint, nil)
	if e != nil {
		return nil, e
	}
	response, e := client.Do(request)
	if e != nil {
		return nil, d.ErrNotReady
	}
	defer response.Body.Close()
	if response.StatusCode != 403 || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || len(response.TLS.VerifiedChains) == 0 {
		return nil, d.ErrNotReady
	}
	// Metadata certificate has no worker JWT/Job identity: real /relay MUSTdeny it.
	leaf, _ := pem.Decode(cert)
	if leaf == nil {
		return nil, d.ErrNotReady
	}
	return &originalRelayRuntimeHandoverReceipt{Version: "original-relay-runtime-handover-result.v1", State: "actual_normal_runtime_TLS_service_handover_verified_not_backup_success", InstallationID: s.Config.InstallationID, ConfigVersion: 2, ConfigSHA256: grant.ConfigSHA256, ServiceUID: pki.ServiceUID, PodUID: s.controllerActor.PodUID, StopSHA256: in.Stop.SHA256, Endpoint: pki.Endpoint, ClientCertificateSHA256: hash(leaf.Bytes), RuntimeStarted: true, ObservedAt: time.Now().UTC()}, nil
}
func (s *DeploymentService) originalRelayHandoverStatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		receipt := s.originalRelayHandover.Load()
		if receipt == nil {
			w.WriteHeader(503)
			return
		}
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) != 1 || hash(r.TLS.PeerCertificates[0].Raw) != receipt.ClientCertificateSHA256 {
			w.WriteHeader(403)
			return
		}
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
}
