package install

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const OriginalObserverPKIDefinitionVersion = "original-observer-pki-definition.v1"

var ErrOriginalObserverPKIUnconfirmed = errors.New("observer files retained; original authority changed before completion; not installed")

// Independently pinned installation choices, never observed facts/approval.
// ServiceAccount must already exist; a new controller Deployment need not.
type OriginalObserverPKIDefinition struct {
	Version           string                             `json:"schema_version"`
	TrustDomain       string                             `json:"trust_domain"`
	ServiceAccount    string                             `json:"service_account"`
	ServiceAccountUID string                             `json:"service_account_uid"`
	ValiditySeconds   int64                              `json:"validity_seconds"`
	Nodes             []OriginalObserverPKINodeSelection `json:"nodes"`
}

type OriginalObserverPKINodeSelection struct {
	Name      string            `json:"name"`
	UID       string            `json:"uid"`
	Endpoints map[string]string `json:"endpoints"` // whole, gateway, stopped-pro
}

type OriginalObserverPKIEndpoint struct {
	Node, NodeUID, MachineID, BootID, Kind string
	Endpoint                               q.ProofEndpoint
	Certificate, PrivateKey, AnchorKey     BootstrapSourceFilePin
}

// Coordinates/hashes only. Neither this receipt nor a certificate is a task,
// stop, NoS3, adoption, Ready or installed-runtime authorization.
type GeneratedOriginalObserverPKI struct {
	Version, Status, PlanSHA256, DefinitionSHA256 string
	Enrollment                                    EnrollmentPin
	AuthorityHead                                 HeadCAS
	Namespace, NamespaceUID                       string
	ServiceAccount, ServiceAccountUID, ClientURI  string
	CA, ClientCertificate, ClientKey              BootstrapSourceFilePin
	Endpoints                                     []OriginalObserverPKIEndpoint
	NotBefore, NotAfter, AuthorityCheckedAt       time.Time
}

type originalObserverPKIState struct {
	ServiceAccount, ServiceAccountUID string
	Endpoints                         []OriginalObserverPKIEndpoint
}

var originalObserverRoute = map[string]string{"whole": "/observation/v1", "gateway": "/gateway-observation/v1", "stopped-pro": "/stopped-pro-observation/v1"}

func (s *authenticatedOperator) observerPKIAccess(ctx context.Context, resource, namespace, name string) error {
	r, err := s.installer.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "get", Resource: resource, Namespace: namespace, Name: name}}}, metav1.CreateOptions{})
	if err != nil || !r.Status.Allowed || r.Status.Denied || r.Status.EvaluationError != "" {
		return ErrInstall
	}
	return nil
}

func (s *authenticatedOperator) observerPKIOwner(ctx context.Context, pin EnrollmentPin) (currentAuthority, time.Time, error) {
	if s.kubernetes(ctx, "get") != nil || s.authority(ctx, pin) != nil {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	current, now, err := snapshot(ctx, s)
	if err != nil || current.cas.HeadRevision != 0 && (current.cas.State != "active" || now.Before(current.head.NotBefore) || !now.Before(current.head.Until)) {
		return currentAuthority{}, time.Time{}, ErrInstall
	}
	return current, now, nil
}

func observerPKIURI(domain, installation, namespaceUID, kind, uid string) string {
	return "spiffe://" + domain + "/system-backup/" + url.PathEscape(installation) + "/namespace/" + url.PathEscape(namespaceUID) + "/" + kind + "/" + url.PathEscape(uid)
}

// Actual Kubernetes authorization/GETs resolve Node UID, native boot/machine
// identity and address. Only direct original Node addresses are supported by
// this first-install producer; no caller DNS alias or uncreated Service is
// silently accepted. D's hostNetwork deployment must serve those exact URLs.
func (s *authenticatedOperator) readObserverPKIState(ctx context.Context, d OriginalObserverPKIDefinition) (originalObserverPKIState, error) {
	var out originalObserverPKIState
	p := s.installer.plan
	if d.Version != OriginalObserverPKIDefinitionVersion || len(validation.IsDNS1123Subdomain(d.TrustDomain)) != 0 || len(validation.IsDNS1123Subdomain(d.ServiceAccount)) != 0 || !namePattern.MatchString(d.ServiceAccountUID) || d.ValiditySeconds < 3600 || d.ValiditySeconds > 86400 || len(d.Nodes) == 0 || len(d.Nodes) > 64 || s.observerPKIAccess(ctx, "serviceaccounts", p.Target.Namespace, d.ServiceAccount) != nil {
		return out, ErrInstall
	}
	sa, err := s.installer.kube.CoreV1().ServiceAccounts(p.Target.Namespace).Get(ctx, d.ServiceAccount, metav1.GetOptions{})
	if err != nil || sa.DeletionTimestamp != nil || sa.Name != d.ServiceAccount || sa.Namespace != p.Target.Namespace || string(sa.UID) != d.ServiceAccountUID {
		return out, ErrInstall
	}
	out.ServiceAccount, out.ServiceAccountUID = sa.Name, string(sa.UID)
	seenNodes, seenURLs := map[string]bool{}, map[string]bool{}
	for _, selected := range d.Nodes {
		if len(validation.IsDNS1123Subdomain(selected.Name)) != 0 || !namePattern.MatchString(selected.UID) || seenNodes[selected.Name] || len(selected.Endpoints) == 0 || len(selected.Endpoints) > 3 || s.observerPKIAccess(ctx, "nodes", "", selected.Name) != nil {
			return originalObserverPKIState{}, ErrInstall
		}
		seenNodes[selected.Name] = true
		node, e := s.installer.kube.CoreV1().Nodes().Get(ctx, selected.Name, metav1.GetOptions{})
		if e != nil || node.DeletionTimestamp != nil || node.Name != selected.Name || string(node.UID) != selected.UID || node.Status.NodeInfo.MachineID == "" || node.Status.NodeInfo.BootID == "" {
			return originalObserverPKIState{}, ErrInstall
		}
		ready := false
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady {
				ready = condition.Status == corev1.ConditionTrue
			}
		}
		if !ready {
			return originalObserverPKIState{}, ErrInstall
		}
		for kind, endpoint := range selected.Endpoints {
			route, known := originalObserverRoute[kind]
			u, e := url.Parse(endpoint)
			if !known || e != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || u.Path != route || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != endpoint || seenURLs[u.Host] {
				return originalObserverPKIState{}, ErrInstall
			}
			port, e := strconv.Atoi(u.Port())
			if e != nil || port < 1 || port > 65535 {
				return originalObserverPKIState{}, ErrInstall
			}
			addressMatched := false
			for _, address := range node.Status.Addresses {
				if address.Type != corev1.NodeInternalIP && address.Type != corev1.NodeInternalDNS && address.Type != corev1.NodeHostName {
					continue
				}
				if ip := net.ParseIP(u.Hostname()); ip != nil {
					addressMatched = addressMatched || ip.Equal(net.ParseIP(address.Address))
				} else {
					addressMatched = addressMatched || strings.EqualFold(u.Hostname(), address.Address) && len(validation.IsDNS1123Subdomain(u.Hostname())) == 0
				}
			}
			if !addressMatched {
				return originalObserverPKIState{}, ErrInstall
			}
			seenURLs[u.Host] = true
			uri := observerPKIURI(d.TrustDomain, p.Target.InstallationID, p.Target.NamespaceUID, "node-"+kind, string(node.UID))
			out.Endpoints = append(out.Endpoints, OriginalObserverPKIEndpoint{Node: node.Name, NodeUID: string(node.UID), MachineID: node.Status.NodeInfo.MachineID, BootID: node.Status.NodeInfo.BootID, Kind: kind, Endpoint: q.ProofEndpoint{URL: endpoint, ServerURI: uri}})
		}
	}
	sort.Slice(out.Endpoints, func(a, b int) bool {
		if out.Endpoints[a].Node == out.Endpoints[b].Node {
			return out.Endpoints[a].Kind < out.Endpoints[b].Kind
		}
		return out.Endpoints[a].Node < out.Endpoints[b].Node
	})
	return out, nil
}

// GenerateOriginalObserverPKI is an actual offline material producer, not an
// admission DTO. It requires independently pinned original plan/enrollment and
// definition, real bcrypt+SQL/Kubernetes owner authorization and real Node/SA
// reads before/after issuance. It mutates no Kubernetes/SQL/source state.
func (i *Installer) GenerateOriginalObserverPKI(ctx context.Context, password []byte, pin EnrollmentPin, definitionFile, definitionSHA, directory string) (GeneratedOriginalObserverPKI, error) {
	var zero GeneratedOriginalObserverPKI
	s, err := i.authenticate(ctx, password)
	if err != nil {
		return zero, ErrInstall
	}
	originalAuthority, now, err := s.observerPKIOwner(ctx, pin)
	if err != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{File: definitionFile, SHA256: definitionSHA}, 262144)
	if err != nil {
		return zero, ErrInstall
	}
	var definition OriginalObserverPKIDefinition
	if decodeExact(raw, &definition) != nil {
		return zero, ErrInstall
	}
	before, err := s.readObserverPKIState(ctx, definition)
	if err != nil {
		return zero, ErrInstall
	}
	clientURI := observerPKIURI(definition.TrustDomain, i.plan.Target.InstallationID, i.plan.Target.NamespaceUID, "controller-service-account", definition.ServiceAccountUID)
	identities := map[string]originalObserverCertificateIdentity{}
	for _, endpoint := range before.Endpoints {
		prefix := "node-" + hash([]byte(endpoint.NodeUID + "\x00" + endpoint.Kind))[:24]
		u, _ := url.Parse(endpoint.Endpoint.URL)
		identities[prefix] = originalObserverCertificateIdentity{URI: endpoint.Endpoint.ServerURI, Host: u.Hostname()}
	}
	issuedAt := now.Truncate(time.Second)
	until := issuedAt.Add(time.Duration(definition.ValiditySeconds) * time.Second)
	files, err := originalObserverCertificates(issuedAt, until, clientURI, identities)
	if err != nil {
		return zero, ErrInstall
	}
	defer func() {
		for _, private := range files {
			clear(private)
		}
	}()
	check := func() (time.Time, error) {
		fresh, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: definitionFile, SHA256: definitionSHA}, 262144)
		if e != nil || hash(fresh) != hash(raw) {
			return time.Time{}, ErrInstall
		}
		current, e := s.readObserverPKIState(ctx, definition)
		if e != nil || !reflect.DeepEqual(current, before) {
			return time.Time{}, ErrInstall
		}
		currentAuthority, checkedAt, e := s.observerPKIOwner(ctx, pin)
		if e != nil || currentAuthority.cas != originalAuthority.cas {
			return time.Time{}, ErrInstall
		}
		return checkedAt, nil
	}
	if _, err = check(); err != nil || writeNewFiles(directory, files) != nil {
		return zero, ErrInstall
	}
	for name, expected := range files {
		actual, readErr := ReadPrivateFile(filepath.Join(directory, name), int64(len(expected)+1))
		same := readErr == nil && bytes.Equal(actual, expected)
		clear(actual)
		if !same {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
	}
	checked, err := check()
	if err != nil {
		// Retain create-only uninstalled material for exact inspection. No
		// success receipt, replacement CA, automatic apply or blind retry.
		return zero, ErrOriginalObserverPKIUnconfirmed
	}
	pinned := func(name string) BootstrapSourceFilePin {
		return BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(files[name])}
	}
	for n := range before.Endpoints {
		ep := &before.Endpoints[n]
		prefix := "node-" + hash([]byte(ep.NodeUID + "\x00" + ep.Kind))[:24]
		ep.Certificate, ep.PrivateKey, ep.AnchorKey = pinned(prefix+".pem"), pinned(prefix+"-key.pem"), pinned(prefix+"-anchor.key")
	}
	return GeneratedOriginalObserverPKI{Version: "original-observer-pki-materials.v1", Status: "materialized_uninstalled_not_task_authority", PlanSHA256: i.planHash, DefinitionSHA256: definitionSHA, Enrollment: pin, AuthorityHead: originalAuthority.cas, Namespace: i.plan.Target.Namespace, NamespaceUID: i.plan.Target.NamespaceUID, ServiceAccount: before.ServiceAccount, ServiceAccountUID: before.ServiceAccountUID, ClientURI: clientURI, CA: pinned("observer-ca.pem"), ClientCertificate: pinned("observer-client.pem"), ClientKey: pinned("observer-client-key.pem"), Endpoints: before.Endpoints, NotBefore: issuedAt.Add(-time.Minute), NotAfter: until, AuthorityCheckedAt: checked}, nil
}
