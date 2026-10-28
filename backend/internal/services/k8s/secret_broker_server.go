package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	defaultSecretBrokerAudience = "clawmanager-secret-broker"
	maxSecretBrokerRequest      = 8 << 20
	maxBrokerSecretData         = 6 << 20
)

var (
	brokerDataKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	numericIDPattern     = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// SecretBrokerConfig closes the broker identity and namespace policy. Tenant
// namespaces are derived by Client.GetNamespace from the installation prefix. An empty allowlist means arbitrary
// Secret references are denied; generated Team and instance Secrets and the
// fixed northbound certificate set remain available.
type SecretBrokerConfig struct {
	NamespacePrefix   string
	SystemNamespace   string
	AppNamespace      string
	AppServiceAccount string
	Audience          string
	ReadAllowlist     []string
}

type secretBrokerPolicy struct {
	prefix             string
	systemNamespace    string
	appUsername        string
	audience           string
	tenantNamespace    *regexp.Regexp
	instanceSecretName *regexp.Regexp
	teamSecretName     *regexp.Regexp
	readAllowlist      map[string]struct{}
}

type secretBrokerServer struct {
	client kubernetes.Interface
	store  SecretStore
	policy *secretBrokerPolicy
}

// NewSecretBrokerHandler creates the authenticated, closed-policy HTTP API.
func NewSecretBrokerHandler(client kubernetes.Interface, cfg SecretBrokerConfig) (http.Handler, error) {
	if client == nil {
		return nil, errors.New("Kubernetes client is required")
	}
	policy, err := newSecretBrokerPolicy(cfg)
	if err != nil {
		return nil, err
	}
	server := &secretBrokerServer{
		client: client,
		store:  &directSecretStore{client: &Client{Clientset: client}},
		policy: policy,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("POST /v1/secrets/get", server.authenticated(http.HandlerFunc(server.get)))
	mux.Handle("POST /v1/secrets/get-value", server.authenticated(http.HandlerFunc(server.getValue)))
	mux.Handle("POST /v1/secrets/upsert", server.authenticated(http.HandlerFunc(server.upsert)))
	mux.Handle("POST /v1/secrets/create", server.authenticated(http.HandlerFunc(server.create)))
	mux.Handle("POST /v1/secrets/delete", server.authenticated(http.HandlerFunc(server.delete)))
	mux.Handle("POST /v1/secrets/delete-by-labels", server.authenticated(http.HandlerFunc(server.deleteByLabels)))
	return mux, nil
}

func newSecretBrokerPolicy(cfg SecretBrokerConfig) (*secretBrokerPolicy, error) {
	cfg.NamespacePrefix = strings.TrimSpace(cfg.NamespacePrefix)
	cfg.SystemNamespace = strings.TrimSpace(cfg.SystemNamespace)
	cfg.AppNamespace = strings.TrimSpace(cfg.AppNamespace)
	cfg.AppServiceAccount = strings.TrimSpace(cfg.AppServiceAccount)
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.Audience == "" {
		cfg.Audience = defaultSecretBrokerAudience
	}
	if cfg.NamespacePrefix == "" || cfg.SystemNamespace == "" || cfg.AppNamespace == "" || cfg.AppServiceAccount == "" {
		return nil, errors.New("namespace prefix, system namespace and app identity are required")
	}
	if cfg.SystemNamespace != cfg.NamespacePrefix+"-system" {
		return nil, errors.New("system namespace must equal <namespace-prefix>-system")
	}
	// Reject prefixes that Client would rewrite or truncate. Otherwise the
	// advertised policy and the namespaces actually used by provisioning differ.
	if sanitizeK8sName(cfg.NamespacePrefix) != cfg.NamespacePrefix || len(cfg.NamespacePrefix) > 37 {
		return nil, errors.New("namespace prefix must be canonical and leave room for a numeric user ID")
	}
	allowlist := map[string]struct{}{}
	for _, raw := range cfg.ReadAllowlist {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		path := strings.Split(strings.TrimSpace(parts[0]), "/")
		if len(parts) != 2 || len(path) != 2 || path[0] == "" || path[1] == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid read allowlist entry %q; expected namespace/name:key", entry)
		}
		allowlist[path[0]+"/"+path[1]+":"+strings.TrimSpace(parts[1])] = struct{}{}
	}
	// Match the actual Client initialized from cfg.GetNamespace(): its Namespace
	// is the installation prefix, and GetSystemNamespace adds -system separately.
	// Never derive a user namespace from the App Pod's system namespace.
	quotedTenantPrefix := regexp.QuoteMeta(cfg.NamespacePrefix)
	return &secretBrokerPolicy{
		prefix:             cfg.NamespacePrefix,
		systemNamespace:    cfg.SystemNamespace,
		appUsername:        "system:serviceaccount:" + cfg.AppNamespace + ":" + cfg.AppServiceAccount,
		audience:           cfg.Audience,
		tenantNamespace:    regexp.MustCompile(`^` + quotedTenantPrefix + `-user-([1-9][0-9]*)$`),
		instanceSecretName: regexp.MustCompile(`^clawreef-([1-9][0-9]*)-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?-(?:openclaw|codex)-bootstrap$`),
		teamSecretName:     regexp.MustCompile(`^clawreef-team-([1-9][0-9]*)-bus$`),
		readAllowlist:      allowlist,
	}, nil
}

func (s *secretBrokerServer) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(authorization, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")) == "" {
			writeBrokerError(w, http.StatusUnauthorized, "authentication_required", "projected service-account token is required")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		review, err := s.client.AuthenticationV1().TokenReviews().Create(r.Context(), &authenticationv1.TokenReview{
			Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{s.policy.audience}},
		}, metav1.CreateOptions{})
		if err != nil {
			writeBrokerError(w, http.StatusServiceUnavailable, "token_review_failed", "caller authentication is unavailable")
			return
		}
		if !review.Status.Authenticated || review.Status.User.Username != s.policy.appUsername || !containsString(review.Status.Audiences, s.policy.audience) {
			writeBrokerError(w, http.StatusForbidden, "caller_forbidden", "caller identity or token audience is not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *secretBrokerServer) get(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if !decodeBrokerRequest(w, r, &request) {
		return
	}
	if !s.policy.allowFullRead(request.Namespace, request.Name) {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", "Secret read is outside the closed policy")
		return
	}
	record, err := s.store.Get(r.Context(), request.Namespace, request.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.policy.validateStoredOwnership(record); err != nil {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", err.Error())
		return
	}
	writeSecretResult(w, record, nil)
}

func (s *secretBrokerServer) getValue(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Key       string `json:"key"`
	}
	if !decodeBrokerRequest(w, r, &request) {
		return
	}
	if !s.policy.allowValueRead(request.Namespace, request.Name, request.Key) {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", "Secret key read is outside the closed policy")
		return
	}
	record, err := s.store.Get(r.Context(), request.Namespace, request.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// Managed Secrets are authorized by both their closed name and their actual
	// persisted ownership labels. Exact external allowlist entries intentionally
	// have no broker-owned label schema and remain key-scoped only.
	if s.policy.allowFullRead(request.Namespace, request.Name) {
		if err := s.policy.validateStoredOwnership(record); err != nil {
			writeBrokerError(w, http.StatusForbidden, "policy_denied", err.Error())
			return
		}
	}
	value, ok := record.Data[request.Key]
	if !ok {
		writeStoreError(w, errors.New("secret key not found"))
		return
	}
	writeBrokerJSON(w, http.StatusOK, struct {
		Value []byte `json:"value"`
	}{Value: append([]byte(nil), value...)})
}

func (s *secretBrokerServer) upsert(w http.ResponseWriter, r *http.Request) {
	var record SecretRecord
	if !decodeBrokerRequest(w, r, &record) {
		return
	}
	if err := s.policy.validateUpsert(&record); err != nil {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", err.Error())
		return
	}
	if err := s.store.Upsert(r.Context(), &record); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *secretBrokerServer) delete(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if !decodeBrokerRequest(w, r, &request) {
		return
	}
	if !s.policy.allowDelete(request.Namespace, request.Name) {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", "Secret delete is outside the closed policy")
		return
	}
	secret, err := s.client.CoreV1().Secrets(request.Namespace).Get(r.Context(), request.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.policy.validateStoredOwnership(secretRecord(secret)); err != nil {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", err.Error())
		return
	}
	uid := secret.UID
	resourceVersion := secret.ResourceVersion
	options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &resourceVersion}}
	if err := s.client.CoreV1().Secrets(request.Namespace).Delete(r.Context(), request.Name, options); err != nil && !apierrors.IsNotFound(err) {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *secretBrokerServer) deleteByLabels(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	}
	if !decodeBrokerRequest(w, r, &request) {
		return
	}
	if !s.policy.allowDeleteByLabels(request.Namespace, request.Labels) {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", "filtered Secret deletion is outside the closed policy")
		return
	}
	selector, err := exactLabelSelector(request.Labels)
	if err != nil {
		writeBrokerError(w, http.StatusBadRequest, "invalid_request", "exact labels are required")
		return
	}
	secrets, err := s.client.CoreV1().Secrets(request.Namespace).List(r.Context(), metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	for i := range secrets.Items {
		secret := &secrets.Items[i]
		if !s.policy.allowManagedTenantSecret(request.Namespace, secret.Name, secret.Labels) {
			writeBrokerError(w, http.StatusConflict, "matched_secret_outside_policy", "selector matched a Secret outside the managed-name policy")
			return
		}
	}
	for i := range secrets.Items {
		uid := secrets.Items[i].UID
		resourceVersion := secrets.Items[i].ResourceVersion
		options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &resourceVersion}}
		if err := s.client.CoreV1().Secrets(request.Namespace).Delete(r.Context(), secrets.Items[i].Name, options); err != nil && !apierrors.IsNotFound(err) {
			writeStoreError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *secretBrokerPolicy) allowFullRead(namespace, name string) bool {
	if namespace == p.systemNamespace {
		return isNorthboundSecret(name)
	}
	return p.allowManagedTenantSecret(namespace, name, nil)
}

func (p *secretBrokerPolicy) allowValueRead(namespace, name, key string) bool {
	if !brokerDataKeyPattern.MatchString(key) {
		return false
	}
	if p.allowFullRead(namespace, name) {
		return true
	}
	_, ok := p.readAllowlist[namespace+"/"+name+":"+key]
	return ok
}

func (p *secretBrokerPolicy) allowDelete(namespace, name string) bool {
	if namespace == p.systemNamespace {
		return name == "clawmanager-northbound-gateway-tls-next" || name == "clawmanager-northbound-gateway-ca-next"
	}
	return p.allowManagedTenantSecret(namespace, name, nil)
}

func (p *secretBrokerPolicy) allowDeleteByLabels(namespace string, labels map[string]string) bool {
	if !p.tenantNamespace.MatchString(namespace) || len(labels) != 2 || labels["managed-by"] != "clawreef" {
		return false
	}
	return numericIDPattern.MatchString(labels["instance-id"])
}

func (p *secretBrokerPolicy) allowManagedTenantSecret(namespace, name string, labels map[string]string) bool {
	if !p.tenantNamespace.MatchString(namespace) {
		return false
	}
	if match := p.instanceSecretName.FindStringSubmatch(name); len(match) == 2 {
		return labels == nil || (labels["managed-by"] == "clawreef" && labels["instance-id"] == match[1])
	}
	if match := p.teamSecretName.FindStringSubmatch(name); len(match) == 2 {
		return labels == nil || (labels["managed-by"] == "clawreef" && labels["team-id"] == match[1])
	}
	return false
}

func (p *secretBrokerPolicy) validateUpsert(record *SecretRecord) error {
	if record == nil || record.Namespace == "" || record.Name == "" || len(record.Data) == 0 {
		return errors.New("Secret namespace, name and non-empty data are required")
	}
	dataBytes := 0
	for key, value := range record.Data {
		if !brokerDataKeyPattern.MatchString(key) {
			return errors.New("Secret data key is invalid")
		}
		dataBytes += len(value)
	}
	if dataBytes > maxBrokerSecretData {
		return errors.New("Secret data exceeds broker limit")
	}
	if record.Namespace == p.systemNamespace {
		return validateNorthboundSecret(record)
	}
	if record.Type != "" && record.Type != corev1.SecretTypeOpaque {
		return errors.New("tenant Secret type must be Opaque")
	}
	if !p.allowManagedTenantSecret(record.Namespace, record.Name, record.Labels) {
		return errors.New("tenant Secret name or ownership labels are not allowed")
	}
	return nil
}

func (p *secretBrokerPolicy) validateStoredOwnership(record *SecretRecord) error {
	if record == nil {
		return errors.New("Secret ownership labels are not allowed")
	}
	if record.Namespace == p.systemNamespace {
		return validateNorthboundOwnership(record.Name, record.Labels)
	}
	if !p.allowManagedTenantSecret(record.Namespace, record.Name, record.Labels) {
		return errors.New("tenant Secret ownership labels do not match its managed name")
	}
	return nil
}

func validateNorthboundSecret(record *SecretRecord) error {
	if err := validateNorthboundOwnership(record.Name, record.Labels); err != nil {
		return err
	}
	allowedKeys := map[string]struct{}{}
	expectedType := corev1.SecretTypeOpaque
	switch record.Name {
	case "clawmanager-northbound-gateway-ca", "clawmanager-northbound-gateway-ca-next":
		allowedKeys["ca.crt"] = struct{}{}
	case "clawmanager-northbound-gateway-tls", "clawmanager-northbound-gateway-tls-next", "clawmanager-northbound-managed-ca":
		expectedType = corev1.SecretTypeTLS
		allowedKeys[corev1.TLSCertKey] = struct{}{}
		allowedKeys[corev1.TLSPrivateKeyKey] = struct{}{}
	default:
		return errors.New("system Secret name is not allowed")
	}
	if record.Type != expectedType {
		return fmt.Errorf("system Secret type must be %s", expectedType)
	}
	if len(record.Data) != len(allowedKeys) {
		return errors.New("system Secret data keys do not match policy")
	}
	for key := range record.Data {
		if _, ok := allowedKeys[key]; !ok {
			return errors.New("system Secret data key is not allowed")
		}
	}
	return nil
}

func validateNorthboundOwnership(name string, labels map[string]string) error {
	expectedStage := "active"
	switch name {
	case "clawmanager-northbound-gateway-tls", "clawmanager-northbound-gateway-ca":
	case "clawmanager-northbound-gateway-tls-next", "clawmanager-northbound-gateway-ca-next", "clawmanager-northbound-managed-ca":
		expectedStage = "staged"
	default:
		return errors.New("system Secret name is not allowed")
	}
	if labels["app.kubernetes.io/managed-by"] != "clawmanager" || labels["clawmanager.io/northbound-certificate"] != expectedStage {
		return fmt.Errorf("system Secret ownership labels must identify the %s certificate stage", expectedStage)
	}
	return nil
}

func isNorthboundSecret(name string) bool {
	switch name {
	case "clawmanager-northbound-gateway-ca", "clawmanager-northbound-gateway-ca-next",
		"clawmanager-northbound-gateway-tls", "clawmanager-northbound-gateway-tls-next",
		"clawmanager-northbound-managed-ca":
		return true
	default:
		return false
	}
}

func decodeBrokerRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretBrokerRequest)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeBrokerError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeBrokerError(w, http.StatusBadRequest, "invalid_request", "request body must contain one JSON object")
		return false
	}
	return true
}

func writeSecretResult(w http.ResponseWriter, record *SecretRecord, err error) {
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeBrokerJSON(w, http.StatusOK, record)
}

func writeStoreError(w http.ResponseWriter, err error) {
	if apierrors.IsNotFound(err) {
		writeBrokerError(w, http.StatusNotFound, "secret_not_found", "Secret was not found")
		return
	}
	writeBrokerError(w, http.StatusServiceUnavailable, "kubernetes_operation_failed", "Kubernetes Secret operation failed")
}

func writeBrokerError(w http.ResponseWriter, status int, code, message string) {
	writeBrokerJSON(w, status, brokerError{Code: code, Message: message})
}

func writeBrokerJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// ParseSecretBrokerReadAllowlist accepts a comma/newline separated registry.
// Sorting makes startup logs and tests deterministic without exposing values.
func ParseSecretBrokerReadAllowlist(raw string) []string {
	entries := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	for i := range entries {
		entries[i] = strings.TrimSpace(entries[i])
	}
	sort.Strings(entries)
	return entries
}

// SecretBrokerPort validates the broker listen port without accepting a raw
// address that could unintentionally expose it on another configured socket.
func SecretBrokerPort(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 9444, nil
	}
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("CLAWMANAGER_SECRET_BROKER_PORT must be a valid TCP port")
	}
	return port, nil
}

// ProbeSecretBrokerKubernetes verifies the broker can reach the API without
// reading or listing any Secret.
func ProbeSecretBrokerKubernetes(ctx context.Context, client kubernetes.Interface) error {
	_, err := client.Discovery().ServerVersion()
	return err
}
