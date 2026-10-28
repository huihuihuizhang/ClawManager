package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	secretBrokerURLenv                       = "CLAWMANAGER_SECRET_BROKER_URL"
	secretBrokerTokenFileEnv                 = "CLAWMANAGER_SECRET_BROKER_TOKEN_FILE"
	secretBrokerMigrationEnv                 = "CLAWMANAGER_SECRET_BROKER_MIGRATION_COMPLETE"
	secretBrokerCAFileEnv                    = "CLAWMANAGER_SECRET_BROKER_CA_FILE"
	secretBrokerAllowInsecureHTTPForTestsEnv = "CLAWMANAGER_SECRET_BROKER_ALLOW_INSECURE_HTTP_FOR_TESTS"
	defaultBrokerTokenFile                   = "/var/run/secrets/clawmanager-secret-broker/token"
	maxSecretBrokerResponse                  = 8 << 20
)

// SecretRecord is the intentionally small Secret projection shared by the app
// and the broker. It excludes annotations, owner references and service-account
// token fields so callers cannot turn the broker into a generic Secret proxy.
type SecretRecord struct {
	Namespace       string            `json:"namespace"`
	Name            string            `json:"name"`
	Type            corev1.SecretType `json:"type"`
	Data            map[string][]byte `json:"data,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	ResourceVersion string            `json:"resource_version,omitempty"`
}

// SecretStore is the complete Secret capability used by the application.
// DeleteByLabels performs a broker-side filtered deletion and never returns a
// list of Secret objects or their data to the application.
type SecretStore interface {
	Get(context.Context, string, string) (*SecretRecord, error)
	GetValue(context.Context, string, string, string) ([]byte, error)
	Upsert(context.Context, *SecretRecord) error
	Delete(context.Context, string, string) error
	DeleteByLabels(context.Context, string, map[string]string) error
}

type directSecretStore struct{ client *Client }

// NewSecretStore selects the broker when configured and otherwise preserves
// the direct client for local development and migration rollback. Production
// cutover sets CLAWMANAGER_SECRET_BROKER_URL and removes app Secret RBAC.
func NewSecretStore(client *Client) SecretStore {
	brokerURL := strings.TrimSpace(os.Getenv(secretBrokerURLenv))
	migrationComplete := strings.EqualFold(strings.TrimSpace(os.Getenv(secretBrokerMigrationEnv)), "true")
	if !migrationComplete {
		return &directSecretStore{client: client}
	}
	if brokerURL == "" {
		return &unavailableSecretStore{err: errors.New("migration is complete but CLAWMANAGER_SECRET_BROKER_URL is empty")}
	}
	store, err := newBrokerSecretStore(brokerURL, strings.TrimSpace(os.Getenv(secretBrokerTokenFileEnv)))
	if err != nil {
		return &unavailableSecretStore{err: err}
	}
	return store
}

func (s *directSecretStore) clientset() (*Client, error) {
	if s == nil || s.client == nil || s.client.Clientset == nil {
		return nil, errors.New("k8s client not initialized")
	}
	return s.client, nil
}

func (s *directSecretStore) Get(ctx context.Context, namespace, name string) (*SecretRecord, error) {
	client, err := s.clientset()
	if err != nil {
		return nil, err
	}
	secret, err := client.Clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return secretRecord(secret), nil
}

func (s *directSecretStore) GetValue(ctx context.Context, namespace, name, key string) ([]byte, error) {
	record, err := s.Get(ctx, namespace, name)
	if err != nil {
		return nil, err
	}
	value, ok := record.Data[key]
	if !ok {
		return nil, fmt.Errorf("secret key not found")
	}
	return append([]byte(nil), value...), nil
}

func (s *directSecretStore) Upsert(ctx context.Context, record *SecretRecord) error {
	client, err := s.clientset()
	if err != nil {
		return err
	}
	api := client.Clientset.CoreV1().Secrets(record.Namespace)
	existing, err := api.Get(ctx, record.Name, metav1.GetOptions{})
	if err == nil {
		existing.Type = record.Type
		existing.Data = cloneSecretBytes(record.Data)
		if existing.Labels == nil {
			existing.Labels = map[string]string{}
		}
		for key, value := range record.Labels {
			existing.Labels[key] = value
		}
		_, err = api.Update(ctx, existing, metav1.UpdateOptions{})
		return err
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	_, err = api.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: record.Name, Namespace: record.Namespace, Labels: cloneStrings(record.Labels)},
		Type:       record.Type,
		Data:       cloneSecretBytes(record.Data),
	}, metav1.CreateOptions{})
	return err
}

func (s *directSecretStore) Delete(ctx context.Context, namespace, name string) error {
	client, err := s.clientset()
	if err != nil {
		return err
	}
	err = client.Clientset.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (s *directSecretStore) DeleteByLabels(ctx context.Context, namespace string, labels map[string]string) error {
	client, err := s.clientset()
	if err != nil {
		return err
	}
	selector, err := exactLabelSelector(labels)
	if err != nil {
		return err
	}
	secrets, err := client.Clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return err
	}
	for i := range secrets.Items {
		uid := secrets.Items[i].UID
		resourceVersion := secrets.Items[i].ResourceVersion
		options := metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &resourceVersion}}
		if err := client.Clientset.CoreV1().Secrets(namespace).Delete(ctx, secrets.Items[i].Name, options); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

type unavailableSecretStore struct{ err error }

func (s *unavailableSecretStore) fail() error {
	return fmt.Errorf("secret broker configuration: %w", s.err)
}
func (s *unavailableSecretStore) Get(context.Context, string, string) (*SecretRecord, error) {
	return nil, s.fail()
}
func (s *unavailableSecretStore) GetValue(context.Context, string, string, string) ([]byte, error) {
	return nil, s.fail()
}
func (s *unavailableSecretStore) Upsert(context.Context, *SecretRecord) error  { return s.fail() }
func (s *unavailableSecretStore) Delete(context.Context, string, string) error { return s.fail() }
func (s *unavailableSecretStore) DeleteByLabels(context.Context, string, map[string]string) error {
	return s.fail()
}

type brokerSecretStore struct {
	baseURL   string
	tokenFile string
	client    *http.Client
}

func newBrokerSecretStore(rawURL, tokenFile string) (*brokerSecretStore, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("CLAWMANAGER_SECRET_BROKER_URL must be an absolute http(s) URL without userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("CLAWMANAGER_SECRET_BROKER_URL must not contain a query or fragment")
	}
	if parsed.Scheme == "http" && !SecretBrokerInsecureHTTPForTestsEnabled() {
		return nil, fmt.Errorf("CLAWMANAGER_SECRET_BROKER_URL must use HTTPS; HTTP is allowed only when %s=true for tests", secretBrokerAllowInsecureHTTPForTestsEnv)
	}
	if tokenFile == "" {
		tokenFile = defaultBrokerTokenFile
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if parsed.Scheme == "https" {
		caFile := strings.TrimSpace(os.Getenv(secretBrokerCAFileEnv))
		if caFile == "" {
			return nil, errors.New("CLAWMANAGER_SECRET_BROKER_CA_FILE is required for HTTPS")
		}
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read Secret broker CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("CLAWMANAGER_SECRET_BROKER_CA_FILE contains no valid certificate")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	}
	return &brokerSecretStore{
		baseURL:   strings.TrimRight(parsed.String(), "/"),
		tokenFile: tokenFile,
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// SecretBrokerInsecureHTTPForTestsEnabled is deliberately narrow: production
// manifests never set it, while synthetic staging must opt in explicitly.
func SecretBrokerInsecureHTTPForTestsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(secretBrokerAllowInsecureHTTPForTestsEnv)), "true")
}

type brokerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (s *brokerSecretStore) call(ctx context.Context, path string, requestBody, responseBody any) error {
	token, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return fmt.Errorf("read projected secret-broker token: %w", err)
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("encode secret-broker request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("secret broker request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxSecretBrokerResponse+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read secret-broker response: %w", err)
	}
	if len(payload) > maxSecretBrokerResponse {
		return errors.New("secret-broker response exceeded size limit")
	}
	if response.StatusCode == http.StatusNotFound {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "redacted")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var remote brokerError
		_ = json.Unmarshal(payload, &remote)
		if remote.Code == "" {
			remote.Code = "request_failed"
		}
		return fmt.Errorf("secret broker %s (%d)", remote.Code, response.StatusCode)
	}
	if responseBody != nil && len(payload) != 0 {
		if err := json.Unmarshal(payload, responseBody); err != nil {
			return fmt.Errorf("decode secret-broker response: %w", err)
		}
	}
	return nil
}

func (s *brokerSecretStore) Get(ctx context.Context, namespace, name string) (*SecretRecord, error) {
	var response SecretRecord
	err := s.call(ctx, "/v1/secrets/get", map[string]string{"namespace": namespace, "name": name}, &response)
	return &response, err
}

func (s *brokerSecretStore) GetValue(ctx context.Context, namespace, name, key string) ([]byte, error) {
	var response struct {
		Value []byte `json:"value"`
	}
	err := s.call(ctx, "/v1/secrets/get-value", map[string]string{"namespace": namespace, "name": name, "key": key}, &response)
	return response.Value, err
}

func (s *brokerSecretStore) Upsert(ctx context.Context, record *SecretRecord) error {
	return s.call(ctx, "/v1/secrets/upsert", record, nil)
}

func (s *brokerSecretStore) Delete(ctx context.Context, namespace, name string) error {
	return s.call(ctx, "/v1/secrets/delete", map[string]string{"namespace": namespace, "name": name}, nil)
}

func (s *brokerSecretStore) DeleteByLabels(ctx context.Context, namespace string, labels map[string]string) error {
	return s.call(ctx, "/v1/secrets/delete-by-labels", struct {
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	}{Namespace: namespace, Labels: labels}, nil)
}

func secretRecord(secret *corev1.Secret) *SecretRecord {
	return &SecretRecord{
		Namespace:       secret.Namespace,
		Name:            secret.Name,
		Type:            secret.Type,
		Data:            cloneSecretBytes(secret.Data),
		Labels:          cloneStrings(secret.Labels),
		ResourceVersion: secret.ResourceVersion,
	}
}

func cloneSecretBytes(input map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(input))
	for key, value := range input {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

func cloneStrings(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func exactLabelSelector(labels map[string]string) (string, error) {
	if len(labels) == 0 {
		return "", errors.New("at least one exact label is required")
	}
	selector := metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: labels})
	if selector == "" {
		return "", errors.New("invalid exact label selector")
	}
	return selector, nil
}
