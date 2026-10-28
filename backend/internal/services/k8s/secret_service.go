package k8s

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

// SecretService handles Kubernetes Secret reads.
type SecretService struct {
	client           *Client
	namespaceService *NamespaceService
	store            SecretStore
}

// NewSecretService creates a new secret service.
func NewSecretService() *SecretService {
	return &SecretService{
		client:           globalClient,
		namespaceService: NewNamespaceService(),
		store:            NewSecretStore(globalClient),
	}
}

// GetSecretValue returns a decoded string value from a Kubernetes Secret.
func (s *SecretService) GetSecretValue(ctx context.Context, namespace, name, key string) (string, error) {
	if s == nil || s.store == nil {
		return "", fmt.Errorf("secret store not initialized")
	}
	value, err := s.store.GetValue(ctx, namespace, name, key)
	if err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}
	return string(value), nil
}

// CreateOwnerTeamSecret never rotates a token on replay. Only an exact,
// labelled Team secret may be reused; name equality alone is not ownership.
func (s *SecretService) CreateOwnerTeamSecret(ctx context.Context, userID, teamID int, name string, data map[string]string) (map[string]string, error) {
	if s == nil || s.client == nil || s.store == nil {
		return nil, fmt.Errorf("secret store not initialized")
	}
	creator, ok := s.store.(createOnlySecretStore)
	if !ok {
		return nil, fmt.Errorf("create-only secret capability unavailable")
	}
	values := map[string][]byte{}
	for k, v := range data {
		values[k] = []byte(v)
	}
	secret, err := creator.CreateIfAbsent(ctx, &SecretRecord{Namespace: s.client.GetNamespace(userID), Name: name, Type: corev1.SecretTypeOpaque, Labels: map[string]string{"app": "clawreef", "managed-by": "clawreef", "team-id": strconv.Itoa(teamID)}, Data: values})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("secret creation unconfirmed")
	}
	if secret.Labels["team-id"] != strconv.Itoa(teamID) || secret.Labels["managed-by"] != "clawreef" {
		return nil, fmt.Errorf("Owner Team secret ownership conflict")
	}
	result := map[string]string{}
	for k := range data {
		if len(secret.Data[k]) == 0 {
			return nil, fmt.Errorf("Owner Team secret is incomplete")
		}
		result[k] = string(secret.Data[k])
	}
	return result, nil
}

// UpsertSecret creates or updates a secret in the user's namespace.
func (s *SecretService) UpsertSecret(ctx context.Context, userID int, name string, data map[string]string, labels map[string]string) error {
	if s == nil || s.client == nil || s.store == nil {
		return fmt.Errorf("secret store not initialized")
	}

	if _, err := s.namespaceService.EnsureNamespace(ctx, userID); err != nil {
		return fmt.Errorf("failed to ensure namespace: %w", err)
	}

	namespace := s.client.GetNamespace(userID)
	secretData := map[string][]byte{}
	for key, value := range data {
		secretData[key] = []byte(value)
	}

	if err := s.store.Upsert(ctx, &SecretRecord{Namespace: namespace, Name: name, Type: corev1.SecretTypeOpaque, Data: secretData, Labels: labels}); err != nil {
		return fmt.Errorf("failed to upsert secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

// DeleteSecret deletes a Secret from the user's namespace. Missing secrets are treated as already deleted.
func (s *SecretService) DeleteSecret(ctx context.Context, userID int, name string) error {
	if s == nil || s.client == nil || s.store == nil {
		return fmt.Errorf("secret store not initialized")
	}
	namespace := s.client.GetNamespace(userID)
	if err := s.store.Delete(ctx, namespace, name); err != nil {
		return fmt.Errorf("failed to delete secret %s/%s: %w", namespace, name, err)
	}
	return nil
}

// DeleteByLabels deletes only broker-policy-approved Secrets that match every
// supplied label. It deliberately exposes no list operation to app callers.
func (s *SecretService) DeleteByLabels(ctx context.Context, namespace string, labels map[string]string) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("secret store not initialized")
	}
	if err := s.store.DeleteByLabels(ctx, namespace, labels); err != nil {
		return fmt.Errorf("failed to delete secrets by labels in %s: %w", namespace, err)
	}
	return nil
}

// Store exposes the restricted store for system certificate operations.
func (s *SecretService) Store() SecretStore {
	if s == nil {
		return nil
	}
	return s.store
}
