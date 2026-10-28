package k8s

import (
	"context"
	"errors"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// createOnlySecretStore is separate from Upsert: a Team creation retry must
// return the first token, including after a lost Create response.
type createOnlySecretStore interface {
	CreateIfAbsent(context.Context, *SecretRecord) (*SecretRecord, error)
}

func (s *directSecretStore) CreateIfAbsent(ctx context.Context, record *SecretRecord) (*SecretRecord, error) {
	client, err := s.clientset()
	if err != nil {
		return nil, err
	}
	api := client.Clientset.CoreV1().Secrets(record.Namespace)
	existing, err := api.Get(ctx, record.Name, metav1.GetOptions{})
	if err == nil {
		return secretRecord(existing), nil
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}
	created, err := api.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: record.Name, Namespace: record.Namespace, Labels: cloneStrings(record.Labels)}, Type: record.Type, Data: cloneSecretBytes(record.Data)}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return s.Get(ctx, record.Namespace, record.Name)
	}
	if err != nil {
		return nil, err
	}
	return secretRecord(created), nil
}

func (s *brokerSecretStore) CreateIfAbsent(ctx context.Context, record *SecretRecord) (*SecretRecord, error) {
	var result SecretRecord
	if err := s.call(ctx, "/v1/secrets/create", record, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *secretBrokerServer) create(w http.ResponseWriter, r *http.Request) {
	var request SecretRecord
	if !decodeBrokerRequest(w, r, &request) {
		return
	}
	if err := s.policy.validateUpsert(&request); err != nil {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", err.Error())
		return
	}
	creator, ok := s.store.(createOnlySecretStore)
	if !ok {
		writeStoreError(w, errors.New("create-only store unavailable"))
		return
	}
	result, err := creator.CreateIfAbsent(r.Context(), &request)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if result == nil || s.policy.validateStoredOwnership(result) != nil {
		writeBrokerError(w, http.StatusForbidden, "policy_denied", "Secret ownership is outside the closed policy")
		return
	}
	writeSecretResult(w, result, nil)
}
