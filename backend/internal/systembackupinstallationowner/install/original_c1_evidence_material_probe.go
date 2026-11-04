package install

import (
	ev "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"strings"
	"time"
)

// Positive and negative calls use the SAME real Pod-bound JWT exchange and
// resulting native Vault batch credential. No local permission label, status
// DTO or JWT decoder can substitute for provider enforcement.
func (i *Installer) originalC1WrapProbe(ctx context.Context, v *originalPublicationVault, b owner.Binding, c ev.TransitJWTConfig, jwt []byte) error {
	tr, err := i.kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{Spec: authn.TokenReviewSpec{Token: string(jwt), Audiences: []string{c.Audience}}}, metav1.CreateOptions{})
	if err != nil || !tr.Status.Authenticated || tr.Status.Error != "" || tr.Status.User.Username != c.Subject || tr.Status.User.UID != b.ServiceAccountUID || !reflect.DeepEqual(tr.Status.Audiences, []string{c.Audience}) || !reflect.DeepEqual([]string(tr.Status.User.Extra["authentication.kubernetes.io/pod-uid"]), []string{b.PodUID}) {
		return ErrInstall
	}
	request, _ := json.Marshal(map[string]string{"role": c.Role, "jwt": string(jwt)})
	defer clear(request)
	started := time.Now()
	raw, status, err := v.call(ctx, "POST", "/v1/auth/"+c.Mount+"/login", nil, request)
	defer clear(raw)
	if err != nil || status != 200 {
		return ErrInstall
	}
	var login struct {
		Auth struct {
			Token            string            `json:"client_token"`
			Type             string            `json:"token_type"`
			Renewable        bool              `json:"renewable"`
			TTL              int64             `json:"lease_duration"`
			Policies         []string          `json:"policies"`
			TokenPolicies    []string          `json:"token_policies"`
			IdentityPolicies []string          `json:"identity_policies"`
			Metadata         map[string]string `json:"metadata"`
		}
	}
	root, err := originalArchiveObject(raw)
	if err != nil || !originalPublicationFields(root["auth"], "client_token", "token_type", "renewable", "lease_duration", "policies", "token_policies", "identity_policies", "metadata") || json.Unmarshal(raw, &login) != nil {
		return ErrInstall
	}
	a := login.Auth
	if a.Type != "batch" || a.Renewable || a.TTL < 1 || a.TTL > 10 || !reflect.DeepEqual(a.Policies, []string{c.Policy}) || !reflect.DeepEqual(a.TokenPolicies, []string{c.Policy}) || len(a.IdentityPolicies) != 0 || a.Metadata["role"] != c.Role || a.Metadata["namespace"] != b.Namespace || a.Metadata["pod_uid"] != b.PodUID || a.Metadata["service_account_uid"] != b.ServiceAccountUID {
		return ErrInstall
	}
	token, err := originalPublicationToken([]byte(a.Token))
	if err != nil {
		return ErrInstall
	}
	defer clear(token)
	probe, cancel := context.WithDeadline(ctx, started.Add(time.Duration(a.TTL)*time.Second))
	defer cancel()
	var dek [32]byte
	if _, err = rand.Read(dek[:]); err != nil {
		return ErrInstall
	}
	defer clear(dek[:])
	evidenceContext, err := ev.EvidenceTransitContext(c.Transit.Installation, c.Transit.Key)
	if err != nil {
		return ErrInstall
	}
	plain := base64.StdEncoding.EncodeToString(dek[:])
	payload, _ := json.Marshal(map[string]any{"context": evidenceContext, "plaintext": plain, "key_version": c.Transit.KeyVersion})
	defer clear(payload)
	encrypted, status, err := v.call(probe, "POST", "/v1/transit/encrypt/"+c.Transit.KeyName, token, payload)
	defer clear(encrypted)
	var result struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion uint32 `json:"key_version"`
		}
	}
	if err != nil || status != 200 || json.Unmarshal(encrypted, &result) != nil || result.Data.KeyVersion != 1 || !strings.HasPrefix(result.Data.Ciphertext, "vault:v1:") {
		return ErrInstall
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(result.Data.Ciphertext, "vault:v1:"))
	defer clear(ciphertext)
	if err != nil || len(ciphertext) != 60 {
		return ErrInstall
	}
	deny := func(method, path string, body []byte) bool {
		response, status, _ := v.call(probe, method, path, token, body)
		clear(response)
		return status == 403
	}
	decrypt, _ := json.Marshal(map[string]string{"context": evidenceContext, "ciphertext": result.Data.Ciphertext})
	defer clear(decrypt)
	wrongContext, _ := json.Marshal(map[string]any{"context": base64.StdEncoding.EncodeToString([]byte("foreign-context")), "plaintext": plain, "key_version": 1})
	defer clear(wrongContext)
	wrongVersion, _ := json.Marshal(map[string]any{"context": evidenceContext, "plaintext": plain, "key_version": 2})
	defer clear(wrongVersion)
	if !deny("POST", "/v1/transit/decrypt/"+c.Transit.KeyName, decrypt) || !deny("GET", "/v1/transit/keys/"+c.Transit.KeyName, nil) || !deny("POST", "/v1/transit/encrypt/"+c.Transit.KeyName, wrongContext) || !deny("POST", "/v1/transit/encrypt/"+c.Transit.KeyName, wrongVersion) || !deny("POST", "/v1/transit/datakey/plaintext/"+c.Transit.KeyName, []byte(`{}`)) {
		return ErrInstall
	}
	if probe.Err() != nil {
		return ErrInstall
	}
	return nil
}
