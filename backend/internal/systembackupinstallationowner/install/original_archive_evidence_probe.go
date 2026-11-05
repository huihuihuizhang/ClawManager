package install

import (
	"bytes"
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

// Actual TokenReview followed by exact native batch-token exchange. A JWT DTO
// or local ACL assertion cannot establish archive read authority.
func (i *Installer) originalArchiveMaterialLogin(ctx context.Context, v *originalPublicationVault, b owner.Binding, c ev.TransitJWTConfig, jwt []byte) ([]byte, time.Time, error) {
	tr, err := i.kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{Spec: authn.TokenReviewSpec{Token: string(jwt), Audiences: []string{c.Audience}}}, metav1.CreateOptions{})
	if err != nil || !tr.Status.Authenticated || tr.Status.Error != "" || tr.Status.User.Username != c.Subject || tr.Status.User.UID != b.ServiceAccountUID || !reflect.DeepEqual(tr.Status.Audiences, []string{c.Audience}) || !reflect.DeepEqual([]string(tr.Status.User.Extra["authentication.kubernetes.io/pod-uid"]), []string{b.PodUID}) {
		return nil, time.Time{}, ErrInstall
	}
	request, _ := json.Marshal(map[string]string{"role": c.Role, "jwt": string(jwt)})
	defer clear(request)
	started := time.Now()
	raw, status, err := v.call(ctx, "POST", "/v1/auth/"+c.Mount+"/login", nil, request)
	defer clear(raw)
	if err != nil || status != 200 {
		return nil, time.Time{}, ErrInstall
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
		return nil, time.Time{}, ErrInstall
	}
	a := login.Auth
	if a.Type != "batch" || a.Renewable || a.TTL < 1 || a.TTL > 10 || !reflect.DeepEqual(a.Policies, []string{c.Policy}) || !reflect.DeepEqual(a.TokenPolicies, []string{c.Policy}) || len(a.IdentityPolicies) != 0 || a.Metadata["role"] != c.Role || a.Metadata["namespace"] != b.Namespace || a.Metadata["pod_uid"] != b.PodUID || a.Metadata["service_account_uid"] != b.ServiceAccountUID {
		return nil, time.Time{}, ErrInstall
	}
	token, err := originalPublicationToken([]byte(a.Token))
	if err != nil {
		return nil, time.Time{}, ErrInstall
	}
	return token, started.Add(time.Duration(a.TTL) * time.Second), nil
}

func (i *Installer) originalArchiveMaterialProbe(ctx context.Context, v *originalPublicationVault, wrapActor, readActor owner.Binding, wrap, read ev.TransitJWTConfig, wrapJWT, readJWT []byte) error {
	wt, wu, e := i.originalArchiveMaterialLogin(ctx, v, wrapActor, wrap, wrapJWT)
	if e != nil {
		return e
	}
	defer clear(wt)
	rt, ru, e := i.originalArchiveMaterialLogin(ctx, v, readActor, read, readJWT)
	if e != nil {
		return e
	}
	defer clear(rt)
	probe, cancel := context.WithDeadline(ctx, minTime(wu, ru))
	defer cancel()
	var dek [32]byte
	if _, e = rand.Read(dek[:]); e != nil {
		return ErrInstall
	}
	defer clear(dek[:])
	ec, e := ev.EvidenceTransitContext(wrap.Transit.Installation, wrap.Transit.Key)
	if e != nil {
		return ErrInstall
	}
	payload, _ := json.Marshal(map[string]any{"context": ec, "plaintext": base64.StdEncoding.EncodeToString(dek[:]), "key_version": wrap.Transit.KeyVersion})
	defer clear(payload)
	encrypted, status, e := v.call(probe, "POST", "/v1/transit/encrypt/"+wrap.Transit.KeyName, wt, payload)
	defer clear(encrypted)
	var enc struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion uint32 `json:"key_version"`
		}
	}
	if e != nil || status != 200 || json.Unmarshal(encrypted, &enc) != nil || enc.Data.KeyVersion != wrap.Transit.KeyVersion || !strings.HasPrefix(enc.Data.Ciphertext, "vault:v1:") {
		return ErrInstall
	}
	decrypt, _ := json.Marshal(map[string]string{"context": ec, "ciphertext": enc.Data.Ciphertext})
	defer clear(decrypt)
	raw, status, e := v.call(probe, "POST", "/v1/transit/decrypt/"+read.Transit.KeyName, rt, decrypt)
	defer clear(raw)
	var dec struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		}
	}
	if e != nil || status != 200 || json.Unmarshal(raw, &dec) != nil {
		return ErrInstall
	}
	plain, e := base64.StdEncoding.Strict().DecodeString(dec.Data.Plaintext)
	defer clear(plain)
	if e != nil || !bytes.Equal(plain, dek[:]) {
		return ErrInstall
	}
	deny := func(token []byte, path string, p []byte) bool {
		r, s, _ := v.call(probe, "POST", path, token, p)
		clear(r)
		return s == 403
	}
	foreign, _ := json.Marshal(map[string]string{"context": base64.StdEncoding.EncodeToString([]byte("foreign-archive-context")), "ciphertext": enc.Data.Ciphertext})
	defer clear(foreign)
	if !deny(wt, "/v1/transit/decrypt/"+wrap.Transit.KeyName, decrypt) || !deny(rt, "/v1/transit/encrypt/"+read.Transit.KeyName, payload) || !deny(rt, "/v1/transit/decrypt/"+read.Transit.KeyName, foreign) || !deny(rt, "/v1/transit/decrypt/foreign-archive-evidence-key", decrypt) || !deny(rt, "/v1/transit/datakey/plaintext/"+read.Transit.KeyName, []byte(`{}`)) {
		return ErrInstall
	}
	r, s, e := v.call(probe, "GET", "/v1/transit/keys/"+read.Transit.KeyName, rt, nil)
	clear(r)
	if s != 403 {
		return ErrInstall
	}
	wrong, _ := json.Marshal(map[string]string{"role": read.Role, "jwt": string(wrapJWT)})
	defer clear(wrong)
	r, s, e = v.call(probe, "POST", "/v1/auth/"+read.Mount+"/login", nil, wrong)
	clear(r)
	if (s != 400 && s != 403) || probe.Err() != nil {
		return ErrInstall
	}
	return nil
}
