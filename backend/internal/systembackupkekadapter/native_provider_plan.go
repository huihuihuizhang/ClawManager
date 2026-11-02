package systembackupkekadapter

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	kms "clawreef/internal/systembackupkms"
)

func vaultPolicyName(name string) bool {
	return keyNameValid(name) && !strings.EqualFold(name, "root") && !strings.EqualFold(name, "default")
}

// Installation payloads are DESIRED CONFIGURATION, never a capability receipt.
// D applies them with its isolated installer, then the independent metadata
// observer verifies the actual running provider before an owner signs evidence.
func VaultJWTAuthRole(role VaultPermissionRole) ([]byte, error) {
	for _, name := range []string{role.AuthMount, role.Role, role.Policy} {
		if !vaultPolicyName(name) {
			return nil, kms.ErrPermission
		}
	}
	for _, pin := range []string{role.Namespace, role.ServiceAccountName, role.ServiceAccountUID, role.Audience} {
		if pin == "" || len(pin) > 1024 || strings.ContainsAny(pin, "\x00\r\n") {
			return nil, kms.ErrPermission
		}
	}
	claims := map[string]string{"/kubernetes.io/namespace": role.Namespace, "/kubernetes.io/serviceaccount/name": role.ServiceAccountName, "/kubernetes.io/serviceaccount/uid": role.ServiceAccountUID}
	if role.PodUID != "" {
		claims["/kubernetes.io/pod/uid"] = role.PodUID
	}
	return json.Marshal(map[string]any{
		"role_type": "jwt", "bound_audiences": []string{role.Audience},
		"bound_subject": "system:serviceaccount:" + role.Namespace + ":" + role.ServiceAccountName,
		"user_claim":    "/kubernetes.io/pod/uid", "user_claim_json_pointer": true,
		"bound_claims_type": "string", "bound_claims": claims,
		"claim_mappings": map[string]string{"/kubernetes.io/namespace": "namespace", "/kubernetes.io/serviceaccount/uid": "service_account_uid", "/kubernetes.io/pod/uid": "pod_uid"},
		"groups_claim":   "", "token_policies": []string{role.Policy}, "token_type": "batch", "token_no_default_policy": true,
		// A provider credential covers the short provider request, never renews
		// the original task/key-use window or the synchronous DEK callback.
		"token_ttl": 10, "token_max_ttl": 10, "token_explicit_max_ttl": 10,
		"token_period": 0, "token_num_uses": 0,
		"clock_skew_leeway": -1, "expiration_leeway": -1, "not_before_leeway": -1,
	})
}

func VaultJWTAuthConfig(trust VaultJWTTrust) ([]byte, error) {
	if trust.Issuer == "" || len(trust.Algorithms) == 0 || (trust.JWKSURL == "") == (len(trust.ValidationPublicKeys) == 0) {
		return nil, kms.ErrPermission
	}
	if trust.JWKSURL != "" {
		u, err := url.Parse(trust.JWKSURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || trust.JWKSCAPEM == "" {
			return nil, kms.ErrPermission
		}
	} else if trust.JWKSCAPEM != "" {
		return nil, kms.ErrPermission
	}
	seen := map[string]bool{}
	for _, algorithm := range trust.Algorithms {
		if seen[algorithm] || (algorithm != "RS256" && algorithm != "ES256" && algorithm != "EdDSA") {
			return nil, kms.ErrPermission
		}
		seen[algorithm] = true
	}
	config := map[string]any{"bound_issuer": trust.Issuer, "jwt_supported_algs": trust.Algorithms, "default_role": ""}
	if trust.JWKSURL != "" {
		config["jwks_url"], config["jwks_ca_pem"] = trust.JWKSURL, trust.JWKSCAPEM
	} else {
		config["jwt_validation_pubkeys"] = trust.ValidationPublicKeys
	}
	return json.Marshal(config)
}

func VaultTransitKeyPayload() []byte {
	return []byte(`{"type":"aes256-gcm96","derived":true,"convergent_encryption":false,"exportable":false,"allow_plaintext_backup":false}`)
}

// Observer policy is independently named and has only exact metadata READs.
// It grants neither token creation nor the runtime crypto operations it audits.
func VaultObserverACL(bindingKey string, worker, publisher VaultPermissionRole, observerPolicy ...string) (string, error) {
	if !keyNameValid(bindingKey) {
		return "", kms.ErrPermission
	}
	paths := map[string]bool{"auth/token/lookup-self": true, "transit/keys/" + bindingKey: true}
	if len(observerPolicy) > 1 {
		return "", kms.ErrPermission
	}
	if len(observerPolicy) == 1 {
		if !vaultPolicyName(observerPolicy[0]) || observerPolicy[0] == worker.Policy || observerPolicy[0] == publisher.Policy {
			return "", kms.ErrPermission
		}
		paths["sys/policies/acl/"+observerPolicy[0]] = true
	}
	for _, role := range []VaultPermissionRole{worker, publisher} {
		for _, name := range []string{role.AuthMount, role.Role, role.Policy} {
			if !vaultPolicyName(name) {
				return "", kms.ErrPermission
			}
		}
		paths["sys/policies/acl/"+role.Policy] = true
		paths["auth/"+role.AuthMount+"/role/"+role.Role] = true
		paths["auth/"+role.AuthMount+"/config"] = true
	}
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	var policy strings.Builder
	for _, path := range ordered {
		policy.WriteString("path \"" + path + "\" { capabilities = [\"read\"] }\n")
	}
	return policy.String(), nil
}
