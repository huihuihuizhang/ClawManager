package systembackupinstallationowner

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"

	"k8s.io/client-go/kubernetes"
)

// IssueInstalledVaultMetadataIdentity uses the actual original administrator
// token only inside the installation process. It creates a native eight-hour,
// nonrenewable metadata-only service token, then repeats the real native census
// through that identity. It issues no crypto/key/config/task authority.
// Caller must also hold its genuine original installer/enrollment authority.
func IssueInstalledVaultMetadataIdentity(ctx context.Context, original InstalledVaultDependencyConfig, kube kubernetes.Interface, namespace, namespaceUID, outputFile string, localForward ...string) (_ InstalledVaultDependencyConfig, resultErr error) {
	var zero InstalledVaultDependencyConfig
	if len(localForward) > 1 {
		return zero, ErrOwner
	}
	address := ""
	if len(localForward) == 1 {
		address = localForward[0]
	}
	if ctx == nil || ctx.Err() != nil || original.IdentityMode != "original-owner-readonly" || !filepath.IsAbs(outputFile) || filepath.Clean(outputFile) != outputFile {
		return zero, ErrOwner
	}
	directory := filepath.Dir(outputFile)
	canonical, e := filepath.EvalSymlinks(directory)
	if e != nil || canonical != directory {
		return zero, ErrOwner
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return zero, ErrOwner
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return zero, ErrOwner
	}
	defer root.Close()
	if _, e := root.Lstat(filepath.Base(outputFile)); !os.IsNotExist(e) {
		return zero, ErrOwner
	}
	o, e := NewInstalledVaultDependencyObserverWithLocalForward(original, kube, namespace, namespaceUID, address)
	if e != nil {
		return zero, ErrOwner
	}
	defer o.Close()
	proof, e := o.Observe(ctx)
	if e != nil {
		return zero, ErrOwner
	}
	before, _, e := proof.Data(ctx)
	if e != nil {
		return zero, ErrOwner
	}
	admin, e := o.inputToken()
	if e != nil {
		return zero, ErrOwner
	}
	defer clear(admin)
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return zero, ErrOwner
	}
	policy := "sbk-dependency-" + hex.EncodeToString(nonce)
	acl, e := InstalledVaultDependencyObserverACL(original.TransitMount, original.JWTMount)
	if e != nil {
		return zero, ErrOwner
	}
	// A random policy is create-only in this action: refuse any existing path.
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, original.Endpoint+"/v1/sys/policies/acl/"+policy, nil)
	if e != nil {
		return zero, ErrOwner
	}
	req.Header.Set("X-Vault-Token", string(admin))
	response, e := o.transport.client.Do(req)
	req.Header.Del("X-Vault-Token")
	if e != nil {
		return zero, ErrOwner
	}
	missing, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	response.Body.Close()
	if e != nil || response.StatusCode != http.StatusNotFound || !equalJSON(missing, []byte(`{"errors":[]}`)) {
		return zero, ErrOwner
	}
	body, _ := json.Marshal(map[string]string{"policy": acl})
	if _, e = o.metadataIdentityWrite(ctx, "/v1/sys/policies/acl/"+policy, admin, body); e != nil {
		return zero, ErrOwner
	}
	// Do not overwrite/remove any unrelated policy or original credential on an
	// uncertain response. A failed mint can leave only this random read policy.
	body, _ = json.Marshal(map[string]any{"policies": []string{policy}, "no_default_policy": true, "renewable": false, "ttl": "8h", "explicit_max_ttl": "8h", "type": "service", "display_name": "system-backup-provider-dependency"})
	raw, e := o.transport.request(ctx, http.MethodPost, "/v1/auth/token/create", admin, body)
	if e != nil {
		return zero, ErrOwner
	}
	defer clear(raw)
	if !equalJSON(raw, raw) {
		return zero, ErrOwner
	}
	var reply struct {
		Auth struct {
			ClientToken      string   `json:"client_token"`
			TokenType        string   `json:"token_type"`
			Renewable        *bool    `json:"renewable"`
			Duration         int64    `json:"lease_duration"`
			Policies         []string `json:"policies"`
			IdentityPolicies []string `json:"identity_policies"`
		} `json:"auth"`
	}
	if json.Unmarshal(raw, &reply) != nil {
		return zero, ErrOwner
	}
	token := []byte(reply.Auth.ClientToken)
	reply.Auth.ClientToken = ""
	defer clear(token)
	if len(token) < 16 || reply.Auth.TokenType != "service" || reply.Auth.Renewable == nil || *reply.Auth.Renewable || reply.Auth.Duration < 60 || reply.Auth.Duration > 28800 || !reflect.DeepEqual(reply.Auth.Policies, []string{policy}) || len(reply.Auth.IdentityPolicies) != 0 {
		return zero, ErrOwner
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return zero, ErrOwner
		}
	}
	// A known, freshly minted token is revoked on every subsequent failed step.
	defer func() {
		if resultErr != nil {
			body, _ := json.Marshal(map[string]string{"token": string(token)})
			defer clear(body)
			_, _ = o.metadataIdentityWrite(ctx, "/v1/auth/token/revoke", admin, body)
		}
	}()
	file, e := root.OpenFile(filepath.Base(outputFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return zero, ErrOwner
	}
	n, e := file.Write(token)
	if e == nil && n != len(token) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e != nil || closeErr != nil {
		return zero, ErrOwner
	}
	disk, e := privateToken(outputFile)
	defer clear(disk)
	if e != nil || !bytes.Equal(disk, token) {
		return zero, ErrOwner
	}
	metadata := original
	metadata.IdentityMode = "metadata-only"
	metadata.ObserverPolicy = policy
	metadata.TokenFile = outputFile
	metadata.TokenSHA256 = digest(token)
	reader, e := NewInstalledVaultMetadataObserverWithLocalForward(metadata, kube, namespace, namespaceUID, address)
	if e != nil {
		return zero, ErrOwner
	}
	defer reader.Close()
	current, e := reader.Observe(ctx)
	if e != nil {
		return zero, ErrOwner
	}
	after, _, e := current.Data(ctx)
	if e != nil {
		return zero, ErrOwner
	}
	// Only transport identity differs. Actual original key/role/scope metadata
	// must be unchanged; a successful policy/token write alone proves nothing.
	after.TransportIdentity = before.TransportIdentity
	if !reflect.DeepEqual(before, after) {
		return zero, ErrOwner
	}
	return metadata, nil
}

// Vault's native policy write/revoke APIs return 204; GET readers deliberately
// retain their existing 200+JSON-only contract.
func (o *InstalledVaultDependencyObserver) metadataIdentityWrite(ctx context.Context, path string, token, body []byte) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.Endpoint+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrOwner
	}
	req.Header.Set("X-Vault-Token", string(token))
	req.Header.Set("Content-Type", "application/json")
	response, e := o.transport.client.Do(req)
	req.Header.Del("X-Vault-Token")
	if e != nil {
		return nil, ErrOwner
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if e != nil || len(raw) > 1048576 || response.Header.Get("Content-Encoding") != "" || ctx.Err() != nil {
		return nil, ErrOwner
	}
	if response.StatusCode == http.StatusNoContent && len(raw) == 0 {
		return nil, nil
	}
	if response.StatusCode != http.StatusOK || !utf8JSON(raw) {
		clear(raw)
		return nil, ErrOwner
	}
	return raw, nil
}
