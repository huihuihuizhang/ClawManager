package install

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	ev "clawreef/internal/systembackupevidence"
	adapter "clawreef/internal/systembackupkekadapter"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func originalArchiveTLSClient(c ev.TransitConfig) (*http.Client, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery ||
		strings.ContainsAny(c.Endpoint, "?#\r\n") || hash(c.CAPEM) != c.CASHA256 {
		return nil, ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CAPEM) {
		return nil, ErrInstall
	}
	return &http.Client{Transport: &http.Transport{Proxy: nil,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseHeaderBytes: 16384, DisableCompression: true}, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (p *OriginalAdoptionArchiveProvider) checkJWT(source OriginalArchiveJWTSource, role adapter.VaultPermissionRole) error {
	jwt, err := p.readJWT(source, role)
	clear(jwt)
	return err
}

// Original fixed Deployment/SA/Pod identity, native TokenReview and exact
// projected JWT bytes. Job/task identities and rotating replacement files
// cannot be borrowed for this distinct original maintenance purpose.
func (p *OriginalAdoptionArchiveProvider) readJWT(source OriginalArchiveJWTSource, role adapter.VaultPermissionRole) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, ErrInstall }
	if source.File == p.definition.Vault.TokenFile || source.PodName == "" ||
		source.DeploymentName == "" || source.DeploymentUID == "" || source.PodUID == "" ||
		role.PodUID != "" && role.PodUID != source.PodUID {
		return fail()
	}
	jwt, err := ReadPrivateFile(source.File, 16384)
	if err != nil || hash(jwt) != source.SHA256 {
		clear(jwt)
		return fail()
	}
	ok := false
	defer func() {
		if !ok {
			clear(jwt)
		}
	}()
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return fail()
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	defer clear(body)
	if _, parseErr := originalArchiveObject(body); parseErr != nil {
		return fail()
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Subject  string          `json:"sub"`
		Audience json.RawMessage `json:"aud"`
		Expires  int64           `json:"exp"`
	}
	if err != nil || json.Unmarshal(body, &claims) != nil || claims.Issuer != p.definition.Vault.Trust.Issuer ||
		claims.Subject != "system:serviceaccount:"+role.Namespace+":"+role.ServiceAccountName ||
		!time.Unix(claims.Expires, 0).After(p.until.Add(5*time.Second)) {
		return fail()
	}
	var audiences []string
	if json.Unmarshal(claims.Audience, &audiences) != nil {
		var single string
		if json.Unmarshal(claims.Audience, &single) != nil {
			return fail()
		}
		audiences = []string{single}
	}
	if len(audiences) != 1 || audiences[0] != role.Audience {
		return fail()
	}
	kube, ctx := p.operator.installer.kube, p.ctx
	pod, err := kube.CoreV1().Pods(role.Namespace).Get(ctx, source.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != source.PodUID || pod.DeletionTimestamp != nil ||
		pod.Status.Phase != "Running" || pod.Spec.ServiceAccountName != role.ServiceAccountName {
		return fail()
	}
	sa, err := kube.CoreV1().ServiceAccounts(role.Namespace).Get(ctx, role.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != role.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return fail()
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" {
		return fail()
	}
	rs, err := kube.AppsV1().ReplicaSets(role.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return fail()
	}
	deploymentOwner := metav1.GetControllerOf(rs)
	if deploymentOwner == nil || deploymentOwner.Kind != "Deployment" || deploymentOwner.Name != source.DeploymentName ||
		string(deploymentOwner.UID) != source.DeploymentUID {
		return fail()
	}
	deployment, err := kube.AppsV1().Deployments(role.Namespace).Get(ctx, source.DeploymentName, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != source.DeploymentUID || deployment.DeletionTimestamp != nil ||
		deployment.Spec.Template.Spec.ServiceAccountName != role.ServiceAccountName {
		return fail()
	}
	review, err := kube.AuthenticationV1().TokenReviews().Create(ctx, &authn.TokenReview{
		Spec: authn.TokenReviewSpec{Token: string(jwt), Audiences: []string{role.Audience}}}, metav1.CreateOptions{})
	if err != nil || !review.Status.Authenticated || review.Status.Error != "" ||
		review.Status.User.Username != claims.Subject || review.Status.User.UID != role.ServiceAccountUID ||
		len(review.Status.Audiences) != 1 || review.Status.Audiences[0] != role.Audience {
		return fail()
	}
	pods := review.Status.User.Extra["authentication.kubernetes.io/pod-uid"]
	if len(pods) != 1 || pods[0] != source.PodUID {
		return fail()
	}
	ok = true
	return jwt, nil
}

func (p *OriginalAdoptionArchiveProvider) sourcePath() (string, string, string, error) {
	kube, ctx := p.operator.installer.kube, p.ctx
	d, provider := p.definition, p.minio.Grant.Provider
	deployment, err := kube.AppsV1().Deployments(p.minio.Grant.Namespace).Get(ctx, provider.Deployment.Name, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != provider.Deployment.UID || deployment.DeletionTimestamp != nil ||
		deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 0 || deployment.Status.Replicas != 0 ||
		deployment.Status.ObservedGeneration < deployment.Generation {
		return "", "", "", ErrInstall
	}
	containerFound, volumeName := false, ""
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != provider.Container {
			continue
		}
		if containerFound {
			return "", "", "", ErrInstall
		}
		containerFound = true
		for _, mount := range container.VolumeMounts {
			if mount.MountPath == "/data" {
				if volumeName != "" || mount.SubPath != "" || mount.SubPathExpr != "" || mount.ReadOnly {
					return "", "", "", ErrInstall
				}
				volumeName = mount.Name
			}
		}
	}
	if !containerFound || volumeName == "" {
		return "", "", "", ErrInstall
	}
	volumeFound := false
	for _, volume := range deployment.Spec.Template.Spec.Volumes {
		if volume.Name == volumeName {
			volumeFound = true
			if volume.PersistentVolumeClaim == nil || volume.PersistentVolumeClaim.ClaimName != d.PVCName || volume.PersistentVolumeClaim.ReadOnly {
				return "", "", "", ErrInstall
			}
		} else if volume.PersistentVolumeClaim != nil || volume.HostPath != nil || volume.CSI != nil || volume.NFS != nil {
			return "", "", "", ErrInstall // Additional original roots need an explicit complete profile.
		}
	}
	if !volumeFound {
		return "", "", "", ErrInstall
	}
	claim, err := kube.CoreV1().PersistentVolumeClaims(p.minio.Grant.Namespace).Get(ctx, d.PVCName, metav1.GetOptions{})
	if err != nil || string(claim.UID) != d.PVCUID || claim.DeletionTimestamp != nil || claim.Spec.VolumeName != d.PVName || claim.Status.Phase != "Bound" {
		return "", "", "", ErrInstall
	}
	pv, err := kube.CoreV1().PersistentVolumes().Get(ctx, d.PVName, metav1.GetOptions{})
	if err != nil || string(pv.UID) != d.PVUID || pv.DeletionTimestamp != nil || pv.Spec.HostPath == nil ||
		pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != d.PVCUID ||
		pv.Spec.ClaimRef.Namespace != p.minio.Grant.Namespace || pv.Spec.ClaimRef.Name != d.PVCName {
		return "", "", "", ErrInstall
	}
	node, err := kube.CoreV1().Nodes().Get(ctx, provider.Node, metav1.GetOptions{})
	if err != nil || string(node.UID) != provider.NodeUID || node.DeletionTimestamp != nil ||
		node.Status.NodeInfo.BootID == "" || node.Status.NodeInfo.MachineID == "" {
		return "", "", "", ErrInstall
	}
	path := pv.Spec.HostPath.Path
	if path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", "", ErrInstall
	}
	return path, node.Status.NodeInfo.BootID, node.Status.NodeInfo.MachineID, nil
}

func (p *OriginalAdoptionArchiveProvider) observeSource() (string, error) {
	path, boot, machine, err := p.sourcePath()
	if err != nil {
		return "", ErrInstall
	}
	custody := p.custodyIdentity()
	if custody == "" {
		return "", ErrInstall
	}
	deployment, err := p.operator.installer.kube.AppsV1().Deployments(p.minio.Grant.Namespace).Get(
		p.ctx, p.minio.Grant.Provider.Deployment.Name, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != p.minio.Grant.Provider.Deployment.UID {
		return "", ErrInstall
	}
	specRaw, err := canonical(deployment.Spec)
	if err != nil {
		return "", ErrInstall
	}
	raw, err := canonical(struct{ Operation, Definition, Path, NodeUID, Boot, Machine, PVCUID, PVUID, Custody, DeploymentSpec string }{
		p.definition.OperationIdentitySHA256, p.definition.MinIODefinitionSHA256, path, p.minio.Grant.Provider.NodeUID,
		boot, machine, p.definition.PVCUID, p.definition.PVUID, custody, hash(specRaw)})
	if err != nil {
		return "", ErrInstall
	}
	return hash(raw), nil
}

func (p *OriginalAdoptionArchiveProvider) custodyIdentity() string {
	path, err := filepath.EvalSymlinks(p.definition.CustodyRoot)
	if err != nil || !filepath.IsAbs(path) || path != p.definition.CustodyRoot {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ""
	}
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return ""
	}
	uid, dev, inode := value.FieldByName("Uid"), value.FieldByName("Dev"), value.FieldByName("Ino")
	if !uid.IsValid() || !dev.IsValid() || !inode.IsValid() || !uid.CanUint() || !dev.CanUint() || !inode.CanUint() || uid.Uint() != uint64(os.Geteuid()) {
		return ""
	}
	raw, err := canonical(struct {
		Path, Source       string
		Device, Inode, UID uint64
	}{path, p.sourceSHA, dev.Uint(), inode.Uint(), uid.Uint()})
	if err != nil {
		return ""
	}
	return hash(raw)
}

type originalArchiveCredentials struct {
	p *OriginalAdoptionArchiveProvider
}

func (c originalArchiveCredentials) Resolve(ctx context.Context, key ev.KeyRef, operation ev.TransitOperation) (ev.TransitCredential, error) {
	p := c.p
	deny := func() (ev.TransitCredential, error) {
		if p != nil {
			p.fail()
		}
		return ev.TransitCredential{}, ErrInstall
	}
	if p == nil || !p.active.Load() || !consumerSameContext(ctx, p.ctx) || key != p.definition.Vault.Transit.Key || p.current() != nil {
		return deny()
	}
	role, source := p.definition.Vault.Wrap, p.definition.WrapJWT
	switch operation {
	case ev.TransitWrap:
		if p.wrapCalls.Add(1) != 1 {
			return deny()
		}
	case ev.TransitUnwrap:
		role, source = p.definition.Vault.Unwrap, p.definition.UnwrapJWT
		if p.wrapCalls.Load() != 1 || p.unwrapCalls.Add(1) != 1 {
			return deny()
		}
	default:
		return deny()
	}
	jwt, err := p.readJWT(source, role)
	if err != nil {
		return deny()
	}
	defer clear(jwt)
	body, err := json.Marshal(struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}{role.Role, string(jwt)})
	if err != nil {
		return deny()
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.definition.Vault.Transit.Endpoint+"/v1/auth/"+role.AuthMount+"/login", bytes.NewReader(body))
	if err != nil {
		return deny()
	}
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := p.client.Do(request)
	if err != nil {
		return deny()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return deny()
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return deny()
	}
	secret, ttl, err := originalArchiveBatchToken(raw, role.Role, role.Policy)
	if err != nil || originalArchiveLoginIdentity(raw, source.PodUID, role) != nil {
		clear(secret)
		return deny()
	}
	expiry := started.Add(ttl)
	if !time.Now().Before(expiry) || time.Now().Add(ttl+5*time.Second).After(p.until) ||
		p.checkJWT(source, role) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		clear(secret)
		return deny()
	}
	if _, err = p.currentSQL(false); err != nil {
		clear(secret)
		return deny()
	}
	return ev.TransitCredential{Key: key, Installation: p.reservation.InstallationID,
		Operation: operation, Secret: secret, ExpiresAt: expiry}, nil
}

func originalArchiveLoginIdentity(raw []byte, podUID string, role adapter.VaultPermissionRole) error {
	root, err := originalArchiveObject(raw)
	if err != nil {
		return ErrInstall
	}
	defer func() {
		for _, value := range root {
			clear(value)
		}
	}()
	auth, err := originalArchiveObject(root["auth"])
	if err != nil {
		return ErrInstall
	}
	defer func() {
		for _, value := range auth {
			clear(value)
		}
	}()
	metadata, err := originalArchiveObject(auth["metadata"])
	if err != nil {
		return ErrInstall
	}
	for name, expected := range map[string]string{"role": role.Role, "pod_uid": podUID,
		"namespace": role.Namespace, "service_account_uid": role.ServiceAccountUID} {
		var actual string
		if json.Unmarshal(metadata[name], &actual) != nil || actual != expected {
			return ErrInstall
		}
	}
	return nil
}

func originalArchiveObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInstall
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || result[name] != nil {
			return nil, ErrInstall
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrInstall
		}
		result[name] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, ErrInstall
	}
	return result, nil
}

func originalArchiveBatchToken(raw []byte, role, policy string) ([]byte, time.Duration, error) {
	deny := func() ([]byte, time.Duration, error) { return nil, 0, ErrInstall }
	root, err := originalArchiveObject(raw)
	if err != nil {
		return deny()
	}
	defer func() {
		for _, value := range root {
			clear(value)
		}
	}()
	for _, name := range []string{"errors", "wrap_info"} {
		if value, ok := root[name]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) &&
			!(name == "errors" && bytes.Equal(bytes.TrimSpace(value), []byte("[]"))) {
			return deny()
		}
	}
	auth, err := originalArchiveObject(root["auth"])
	if err != nil {
		return deny()
	}
	defer func() {
		for _, value := range auth {
			clear(value)
		}
	}()
	var token, kind string
	var ttl int64
	var policies []string
	if json.Unmarshal(auth["client_token"], &token) != nil || len(token) < 16 || len(token) > 4096 ||
		json.Unmarshal(auth["token_type"], &kind) != nil || kind != "batch" ||
		!bytes.Equal(bytes.TrimSpace(auth["renewable"]), []byte("false")) ||
		json.Unmarshal(auth["lease_duration"], &ttl) != nil || ttl < 1 || ttl > 20 ||
		json.Unmarshal(auth["policies"], &policies) != nil || len(policies) != 1 || policies[0] != policy {
		return deny()
	}
	for _, ch := range []byte(token) {
		if ch < 33 || ch > 126 {
			return deny()
		}
	}
	if v, ok := auth["token_policies"]; ok && (json.Unmarshal(v, &policies) != nil || len(policies) != 1 || policies[0] != policy) {
		return deny()
	}
	if v, ok := auth["identity_policies"]; ok && (json.Unmarshal(v, &policies) != nil || len(policies) != 0) {
		return deny()
	}
	metadata, err := originalArchiveObject(auth["metadata"])
	var actualRole string
	if err != nil || json.Unmarshal(metadata["role"], &actualRole) != nil || actualRole != role {
		return deny()
	}
	return []byte(token), time.Duration(ttl) * time.Second, nil
}
