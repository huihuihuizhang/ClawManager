package systembackup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/minio/minio-go/v7"
)

func minioGateJSON(raw []byte) bool {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		x, ok := t.(json.Delim)
		if !ok {
			return true
		}
		if x != '{' && x != '[' {
			return false
		}
		seen := map[string]bool{}
		count := 0
		for d.More() {
			count++
			if count > 10000 {
				return false
			}
			if x == '{' {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return false
				}
				seen[s] = true
			}
			if !value(depth + 1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && (x == '{' && end == json.Delim('}') || x == '[' && end == json.Delim(']'))
	}
	if !value(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func minioGateDecode(raw []byte, out any) error {
	if !minioGateJSON(raw) {
		return ErrMinIOReadGate
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrMinIOReadGate
	}
	return nil
}
func minioGateStream(raw []byte, visit func(json.RawMessage) error) error {
	if len(raw) > 4<<20 {
		return ErrMinIOReadGate
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	for count := 0; ; count++ {
		var item json.RawMessage
		e := d.Decode(&item)
		if e == io.EOF {
			return nil
		}
		if e != nil || count >= 1000 || !minioGateJSON(item) || visit(item) != nil {
			return ErrMinIOReadGate
		}
	}
}

type minioGateKV struct {
	Key, Value  string
	EnvOverride *struct{ Name, Value string } `json:"envOverride,omitempty"`
}
type minioGateConfig struct {
	SubSystem string        `json:"subSystem"`
	Target    string        `json:"target,omitempty"`
	KV        []minioGateKV `json:"kv"`
}

func (n *minioGateNative) config(ctx context.Context, subsystem string) ([]minioGateConfig, error) {
	b, e := n.mc(ctx, "admin", "config", "get", "native", subsystem)
	if e != nil {
		return nil, e
	}
	defer clear(b)
	var out struct {
		Status string            `json:"status"`
		Config []minioGateConfig `json:"config"`
	}
	if minioGateDecode(b, &out) != nil || out.Status != "success" || len(out.Config) < 1 || len(out.Config) > 64 {
		return nil, ErrMinIOReadGate
	}
	for _, c := range out.Config {
		if c.SubSystem != subsystem || len(c.KV) == 0 || len(c.KV) > 256 {
			return nil, ErrMinIOReadGate
		}
		seen := map[string]bool{}
		for _, kv := range c.KV {
			if kv.Key == "" || seen[kv.Key] {
				return nil, ErrMinIOReadGate
			}
			seen[kv.Key] = true
		}
	}
	return out.Config, nil
}
func (n *minioGateNative) apiConfig(ctx context.Context) (json.RawMessage, string, error) {
	c, e := n.config(ctx, "api")
	if e != nil || len(c) != 1 || c[0].Target != "" {
		return nil, "", ErrMinIOReadGate
	}
	root := ""
	for _, kv := range c[0].KV {
		if kv.Key == "root_access" {
			root = kv.Value
			if kv.EnvOverride != nil {
				if kv.EnvOverride.Name != "MINIO_API_ROOT_ACCESS" || kv.EnvOverride.Value != "off" {
					return nil, "", ErrMinIOReadGate
				}
				root = kv.EnvOverride.Value
			}
		}
	}
	if root != "on" && root != "off" {
		return nil, "", ErrMinIOReadGate
	}
	raw, _ := json.Marshal(c)
	return raw, root, nil
}
func minioGateComparableAPI(raw []byte) string {
	var c []minioGateConfig
	if minioGateDecode(raw, &c) != nil || len(c) != 1 {
		return ""
	}
	for n := range c[0].KV {
		if c[0].KV[n].Key == "root_access" {
			c[0].KV[n].Value = "<owned-root-access>"
		}
	}
	sort.Slice(c[0].KV, func(a, b int) bool { return c[0].KV[a].Key < c[0].KV[b].Key })
	return minioGateHash(c)
}

func (n *minioGateNative) user(ctx context.Context, name string) (minioGateUser, error) {
	var zero minioGateUser
	b, status, e := n.request(ctx, 1, "GET", "/minio/admin/v3/user-info", url.Values{"accessKey": {name}}, nil)
	var u struct {
		SecretKey, PolicyName, Status string
		MemberOf                      []string
		UpdatedAt                     json.RawMessage
		AuthInfo                      *struct{ Type, AuthServer, AuthServerUserID string } `json:"userAuthInfo,omitempty"`
	}
	if e != nil || status != 200 || minioGateDecode(b, &u) != nil || u.SecretKey != "" || len(u.MemberOf) != 0 || u.Status != "enabled" && u.Status != "disabled" || u.UpdatedAt == nil || u.AuthInfo != nil && (u.AuthInfo.Type != "builtin" || u.AuthInfo.AuthServer != "" || u.AuthInfo.AuthServerUserID != name) {
		return zero, ErrMinIOReadGate
	}
	if u.PolicyName == "" {
		// RawMessage(nil) serializes as null but unmarshals as bytes("null").
		// Preserve this native absent-policy state canonically before sealing,
		// so complete original readback remains exact after process restart.
		return minioGateUser{Name: name, Status: u.Status, Policy: json.RawMessage("null")}, nil
	}
	if !minioGateName(u.PolicyName) {
		return zero, ErrMinIOReadGate
	}
	p, status, e := n.request(ctx, 1, "GET", "/minio/admin/v3/info-canned-policy", url.Values{"name": {u.PolicyName}, "v": {"2"}}, nil)
	var policy struct {
		PolicyName             string
		Policy                 json.RawMessage
		CreateDate, UpdateDate json.RawMessage
	}
	if e != nil || status != 200 || minioGateDecode(p, &policy) != nil || policy.PolicyName != u.PolicyName || !minioGateJSON(policy.Policy) {
		return zero, ErrMinIOReadGate
	}
	return minioGateUser{Name: name, Status: u.Status, PolicyName: u.PolicyName, Policy: policy.Policy}, nil
}
func (n *minioGateNative) users(ctx context.Context) ([]minioGateUser, error) {
	b, e := n.mc(ctx, "admin", "user", "list", "native")
	if e != nil {
		return nil, e
	}
	defer clear(b)
	seen := map[string]bool{}
	out := []minioGateUser{}
	e = minioGateStream(b, func(raw json.RawMessage) error {
		var u struct {
			Status, AccessKey, SecretKey, PolicyName, UserStatus, Authentication string
			MemberOf                                                             []json.RawMessage
		}
		if minioGateDecode(raw, &u) != nil || u.Status != "success" || !minioGateName(u.AccessKey) || u.SecretKey != "" || len(u.MemberOf) != 0 || seen[u.AccessKey] || u.Authentication != "" && u.Authentication != "builtin" {
			return ErrMinIOReadGate
		}
		seen[u.AccessKey] = true
		item, e := n.user(ctx, u.AccessKey)
		if e != nil || item.Status != u.UserStatus || item.PolicyName != u.PolicyName {
			return ErrMinIOReadGate
		}
		out = append(out, item)
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}
func (n *minioGateNative) noDerived(ctx context.Context) error {
	// --all is explicit: mc must not fall back to listing only itself.
	b, e := n.mc(ctx, "admin", "accesskey", "list", "--all", "native")
	if e != nil {
		return e
	}
	defer clear(b)
	seen := map[string]bool{}
	return minioGateStream(b, func(raw json.RawMessage) error {
		var r struct {
			Status, User    string
			STSKeys         []json.RawMessage `json:"stsKeys"`
			ServiceAccounts []json.RawMessage `json:"svcaccs"`
			LDAP            bool              `json:"ldap,omitempty"`
		}
		if minioGateDecode(raw, &r) != nil || r.Status != "success" || !minioGateName(r.User) || seen[r.User] || r.LDAP || len(r.STSKeys) != 0 || len(r.ServiceAccounts) != 0 {
			return ErrMinIOReadGate
		}
		seen[r.User] = true
		return nil
	})
}

func (g *MinIOReadServiceGate) collect(ctx context.Context) (*minioGateOriginal, error) {
	if g.identity(ctx, false) != nil {
		return nil, ErrMinIOReadGate
	}
	api, root, e := g.native.apiConfig(ctx)
	if e != nil {
		return nil, e
	}
	users, e := g.native.users(ctx)
	if e != nil || g.native.noDerived(ctx) != nil {
		return nil, ErrMinIOReadGate
	}
	keeper, reader, rootUser := false, false, false
	kp, rp, e := MinIOReadGatePolicies(g.in.BusinessBuckets)
	if e != nil {
		return nil, e
	}
	for _, u := range users {
		switch u.Name {
		case g.credentials[0].AccessKey:
			rootUser = true
		case g.credentials[1].AccessKey:
			keeper = u.Status == "enabled" && minioGateSamePolicy(u.Policy, kp)
		case g.credentials[2].AccessKey:
			reader = u.Status == "enabled" && minioGateSamePolicy(u.Policy, rp)
		}
	}
	if rootUser || !keeper || !reader {
		return nil, ErrMinIOReadGate
	}
	for _, name := range g.in.OutputAccounts {
		found := false
		for _, u := range users {
			if u.Name == name {
				if found || u.Status != "enabled" || !minioGateOutputPolicy(u.Policy, g.in.BusinessBuckets) {
					return nil, ErrMinIOReadGate
				}
				found = true
			}
		}
		if !found {
			return nil, ErrMinIOReadGate
		}
	}
	all, e := g.admin.ListBuckets(ctx)
	if e != nil || len(all) > 1000 {
		return nil, ErrMinIOReadGate
	}
	names := []string{}
	seen := map[string]bool{}
	for _, bucket := range all {
		if bucket.Name == "" || seen[bucket.Name] {
			return nil, ErrMinIOReadGate
		}
		seen[bucket.Name] = true
		names = append(names, bucket.Name)
	}
	sort.Strings(names)
	policies := map[string]string{}
	for _, bucket := range g.in.BusinessBuckets {
		if !seen[bucket] {
			return nil, ErrMinIOReadGate
		}
		policies[bucket], e = g.native.bucketPolicy(ctx, bucket)
		if e != nil {
			return nil, e
		}
		// Supported first native profile has no configured asynchronous source
		// transformation. Presence (even a disabled/unknown future rule) refuses.
		l, e := g.admin.GetBucketLifecycle(ctx, bucket)
		if e != nil && !minioGateS3Missing(e, "NoSuchLifecycleConfiguration") {
			return nil, ErrMinIOReadGate
		}
		if e == nil && l != nil && len(l.Rules) != 0 {
			return nil, ErrMinIOReadGate
		}
		r, e := g.admin.GetBucketReplication(ctx, bucket)
		if e != nil && !minioGateS3Missing(e, "ReplicationConfigurationNotFoundError") {
			return nil, ErrMinIOReadGate
		}
		if e == nil && len(r.Rules) != 0 {
			return nil, ErrMinIOReadGate
		}
	}
	if g.native.noBackground(ctx) != nil || g.identity(ctx, false) != nil {
		return nil, ErrMinIOReadGate
	}
	out := &minioGateOriginal{Version: "original-minio-read-gate-state.v1", Input: g.in, RootAccount: g.credentials[0].AccessKey, KeeperAccount: g.credentials[1].AccessKey, ReaderAccount: g.credentials[2].AccessKey, CredentialBinding: minioGateCredentialBinding(g.credentials), RootAccess: root, APIConfig: api, Users: users, BucketPolicies: policies, BucketNames: names}
	out.ContainerID = g.containerID
	out.CaptureUntil = g.until
	if g.recovering {
		out.CaptureUntil = g.original.CaptureUntil
	}
	return out, nil
}
func minioGateCredentialBinding(creds [3]MinIOGateCredential) string {
	type pin struct{ Account, Version, SecretSHA string }
	p := []pin{}
	for _, c := range creds {
		p = append(p, pin{c.AccessKey, c.Version, minioGateBytesHash(c.SecretKey)})
	}
	return minioGateHash(p)
}

func (g *MinIOReadServiceGate) recheckRecoverable(ctx context.Context) error {
	current, e := g.collect(ctx)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(current.Input, g.original.Input) || current.CredentialBinding != g.original.CredentialBinding || minioGateComparableAPI(current.APIConfig) != minioGateComparableAPI(g.original.APIConfig) || !reflect.DeepEqual(current.BucketNames, g.original.BucketNames) || len(current.Users) != len(g.original.Users) {
		return ErrMinIOReadGate
	}
	if current.RootAccess != "off" && current.RootAccess != g.original.RootAccess {
		return ErrMinIOReadGate
	}
	for n, u := range current.Users {
		old := g.original.Users[n]
		if u.Name != old.Name || u.PolicyName != old.PolicyName || !bytes.Equal(u.Policy, old.Policy) || u.Status != old.Status && u.Status != "disabled" {
			return ErrMinIOReadGate
		}
	}
	for b, p := range current.BucketPolicies {
		if p != "" && p != g.original.BucketPolicies[b] {
			return ErrMinIOReadGate
		}
	}
	return nil
}
func (g *MinIOReadServiceGate) recheckState(ctx context.Context, held bool) error {
	if g.guard(ctx) != nil {
		return ErrMinIOReadGate
	}
	current, e := g.collect(ctx)
	if e != nil {
		return e
	}
	expected := g.original
	expected.Users = append([]minioGateUser(nil), g.original.Users...)
	expected.BucketPolicies = map[string]string{}
	for b, p := range g.original.BucketPolicies {
		expected.BucketPolicies[b] = p
	}
	if held {
		expected.RootAccess = "off"
		for n := range expected.Users {
			u := &expected.Users[n]
			if !g.keptAccount(u.Name) {
				u.Status = "disabled"
			}
		}
		for b := range expected.BucketPolicies {
			expected.BucketPolicies[b] = ""
		}
	}
	if minioGateComparableAPI(current.APIConfig) != minioGateComparableAPI(expected.APIConfig) {
		return ErrMinIOReadGate
	}
	current.APIConfig = expected.APIConfig
	if !reflect.DeepEqual(*current, expected) {
		return ErrMinIOReadGate
	}
	return g.native.rootAccessProbe(ctx, held || g.original.RootAccess == "off")
}
func (g *MinIOReadServiceGate) readProbe(ctx context.Context) error {
	for _, bucket := range g.in.BusinessBuckets {
		if _, e := g.reader.GetBucketVersioning(ctx, bucket); e != nil {
			return ErrMinIOReadGate
		}
		// Permission probe only: this is explicitly NOT a historical EOF walk.
		child, cancel := context.WithCancel(ctx)
		ch := g.reader.ListObjects(child, bucket, minio.ListObjectsOptions{WithVersions: true, MaxKeys: 1, Recursive: true})
		item, ok := <-ch
		cancel()
		if ok && item.Err != nil {
			return ErrMinIOReadGate
		}
		if ok && !item.IsDeleteMarker && item.Size > 0 {
			o, e := g.reader.GetObject(ctx, bucket, item.Key, minio.GetObjectOptions{VersionID: item.VersionID})
			if e != nil {
				return ErrMinIOReadGate
			}
			var sample [1]byte
			_, e = io.ReadFull(o, sample[:])
			ce := o.Close()
			if e != nil || ce != nil {
				return ErrMinIOReadGate
			}
		}
	}
	return nil
}
func (n *minioGateNative) rootAccessProbe(ctx context.Context, disabled bool) error {
	b, status, e := n.request(ctx, 0, "GET", "/minio/admin/v3/help-config-kv", url.Values{"subSys": {"policy_plugin"}, "key": {""}}, nil)
	if e != nil {
		return e
	}
	if !disabled {
		if status != 200 || !minioGateJSON(b) {
			return ErrMinIOReadGate
		}
		return nil
	}
	var r struct {
		Code, Message, Resource string
		RequestID               string `json:"RequestId"`
		HostID                  string `json:"HostId"`
		Region                  string
	}
	if status != 403 || minioGateDecode(b, &r) != nil || r.Code != "InvalidAccessKeyId" || r.Message != "Your account is disabled; please contact your administrator." || r.Resource != "/minio/admin/v3/help-config-kv" || r.RequestID == "" {
		return ErrMinIOReadGate
	}
	return nil
}

// External identity/policy and asynchronous namespace changes are actual native
// inputs. Unknown/nonempty profiles fail; they are never silently made empty.
func (n *minioGateNative) noBackground(ctx context.Context) error {
	for _, sub := range []string{"policy_plugin", "policy_opa", "identity_ldap", "identity_openid", "identity_tls", "identity_plugin", "etcd"} {
		configs, e := n.config(ctx, sub)
		if e != nil {
			return e
		}
		for _, c := range configs {
			if c.Target != "" {
				return ErrMinIOReadGate
			}
			for _, kv := range c.KV {
				v := kv.Value
				if kv.EnvOverride != nil {
					v = kv.EnvOverride.Value
				}
				switch kv.Key {
				case "enable":
					if v != "off" && v != "false" && v != "" {
						return ErrMinIOReadGate
					}
				case "url", "endpoint", "endpoints", "server_addr", "config_url", "role_policy", "path_prefix":
					if strings.TrimSpace(v) != "" {
						return ErrMinIOReadGate
					}
				}
			}
		}
	}
	// These exact APIs are unpaginated complete JSON replies in the pinned
	// September server. Any unknown field/shape or active job/peer refuses.
	b, status, e := n.request(ctx, 1, "GET", "/minio/admin/v3/site-replication/info", url.Values{"api-version": {"1"}}, nil)
	var site struct {
		Enabled                 *bool             `json:"enabled"`
		Name                    string            `json:"name"`
		Sites                   []json.RawMessage `json:"sites"`
		ServiceAccountAccessKey string            `json:"serviceAccountAccessKey,omitempty"`
		APIVersion              string            `json:"apiVersion,omitempty"`
	}
	if e != nil || status != 200 || minioGateDecode(b, &site) != nil || site.Enabled == nil || *site.Enabled || len(site.Sites) != 0 || site.ServiceAccountAccessKey != "" || site.APIVersion != "" && site.APIVersion != "1" {
		return ErrMinIOReadGate
	}
	b, status, e = n.request(ctx, 1, "GET", "/minio/admin/v3/list-jobs", url.Values{"jobType": {""}}, nil)
	var jobs struct {
		Jobs json.RawMessage `json:"jobs"`
	}
	if e != nil || status != 200 || minioGateDecode(b, &jobs) != nil || jobs.Jobs == nil {
		return ErrMinIOReadGate
	}
	var list []json.RawMessage
	if minioGateDecode(jobs.Jobs, &list) != nil || len(list) != 0 {
		return ErrMinIOReadGate
	}
	return nil
}
