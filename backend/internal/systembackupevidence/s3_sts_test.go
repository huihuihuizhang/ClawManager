package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type stsAuthorityFunc func(context.Context, S3Scope) (S3WebIdentityGrant, error)

func (f stsAuthorityFunc) AuthorizeS3(ctx context.Context, v S3Scope) (S3WebIdentityGrant, error) {
	return f(ctx, v)
}

type stsFixture struct {
	resolver *S3STSCredentials
	config   S3STSConfig
	scope    S3Scope
	identity Identity
	until    time.Time
	requests atomic.Int32
	owned    [][]byte
	policy   atomic.Value
}

func newSTSFixture(t *testing.T, mode string) *stsFixture {
	t.Helper()
	_, identity, _ := sanitizedLogFixture(t)
	key, _ := keyFor("evidence", identity)
	f := &stsFixture{identity: identity, until: time.Now().UTC().Add(2 * time.Minute)}
	f.scope = S3Scope{Ref: Ref{strings.Repeat("a", 64), "v1", key, "object-v1"}, Operation: S3Range, Offset: 12, Length: 100}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			if !verifyS3Wire(r) || r.URL.Query().Get("versionId") != "object-v1" {
				t.Error("issued credentials did not sign exact S3 version")
				w.WriteHeader(403)
				return
			}
			digest, _ := hex.DecodeString(identity.ContentHash)
			w.Header().Set("X-Amz-Version-Id", "object-v1")
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
			w.Header().Set("Content-Length", "123")
			return
		}
		f.requests.Add(1)
		if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.Path != "/" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("unsafe STS transport")
			w.WriteHeader(403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32768)
		if r.ParseForm() != nil || len(r.Form) != 7 {
			t.Error("wrong STS query profile")
			w.WriteHeader(400)
			return
		}
		for _, values := range r.Form {
			if len(values) != 1 {
				t.Error("duplicate form")
				w.WriteHeader(400)
				return
			}
		}
		if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("Version") != "2011-06-15" || r.Form.Get("DurationSeconds") != "900" || r.Form.Get("RoleArn") != "arn:aws:iam::123456789012:role/evidence" || r.Form.Get("WebIdentityToken") != "synthetic.oidc.token" {
			t.Error("incorrect STS identity request")
			w.WriteHeader(403)
			return
		}
		f.policy.Store(r.Form.Get("Policy"))
		session := r.Form.Get("RoleSessionName")
		if len(session) != 41 || !strings.HasPrefix(session, "evidence-") {
			t.Error("session name must be opaque")
		}
		if mode == "denied" {
			w.WriteHeader(403)
			io.WriteString(w, "private provider error")
			return
		}
		if mode == "redirect" {
			w.Header().Set("Location", "/credential-sink")
			w.WriteHeader(307)
			return
		}
		if mode == "encoding" {
			w.Header().Set("Content-Encoding", "gzip")
		}
		expires := time.Now().UTC().Add(899 * time.Second).Format(time.RFC3339)
		body := fmt.Sprintf(`<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>evidence-client</Audience><Provider>https://issuer.example</Provider><SubjectFromWebIdentityToken>task-subject</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser><PackedPolicySize>10</PackedPolicySize></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, expires, session, session)
		switch mode {
		case "duplicate":
			body = strings.Replace(body, "</AccessKeyId>", "</AccessKeyId><AccessKeyId>private</AccessKeyId>", 1)
		case "unknown":
			body = strings.Replace(body, "</Credentials>", "<Private>secret</Private></Credentials>", 1)
		case "namespace":
			body = strings.Replace(body, stsNamespace, "https://wrong.example", 1)
		case "attribute":
			body = strings.Replace(body, "<Credentials>", `<Credentials private="secret">`, 1)
		case "duplicate-xmlns":
			body = strings.Replace(body, `xmlns="`+stsNamespace+`"`, `xmlns="`+stsNamespace+`" xmlns="`+stsNamespace+`"`, 1)
		case "dtd":
			body = `<!DOCTYPE foo [<!ENTITY private SYSTEM "file:///secret">]>` + body
		case "trailing":
			body += body
		case "mixed":
			body = "private" + body
		case "oversize":
			body += strings.Repeat(" ", 65536)
		case "audience":
			body = strings.Replace(body, "evidence-client", "other-client", 1)
		case "issuer":
			body = strings.Replace(body, "https://issuer.example", "https://wrong.example", 1)
		case "subject":
			body = strings.Replace(body, "task-subject", "wrong-subject", 1)
		case "role":
			body = strings.Replace(body, "assumed-role/evidence/", "assumed-role/other/", 1)
		case "session":
			body = strings.Replace(body, "ROLEID:"+session, "ROLEID:other", 1)
		case "missing-token":
			body = strings.Replace(body, "<SessionToken>"+s3TestSession+"</SessionToken>", "", 1)
		case "expired":
			body = strings.Replace(body, expires, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), 1)
		case "too-long":
			body = strings.Replace(body, expires, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), 1)
		case "policy-size":
			body = strings.Replace(body, "<PackedPolicySize>10", "<PackedPolicySize>101", 1)
		case "whitespace-key":
			body = strings.Replace(body, s3TestSecret, "private credential with whitespace", 1)
		case "comment":
			body = "<!--private-->" + body
		}
		w.Header().Set("Content-Type", "text/xml")
		io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	f.config = S3STSConfig{Store: S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "test-bucket", Root: "evidence", Installation: identity.Installation, Identity: f.scope.Ref.Identity, Version: "v1", CAPEM: ca, CASHA256: hash(ca)}, Endpoint: server.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence", Issuer: "https://issuer.example", Audience: "evidence-client", CAPEM: ca, CASHA256: hash(ca)}
	a := stsAuthorityFunc(func(_ context.Context, v S3Scope) (S3WebIdentityGrant, error) { return f.grant(v), nil })
	var err error
	f.resolver, err = NewS3STSCredentials(f.config, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.resolver.Close)
	return f
}

func (f *stsFixture) grant(v S3Scope) S3WebIdentityGrant {
	token := []byte("synthetic.oidc.token")
	f.owned = append(f.owned, token)
	kind, attempt := "task", int64(1)
	if v.Operation == S3Delete {
		kind, attempt = "gc", 0
	}
	return S3WebIdentityGrant{Authorization: S3Authorization{Scope: v, Evidence: f.identity, ConfigVersion: 1, AccessKind: kind, AttemptNumber: attempt, PrincipalHash: strings.Repeat("b", 64), LeaseHash: strings.Repeat("c", 64), Subject: "task-subject", ExpiresAt: f.until}, Token: token, TokenExpiresAt: f.until.Add(time.Minute)}
}

// A small policy evaluator in the independent mock provider tests actual wire
// policy behavior, including explicit denial against extra resource-policy grants.
func stsPolicyAllows(t *testing.T, raw, action, resource, version, condition string, secure bool, now time.Time, extraGrant bool) bool {
	t.Helper()
	var policy struct {
		Version   string
		Statement []struct {
			Effect, Action, NotAction, Resource, NotResource string
			Condition                                        map[string]map[string]string
		}
	}
	if json.Unmarshal([]byte(raw), &policy) != nil || policy.Version != "2012-10-17" || len(raw) > 2048 {
		t.Fatal("invalid wire policy")
	}
	match := func(pattern, value string) bool { return pattern == "*" || pattern == value }
	allowed := extraGrant
	for _, s := range policy.Statement {
		if s.Action != "" && !match(s.Action, action) || s.NotAction != "" && match(s.NotAction, action) || s.Resource != "" && !match(s.Resource, resource) || s.NotResource != "" && match(s.NotResource, resource) {
			continue
		}
		applies := true
		for operator, keys := range s.Condition {
			for key, want := range keys {
				switch operator {
				case "DateGreaterThanEquals":
					if key != "aws:CurrentTime" {
						t.Fatal("unexpected date key")
					}
					limit, e := time.Parse(time.RFC3339, want)
					if e != nil {
						t.Fatal(e)
					}
					applies = applies && !now.Before(limit)
				case "BoolIfExists":
					if key != "aws:SecureTransport" || want != "false" {
						t.Fatal("unexpected bool")
					}
					applies = applies && !secure
				case "StringNotEquals":
					actual := ""
					switch key {
					case "s3:VersionId":
						actual = version
					case "s3:if-none-match":
						actual = condition
					default:
						t.Fatal("unknown condition")
					}
					applies = applies && actual != want
				default:
					t.Fatal("unknown policy operator")
				}
			}
		}
		if applies {
			if s.Effect == "Deny" {
				return false
			}
			if s.Effect != "Allow" {
				t.Fatal("unknown effect")
			}
			allowed = true
		}
	}
	return allowed
}

func TestSTSExactObjectPolicyAndS3Integration(t *testing.T) {
	f := newSTSFixture(t, "")
	for _, op := range []S3Operation{S3Stat, S3Range, S3Put, S3Delete} {
		v := f.scope
		v.Operation = op
		if op != S3Range {
			v.Offset, v.Length = 0, 0
		}
		if op == S3Put {
			v.Ref.ImmutableVersion = ""
			v.Object = ObjectInfo{SHA256: strings.Repeat("d", 64), Size: 100}
			v.Deadline = time.Now().Add(30 * time.Second)
		}
		if op == S3Delete {
			v.Object = ObjectInfo{Version: v.Ref.ImmutableVersion, SHA256: strings.Repeat("d", 64), Size: 100}
		}
		g, err := f.resolver.Resolve(context.Background(), v)
		if err != nil || g.Scope != v || len(g.SessionToken) == 0 || !g.ExpiresAt.Before(time.Now().Add(61*time.Second)) {
			t.Fatal("exchange failed", op, err)
		}
		resource := "arn:aws:s3:::test-bucket/" + v.Ref.RelativeKey
		action := "s3:GetObjectVersion"
		if op == S3Put {
			action = "s3:PutObject"
		}
		if op == S3Delete {
			action = "s3:DeleteObjectVersion"
		}
		if !stsPolicyAllows(t, f.policy.Load().(string), action, resource, v.Ref.ImmutableVersion, "*", true, time.Now(), false) {
			t.Fatal("exact operation denied")
		}
		for _, attack := range []string{"object", "action", "expiry", "tls", "version", "condition"} {
			a, r, version, condition, secure, now := action, resource, v.Ref.ImmutableVersion, "*", true, time.Now()
			switch attack {
			case "object":
				r += "-other"
			case "action":
				a = "s3:ListBucket"
			case "expiry":
				now = g.ExpiresAt
			case "tls":
				secure = false
			case "version":
				if op == S3Put {
					continue
				}
				version = "wrong"
			case "condition":
				if op != S3Put {
					continue
				}
				condition = ""
			}
			if stsPolicyAllows(t, f.policy.Load().(string), a, r, version, condition, secure, now, true) {
				t.Fatal("policy scope escaped", op, attack)
			}
		}
		wipe(g.AccessKey)
		wipe(g.SecretKey)
		wipe(g.SessionToken)
	}
	// STS result is consumed by the existing S3 SigV4 client, not merely returned.
	store, err := NewS3Store(f.config.Store, f.resolver, s3AbsenceFunc(func(context.Context, S3AbsenceRequest) (S3AbsenceProof, error) { return S3AbsenceProof{}, ErrDenied }))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for n := 0; n < 2; n++ {
		info, err := store.Stat(context.Background(), f.scope.Ref)
		if err != nil || info.Version != "object-v1" || info.Size != 123 {
			t.Fatal("STS/S3 integration", err)
		}
	}
	if f.requests.Load() != 6 || len(f.owned) != 12 {
		t.Fatal("credentials were cached")
	}
	for _, b := range f.owned {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("OIDC token copy not erased")
		}
	}
}

func TestSTSResponseRejection(t *testing.T) {
	for _, mode := range []string{"denied", "redirect", "encoding", "duplicate", "unknown", "namespace", "attribute", "duplicate-xmlns", "dtd", "trailing", "mixed", "oversize", "audience", "issuer", "subject", "role", "session", "missing-token", "expired", "too-long", "policy-size", "whitespace-key", "comment"} {
		t.Run(mode, func(t *testing.T) {
			f := newSTSFixture(t, mode)
			g, err := f.resolver.Resolve(context.Background(), f.scope)
			if err != ErrDenied || len(g.AccessKey)+len(g.SecretKey)+len(g.SessionToken) != 0 || f.requests.Load() != 1 {
				t.Fatal("response was accepted/retried or leaked", err)
			}
			for _, b := range f.owned {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("denied token not erased")
				}
			}
		})
	}
}

func TestSTSAuthorizationRejection(t *testing.T) {
	for _, mode := range []string{"error", "scope", "evidence", "config", "principal", "lease", "subject", "expired", "token-expired", "token-invalid", "kind", "attempt", "download-write", "gc-write", "task-delete", "revoke-after", "rotate-after", "token-window-after", "cancel-after"} {
		t.Run(mode, func(t *testing.T) {
			f := newSTSFixture(t, "")
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "download-write" || mode == "gc-write" {
				f.scope.Operation = S3Put
				f.scope.Ref.ImmutableVersion = ""
				f.scope.Offset = 0
				f.scope.Length = 0
				f.scope.Object = ObjectInfo{SHA256: strings.Repeat("d", 64), Size: 100}
				f.scope.Deadline = time.Now().Add(time.Minute)
			}
			if mode == "task-delete" {
				f.scope.Operation = S3Delete
				f.scope.Offset = 0
				f.scope.Length = 0
				f.scope.Object = ObjectInfo{Version: f.scope.Ref.ImmutableVersion, SHA256: strings.Repeat("d", 64), Size: 100}
			}
			f.resolver.authority = stsAuthorityFunc(func(_ context.Context, v S3Scope) (S3WebIdentityGrant, error) {
				calls++
				g := f.grant(v)
				switch mode {
				case "error":
					return g, errors.New("private credential")
				case "scope":
					g.Authorization.Scope.Length++
				case "evidence":
					g.Authorization.Evidence.ID = "sev_22222222-2222-4333-8444-555555555555"
				case "config":
					g.Authorization.ConfigVersion = 0
				case "principal":
					g.Authorization.PrincipalHash = ""
				case "lease":
					g.Authorization.LeaseHash = ""
				case "subject":
					g.Authorization.Subject = ""
				case "expired":
					g.Authorization.ExpiresAt = time.Now().Add(-time.Second)
				case "token-expired":
					g.TokenExpiresAt = time.Now().Add(-time.Second)
				case "token-invalid":
					g.Token[0] = ' '
				case "kind":
					g.Authorization.AccessKind = "admin"
				case "attempt":
					g.Authorization.AttemptNumber = 0
				case "download-write":
					g.Authorization.AccessKind = "download"
					g.Authorization.AttemptNumber = 0
				case "gc-write":
					g.Authorization.AccessKind = "gc"
					g.Authorization.AttemptNumber = 0
				case "task-delete":
					g.Authorization.AccessKind = "task"
					g.Authorization.AttemptNumber = 1
				case "revoke-after":
					if calls == 2 {
						return g, errors.New("revoked private")
					}
				case "rotate-after":
					if calls == 2 {
						g.Authorization.ConfigVersion++
					}
				case "cancel-after":
					if calls == 2 {
						cancel()
					}
				case "token-window-after":
					if calls == 2 {
						g.TokenExpiresAt = time.Now().Add(5 * time.Second)
					}
				}
				return g, nil
			})
			g, err := f.resolver.Resolve(ctx, f.scope)
			if err != ErrDenied || len(g.SessionToken) != 0 {
				t.Fatal("authorization accepted", err)
			}
			want := int32(0)
			if strings.HasSuffix(mode, "-after") {
				want = 1
			}
			if f.requests.Load() != want {
				t.Fatal("unexpected STS side effect")
			}
			for _, b := range f.owned {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Fatal("authority error token not erased")
				}
			}
		})
	}
}

func TestSTSUnversionedStatAndGrantDeadline(t *testing.T) {
	f := newSTSFixture(t, "")
	v := f.scope
	v.Operation = S3Stat
	v.Ref.ImmutableVersion = ""
	v.Offset = 0
	v.Length = 0
	f.until = time.Now().UTC().Add(20 * time.Second)
	f.resolver.authority = stsAuthorityFunc(func(_ context.Context, scope S3Scope) (S3WebIdentityGrant, error) {
		g := f.grant(scope)
		g.Authorization.AccessKind = "download"
		g.Authorization.AttemptNumber = 0
		return g, nil
	})
	g, err := f.resolver.Resolve(context.Background(), v)
	if err != nil || g.ExpiresAt.After(f.until) {
		t.Fatal("grant deadline lost", err)
	}
	defer wipe(g.AccessKey)
	defer wipe(g.SecretKey)
	defer wipe(g.SessionToken)
	resource := "arn:aws:s3:::test-bucket/" + v.Ref.RelativeKey
	policy := f.policy.Load().(string)
	if !stsPolicyAllows(t, policy, "s3:GetObject", resource, "", "", true, time.Now(), false) || stsPolicyAllows(t, policy, "s3:GetObjectVersion", resource, "old", "", true, time.Now(), true) {
		t.Fatal("pending-key stat widened to historical versions")
	}
	// A policy larger than STS's limit must fail before sending any credentials.
	f.config.Store.Root = strings.Repeat("a", 700)
	f.resolver.config.Store.Root = f.config.Store.Root
	v.Ref.RelativeKey, _ = keyFor(f.config.Store.Root, f.identity)
	if _, err := f.resolver.Resolve(context.Background(), v); err != ErrDenied || f.requests.Load() != 1 {
		t.Fatal("oversize policy sent or truncated")
	}
}

func TestSTSScopeConfigurationAndTLS(t *testing.T) {
	f := newSTSFixture(t, "")
	for _, mode := range []string{"unknown", "provider", "prefix", "version", "policy-variable", "range", "overflow", "extra-object", "extra-deadline"} {
		v := f.scope
		switch mode {
		case "unknown":
			v.Operation = "wildcard"
		case "provider":
			v.Ref.Identity = strings.Repeat("0", 64)
		case "prefix":
			v.Ref.RelativeKey = "outside/key"
		case "version":
			v.Ref.ImmutableVersion = ""
		case "policy-variable":
			v.Ref.ImmutableVersion = "${aws:username}"
		case "range":
			v.Length = ChunkSize + 29
		case "overflow":
			v.Offset = 1 << 62
		case "extra-object":
			v.Object.Size = 1
		case "extra-deadline":
			v.Deadline = time.Now().Add(time.Minute)
		}
		if _, err := f.resolver.Resolve(context.Background(), v); err != ErrDenied {
			t.Fatal("scope accepted", mode)
		}
	}
	if f.requests.Load() != 0 {
		t.Fatal("invalid scope reached provider")
	}
	for _, mode := range []string{"http", "query", "userinfo", "role", "audience", "ca", "store-ca", "issuer", "wildcard-root", "bucket"} {
		c := f.config
		switch mode {
		case "http":
			c.Endpoint = "http://issuer.example"
		case "query":
			c.Endpoint += "?secret=private"
		case "userinfo":
			c.Endpoint = "https://user:private@host"
		case "role":
			c.RoleARN = "arn:aws:iam::123456789012:role/*"
		case "audience":
			c.Audience = ""
		case "ca":
			c.CASHA256 = strings.Repeat("0", 64)
		case "store-ca":
			c.Store.CASHA256 = strings.Repeat("0", 64)
		case "issuer":
			c.Issuer = "http://issuer.example"
		case "wildcard-root":
			c.Store.Root = "evidence/*"
		case "bucket":
			c.Store.Bucket = "test/other"
		}
		if r, err := NewS3STSCredentials(c, f.resolver.authority); err != ErrInvalid {
			if r != nil {
				r.Close()
			}
			t.Fatal("bad configuration accepted", mode)
		}
	}
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("token reached untrusted TLS endpoint") }))
	defer other.Close()
	// httptest default certificates are shared; force a hostname mismatch instead.
	c := f.config
	c.Endpoint = strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	r, err := NewS3STSCredentials(c, f.resolver.authority)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.Resolve(context.Background(), f.scope); err != ErrDenied {
		t.Fatal("TLS mismatch accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = f.resolver.Resolve(ctx, f.scope); err != ErrDenied {
		t.Fatal("cancel accepted")
	}
	if _, err = NewS3STSCredentials(f.config, nil); err != ErrInvalid {
		t.Fatal("missing authority accepted")
	}
}
