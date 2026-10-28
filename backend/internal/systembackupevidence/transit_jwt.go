package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// SQL authorities permit five seconds of database clock skew. Reserve it when
// bounding a provider's real TTL, not just the client's usable expiry.
const transitClockMargin = 5 * time.Second

// transitJWTExchange exchanges one projected identity for a nonrenewable,
// narrowly reviewed batch token. Callers must authorize before and after it.
// until already includes the database clock margin. No caching or retries.
func transitJWTExchange(ctx context.Context, client *http.Client, c TransitJWTConfig, jwt []byte, until time.Time) ([]byte, time.Time, error) {
	deny := func() ([]byte, time.Time, error) { return nil, time.Time{}, ErrKey }
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if ctx.Err() != nil {
		return deny()
	}
	body, err := json.Marshal(struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}{c.Role, string(jwt)})
	if err != nil {
		return deny()
	}
	defer wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Transit.Endpoint+"/v1/auth/"+c.Mount+"/login", bytes.NewReader(body))
	if err != nil {
		return deny()
	}
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return deny()
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Encoding") != "" {
		return deny()
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer wipe(raw)
	if err != nil || len(raw) > 65536 || ctx.Err() != nil {
		return deny()
	}
	secret, ttl, err := transitJWTToken(raw, c.Role, c.Policy)
	// Receipt + TTL conservatively bounds provider expiry; request start + TTL
	// is our earlier usable deadline. An oversized provider TTL is rejected.
	expiry := started.Add(ttl)
	if err != nil || time.Now().Add(ttl).After(until) || !time.Now().Before(expiry) {
		wipe(secret)
		return deny()
	}
	return secret, expiry, nil
}
func transitJWTToken(raw []byte, role, policy string) ([]byte, time.Duration, error) {
	root, err := transitObject(raw)
	if err != nil {
		return nil, 0, ErrKey
	}
	defer wipeTransitFields(root)
	for _, name := range []string{"errors", "wrap_info"} {
		if v, ok := root[name]; ok && !bytes.Equal(bytes.TrimSpace(v), []byte("null")) && !(name == "errors" && bytes.Equal(bytes.TrimSpace(v), []byte("[]"))) {
			return nil, 0, ErrKey
		}
	}
	auth, err := transitObject(root["auth"])
	if err != nil {
		return nil, 0, ErrKey
	}
	defer wipeTransitFields(auth)
	var token, kind string
	var seconds int64
	var policies []string
	if json.Unmarshal(auth["client_token"], &token) != nil || !s3Token([]byte(token), 16, 4096) ||
		json.Unmarshal(auth["token_type"], &kind) != nil || kind != "batch" || !bytes.Equal(bytes.TrimSpace(auth["renewable"]), []byte("false")) ||
		json.Unmarshal(auth["lease_duration"], &seconds) != nil || seconds < 1 || seconds > 20 ||
		json.Unmarshal(auth["policies"], &policies) != nil || len(policies) != 1 || policies[0] != policy {
		return nil, 0, ErrKey
	}
	// Some versions include the split policy fields; reject added identity or
	// token privileges rather than trusting only the combined list.
	if v, ok := auth["token_policies"]; ok {
		if json.Unmarshal(v, &policies) != nil || len(policies) != 1 || policies[0] != policy {
			return nil, 0, ErrKey
		}
	}
	if v, ok := auth["identity_policies"]; ok {
		if json.Unmarshal(v, &policies) != nil || len(policies) != 0 {
			return nil, 0, ErrKey
		}
	}
	metadata, err := transitObject(auth["metadata"])
	if err != nil {
		return nil, 0, ErrKey
	}
	defer wipeTransitFields(metadata)
	var gotRole string
	if json.Unmarshal(metadata["role"], &gotRole) != nil || gotRole != role {
		return nil, 0, ErrKey
	}
	return []byte(token), time.Duration(seconds) * time.Second, nil
}
