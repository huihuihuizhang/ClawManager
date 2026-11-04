package systembackup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Use the pinned mc's native metrics-token schema, verify its MAC/subject, and
// shorten expiry to the SAME current authority cap. No 100-year generated mc
// token is exported, persisted, logged or used as an independent source grant.
func (n *minioGateNative) metricsToken(ctx context.Context) (string, error) {
	raw, e := n.mc(ctx, "admin", "prometheus", "generate", "--api-version", "v3", "native", "api")
	if e != nil {
		return "", e
	}
	defer clear(raw)
	var c struct {
		JobName, MetricsPath, BearerToken, Scheme string
		StaticConfigs                             []struct{ Targets []string }
	}
	if minioGateDecode(raw, &c) != nil || c.Scheme != "https" || !strings.HasPrefix(c.MetricsPath, "/minio/metrics/v3/api") || len(c.StaticConfigs) != 1 || len(c.StaticConfigs[0].Targets) != 1 || "https://"+c.StaticConfigs[0].Targets[0] != n.g.in.Endpoint {
		return "", ErrMinIOReadGate
	}
	parts := strings.Split(c.BearerToken, ".")
	if len(parts) != 3 {
		return "", ErrMinIOReadGate
	}
	header, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return "", ErrMinIOReadGate
	}
	var h struct{ Alg, Typ string }
	if minioGateDecode(header, &h) != nil || h.Typ != "JWT" {
		return "", ErrMinIOReadGate
	}
	var hf func() hash.Hash
	switch h.Alg {
	case "HS512":
		hf = sha512.New
	case "HS256":
		hf = sha256.New
	default:
		return "", ErrMinIOReadGate
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return "", ErrMinIOReadGate
	}
	mac := hmac.New(hf, n.g.credentials[1].SecretKey)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", ErrMinIOReadGate
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !minioGateJSON(payload) {
		return "", ErrMinIOReadGate
	}
	defer clear(payload)
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil {
		return "", ErrMinIOReadGate
	}
	for k := range claims {
		switch k {
		case "exp", "iat", "nbf", "sub", "iss", "aud", "accessKey":
		default:
			return "", ErrMinIOReadGate
		}
	}
	var issuer, subject, key string
	_ = json.Unmarshal(claims["iss"], &issuer)
	_ = json.Unmarshal(claims["sub"], &subject)
	_ = json.Unmarshal(claims["accessKey"], &key)
	if issuer != "prometheus" || subject != n.g.credentials[1].AccessKey && key != n.g.credentials[1].AccessKey {
		return "", ErrMinIOReadGate
	}
	claims["exp"], _ = json.Marshal(n.g.until.Unix())
	claims["iat"], _ = json.Marshal(time.Now().UTC().Unix())
	payload, e = json.Marshal(claims)
	if e != nil {
		return "", ErrMinIOReadGate
	}
	defer clear(payload)
	unsigned := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac = hmac.New(hf, n.g.credentials[1].SecretKey)
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (n *minioGateNative) waitS3Drain(ctx context.Context) error {
	token, e := n.metricsToken(ctx)
	if e != nil {
		return e
	}
	for {
		if ctx.Err() != nil || n.g.check(ctx) != nil {
			return ErrMinIOReadGate
		}
		req, e := http.NewRequestWithContext(ctx, "GET", n.g.in.Endpoint+"/minio/metrics/v3/api/requests", nil)
		if e != nil {
			return ErrMinIOReadGate
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "text/plain; version=0.0.4")
		req.Header.Set("Accept-Encoding", "identity")
		res, e := n.http.Do(req)
		if e != nil {
			return ErrMinIOReadGate
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
		ce := res.Body.Close()
		if e != nil || ce != nil || res.StatusCode != 200 || len(raw) > 4<<20 || res.Header.Get("Content-Encoding") != "" || res.ContentLength >= 0 && int64(len(raw)) != res.ContentLength {
			return ErrMinIOReadGate
		}
		zero, e := minioGateDrainedMetrics(raw)
		clear(raw)
		if e != nil {
			return e
		}
		if zero {
			return nil
		}
		t := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return ErrMinIOReadGate
		case <-t.C:
		}
	}
}

// September's current-S3 loader reads the live HTTP counters directly. Its
// MetricValues.Set omits zeros. Therefore missing gauge samples mean zero ONLY
// after the complete authenticated fixed-profile endpoint, full EOF, valid
// positive S3 total heartbeat and strict text/labels have been checked here.
// These metrics cover S3 handlers, NOT prior native admin/peer/ILM operations;
// the real D original composite owner must hold those actual actors separately.
func minioGateDrainedMetrics(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > 4<<20 || raw[len(raw)-1] != '\n' {
		return false, ErrMinIOReadGate
	}
	s := bufio.NewScanner(bytes.NewReader(raw))
	s.Buffer(make([]byte, 4096), 1<<20)
	heartbeat := false
	active := false
	seen := map[string]bool{}
	linePattern := regexp.MustCompile(`^(minio_api_requests_[A-Za-z0-9_]+)(\{[^\r\n]*\})? ([^ ]+)$`)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "# HELP ") || strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		m := linePattern.FindStringSubmatch(line)
		if m == nil {
			return false, ErrMinIOReadGate
		}
		if seen[m[1]+m[2]] {
			return false, ErrMinIOReadGate
		}
		seen[m[1]+m[2]] = true
		v, e := strconv.ParseFloat(m[3], 64)
		if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return false, ErrMinIOReadGate
		}
		if !strings.Contains(m[2], `type="s3"`) {
			return false, ErrMinIOReadGate
		}
		switch m[1] {
		case "minio_api_requests_total":
			if v > 0 {
				heartbeat = true
			}
		case "minio_api_requests_waiting_total", "minio_api_requests_incoming_total", "minio_api_requests_inflight_total":
			if v > 0 {
				active = true
			}
		}
	}
	if s.Err() != nil || !heartbeat {
		return false, ErrMinIOReadGate
	}
	return !active, nil
}
