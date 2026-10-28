package systembackupsecurity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

// Narrow read-only SigV4 implementation for the pinned lab's path-style,
// us-east-1, static-credential S3 profile. No writes, redirects, endpoint
// discovery, public URLs, listing, session credentials or fallback storage.
type s3ReadClient struct {
	endpoint, access, secret string
	http                     *http.Client
}
type s3VersionOptions struct{ VersionID string }
type s3ObjectInfo struct {
	VersionID string
	Size      int64
}

func awsURI(s string, slash bool) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for _, b := range []byte(s) {
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-_.~", rune(b)) || slash && b == '/' {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[b>>4])
			out.WriteByte(hex[b&15])
		}
	}
	return out.String()
}
func s3Authorization(method, path, query, host, access, secret string, now time.Time) (string, string) {
	date := now.UTC().Format("20060102T150405Z")
	day := date[:8]
	emptyHash := registrationHash("")
	names := "host;x-amz-content-sha256;x-amz-date"
	headers := "host:" + host + "\nx-amz-content-sha256:" + emptyHash + "\nx-amz-date:" + date + "\n"
	canonical := strings.Join([]string{method, path, query, headers, names, emptyHash}, "\n")
	scope := day + "/us-east-1/s3/aws4_request"
	input := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + registrationHash(canonical)
	key := []byte("AWS4" + secret)
	for _, part := range []string{day, "us-east-1", "s3", "aws4_request"} {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(part))
		key = mac.Sum(nil)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return "AWS4-HMAC-SHA256 Credential=" + access + "/" + scope + ",SignedHeaders=" + names + ",Signature=" + hex.EncodeToString(mac.Sum(nil)), date
}
func (c *s3ReadClient) request(ctx context.Context, method, bucket, key, version string) (*http.Response, error) {
	if c == nil || c.http == nil || method != "HEAD" && method != "GET" || strings.ContainsAny(bucket, "/\r\n") || bucket == "" || len(key) > 4096 || key == "" || len(version) > 256 || strings.ContainsAny(c.access, "\r\n") {
		return nil, ErrRegistrationUnavailable
	}
	path := "/" + awsURI(bucket, false) + "/" + awsURI(key, true)
	query := ""
	if version != "" {
		query = "versionId=" + awsURI(version, false)
	}
	address := c.endpoint + path
	if query != "" {
		address += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, address, nil)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	auth, date := s3Authorization(method, path, query, req.URL.Host, c.access, c.secret, time.Now())
	req.Header.Set("Authorization", auth)
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Content-Sha256", registrationHash(""))
	res, err := c.http.Do(req)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" || res.Header.Get("x-amz-delete-marker") == "true" {
		res.Body.Close()
		return nil, ErrRegistrationUnavailable
	}
	returned := res.Header.Get("x-amz-version-id")
	if returned == "" || returned == "null" || len(returned) > 256 || version != "" && version != returned {
		res.Body.Close()
		return nil, ErrRegistrationUnavailable
	}
	return res, nil
}
func (c *s3ReadClient) StatObject(ctx context.Context, bucket, key string, options s3VersionOptions) (s3ObjectInfo, error) {
	res, err := c.request(ctx, "HEAD", bucket, key, options.VersionID)
	if err != nil {
		return s3ObjectInfo{}, err
	}
	defer res.Body.Close()
	if res.ContentLength < 1 || res.ContentLength > 262144 {
		return s3ObjectInfo{}, ErrRegistrationUnavailable
	}
	return s3ObjectInfo{VersionID: res.Header.Get("x-amz-version-id"), Size: res.ContentLength}, nil
}
func (c *s3ReadClient) GetObject(ctx context.Context, bucket, key string, options s3VersionOptions) (io.ReadCloser, error) {
	if options.VersionID == "" || options.VersionID == "null" {
		return nil, ErrRegistrationUnavailable
	}
	res, err := c.request(ctx, "GET", bucket, key, options.VersionID)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}
