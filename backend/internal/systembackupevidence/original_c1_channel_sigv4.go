package systembackupevidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7/pkg/s3utils"
)

func c1MAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(value))
	return h.Sum(nil)
}

// Verify the actual v4 presigned wire request, not a bearer access-key lookup.
// Method/key/version/body constraints are independently enforced by the server.
func c1VerifyPresign(r *http.Request, access string, secret []byte, token, region string, until, now time.Time) bool {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || r.TLS == nil || !now.Before(until) {
		return false
	}
	allowed := map[string]bool{"X-Amz-Algorithm": true, "X-Amz-Credential": true, "X-Amz-Date": true, "X-Amz-Expires": true, "X-Amz-SignedHeaders": true, "X-Amz-Signature": true, "X-Amz-Security-Token": true, "versionId": true}
	for key, values := range q {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return false
		}
	}
	if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || q.Get("X-Amz-Security-Token") != token {
		return false
	}
	signedAt, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil || signedAt.After(now.Add(time.Second)) {
		return false
	}
	expires, err := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if err != nil || expires < 1 || expires > 60 || !now.Before(signedAt.Add(time.Duration(expires)*time.Second)) || signedAt.Add(time.Duration(expires)*time.Second).After(until) {
		return false
	}
	credential := access + "/" + signedAt.Format("20060102") + "/" + region + "/s3/aws4_request"
	if q.Get("X-Amz-Credential") != credential {
		return false
	}
	headers := strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
	if len(headers) == 0 || !sort.StringsAreSorted(headers) {
		return false
	}
	canonicalHeaders := ""
	seen := map[string]bool{}
	for _, name := range headers {
		if name == "" || name != strings.ToLower(name) || seen[name] {
			return false
		}
		seen[name] = true
		var value string
		switch name {
		case "host":
			value = r.Host
		case "content-length":
			value = strconv.FormatInt(r.ContentLength, 10)
		default:
			values := r.Header.Values(name)
			if len(values) != 1 {
				return false
			}
			value = values[0]
		}
		canonicalHeaders += name + ":" + strings.Join(strings.Fields(value), " ") + "\n"
	}
	if !seen["host"] || !seen["x-amz-content-sha256"] {
		return false
	}
	want, err := hex.DecodeString(q.Get("X-Amz-Signature"))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	q.Del("X-Amz-Signature")
	canonical := strings.Join([]string{r.Method, s3utils.EncodePath(r.URL.Path), strings.ReplaceAll(q.Encode(), "+", "%20"), canonicalHeaders, strings.Join(headers, ";"), r.Header.Get("X-Amz-Content-Sha256")}, "\n")
	credentialScope := signedAt.Format("20060102") + "/" + region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + signedAt.Format("20060102T150405Z") + "\n" + credentialScope + "\n" + hash([]byte(canonical))
	seed := append([]byte("AWS4"), secret...)
	defer wipe(seed)
	date := c1MAC(seed, signedAt.Format("20060102"))
	defer wipe(date)
	regional := c1MAC(date, region)
	defer wipe(regional)
	service := c1MAC(regional, "s3")
	defer wipe(service)
	key := c1MAC(service, "aws4_request")
	defer wipe(key)
	return hmac.Equal(want, c1MAC(key, toSign))
}
