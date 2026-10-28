package systembackupread

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
)

const configListCursorDomain = "system-backup-admin-config-version-page.v1\n"

func (c *CursorCodec) EncodeConfig(request ConfigPageRequest, page ConfigPage) (string, error) {
	if c == nil || len(c.key) < 32 || request.Limit < 1 || request.Limit > 500 ||
		!page.HasMore || len(page.Items) != request.Limit ||
		!installationID.MatchString(page.InstallationID) ||
		page.CutoffVersion == 0 || page.CutoffVersion > maxJSONSafeInteger ||
		page.BeforeVersion == 0 || page.BeforeVersion > page.CutoffVersion ||
		request.InstallationID != "" && request.InstallationID != page.InstallationID ||
		request.CutoffVersion != 0 && (request.CutoffVersion != page.CutoffVersion ||
			request.BeforeVersion == 0 || request.BeforeVersion > request.CutoffVersion) ||
		request.CutoffVersion == 0 && (request.BeforeVersion != 0 || request.InstallationID != "") {
		return "", ErrInvalid
	}
	for i, row := range page.Items {
		if row.installationID != page.InstallationID || row.version == 0 || row.version > page.CutoffVersion ||
			i > 0 && row.version >= page.Items[i-1].version ||
			request.BeforeVersion != 0 && row.version >= request.BeforeVersion {
			return "", ErrInvalid
		}
	}
	if page.Items[len(page.Items)-1].version != page.BeforeVersion ||
		request.CutoffVersion == 0 && page.Items[0].version != page.CutoffVersion {
		return "", ErrInvalid
	}
	payload := strings.Join([]string{"v1", page.InstallationID, strconv.Itoa(request.Limit),
		strconv.FormatUint(page.CutoffVersion, 10), strconv.FormatUint(page.BeforeVersion, 10)}, "|")
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(configListCursorDomain))
	mac.Write([]byte(payload))
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > maxCursorBytes {
		return "", ErrInvalid
	}
	return token, nil
}

func (c *CursorCodec) DecodeConfig(token string, limit int) (ConfigPageRequest, error) {
	if c == nil || len(c.key) < 32 || len(token) == 0 || len(token) > maxCursorBytes || limit < 1 || limit > 500 {
		return ConfigPageRequest{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return ConfigPageRequest{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return ConfigPageRequest{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != parts[1] {
		return ConfigPageRequest{}, ErrInvalid
	}
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(configListCursorDomain))
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return ConfigPageRequest{}, ErrInvalid
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 5 || fields[0] != "v1" || !installationID.MatchString(fields[1]) || fields[2] != strconv.Itoa(limit) {
		return ConfigPageRequest{}, ErrInvalid
	}
	cutoff, err := canonicalUint(fields[3])
	if err != nil || cutoff == 0 || cutoff > maxJSONSafeInteger {
		return ConfigPageRequest{}, ErrInvalid
	}
	before, err := canonicalUint(fields[4])
	if err != nil || before == 0 || before > cutoff {
		return ConfigPageRequest{}, ErrInvalid
	}
	return ConfigPageRequest{InstallationID: fields[1], Limit: limit, CutoffVersion: cutoff, BeforeVersion: before}, nil
}
