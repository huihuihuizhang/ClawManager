package systembackupread

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
)

const cursorDomain = "system-backup-admin-task-page.v1\n"
const maxCursorBytes = 4096

// CursorCodec signs an internal page position with a dedicated key. The
// caller must never reuse a provider, JWT or audit signing key for this role.
type CursorCodec struct{ key []byte }

func NewCursorCodec(key []byte) (*CursorCodec, error) {
	if len(key) < 32 {
		return nil, ErrInvalid
	}
	return &CursorCodec{key: append([]byte(nil), key...)}, nil
}

// Encode signs the next page position only after an authorized read returned
// a nonempty continuation. It does not turn TaskPage into a wire DTO.
func (c *CursorCodec) Encode(request PageRequest, page TaskPage) (string, error) {
	if c == nil || len(c.key) < 32 || !page.HasMore || page.BeforeID == 0 ||
		page.CutoffID < page.BeforeID || !installationID.MatchString(page.InstallationID) ||
		request.InstallationID != "" && request.InstallationID != page.InstallationID ||
		request.CutoffID != 0 && request.CutoffID != page.CutoffID ||
		request.CutoffID == 0 && request.BeforeID != 0 ||
		request.CutoffID != 0 && request.InstallationID == "" ||
		request.Limit < 1 || request.Limit > 500 {
		return "", ErrInvalid
	}
	table, ok := taskTables[request.Kind]
	if !ok || request.Status != "" && !table.status[request.Status] {
		return "", ErrInvalid
	}
	consistency := "stable_cutoff"
	if request.Status != "" {
		consistency = "eventual"
	}
	if len(page.Items) != request.Limit || page.Items[len(page.Items)-1].ID != page.BeforeID || page.Consistency != consistency {
		return "", ErrInvalid
	}
	for i, item := range page.Items {
		if item.InstallationID != page.InstallationID || item.Kind != request.Kind || item.ID == 0 || item.ID > page.CutoffID ||
			request.Status != "" && item.Status != request.Status {
			return "", ErrInvalid
		}
		if i > 0 && item.ID >= page.Items[i-1].ID || request.BeforeID != 0 && item.ID >= request.BeforeID {
			return "", ErrInvalid
		}
	}
	payload := strings.Join([]string{
		"v1", page.InstallationID, string(request.Kind), request.Status,
		strconv.Itoa(request.Limit), strconv.FormatUint(page.CutoffID, 10), strconv.FormatUint(page.BeforeID, 10),
	}, "|")
	signature := c.sign([]byte(payload))
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > maxCursorBytes {
		return "", ErrInvalid
	}
	return token, nil
}

// Decode binds kind, filter and limit to the current request. The returned
// InstallationID is checked again by Reader against fresh authorization.
func (c *CursorCodec) Decode(token string, kind TaskKind, status string, limit int) (PageRequest, error) {
	if c == nil || len(c.key) < 32 || len(token) == 0 || len(token) > maxCursorBytes {
		return PageRequest{}, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return PageRequest{}, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return PageRequest{}, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != parts[1] ||
		!hmac.Equal(signature, c.sign(payload)) {
		return PageRequest{}, ErrInvalid
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 7 || fields[0] != "v1" || !installationID.MatchString(fields[1]) ||
		fields[2] != string(kind) || fields[3] != status || limit < 1 || limit > 500 ||
		fields[4] != strconv.Itoa(limit) {
		return PageRequest{}, ErrInvalid
	}
	table, ok := taskTables[kind]
	if !ok || status != "" && !table.status[status] {
		return PageRequest{}, ErrInvalid
	}
	cutoff, err := canonicalUint(fields[5])
	if err != nil || cutoff == 0 {
		return PageRequest{}, ErrInvalid
	}
	before, err := canonicalUint(fields[6])
	if err != nil || before == 0 || before > cutoff {
		return PageRequest{}, ErrInvalid
	}
	return PageRequest{InstallationID: fields[1], Kind: kind, Status: status, Limit: limit, CutoffID: cutoff, BeforeID: before}, nil
}

func canonicalUint(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != raw {
		return 0, ErrInvalid
	}
	return value, nil
}

func (c *CursorCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(cursorDomain))
	mac.Write(payload)
	return mac.Sum(nil)
}
