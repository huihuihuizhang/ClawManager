package systembackupread

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

const taskEventControlCursorDomain = "system-backup-admin-task-event-control-page.v1\n"

func (c *CursorCodec) signTaskEventControl(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(taskEventControlCursorDomain))
	mac.Write(payload)
	return mac.Sum(nil)
}

func (c *CursorCodec) EncodeTaskEvents(request TaskEventPageRequest, page TaskEventControlPage) (string, error) {
	if c == nil || len(c.key) < 32 || !validTaskEventRequest(request) || !page.hasMore || page.consistency != "stable_cutoff" || len(page.events) != request.Limit ||
		page.task.Kind != request.Kind || page.task.PublicID != request.PublicID || !installationID.MatchString(page.installation) ||
		page.installation != page.task.InstallationID || request.InstallationID != "" && request.InstallationID != page.installation ||
		page.cutoff == 0 || request.CutoffID != 0 && request.CutoffID != page.cutoff || page.before == 0 || page.before > page.cutoff || !validEventCursorTime(page.beforeCreatedAt) {
		return "", ErrInvalid
	}
	seen := make(map[uint64]bool, len(page.events))
	for i, event := range page.events {
		if !validTaskEventControl(event, page.task) || seen[event.ID] || event.ID > page.cutoff ||
			request.BeforeID != 0 && !eventPositionBefore(event.CreatedAt, event.ID, request.BeforeCreatedAt, request.BeforeID) ||
			i > 0 && !eventPositionBefore(event.CreatedAt, event.ID, page.events[i-1].CreatedAt, page.events[i-1].ID) {
			return "", ErrInvalid
		}
		seen[event.ID] = true
	}
	last := page.events[len(page.events)-1]
	if last.ID != page.before || !last.CreatedAt.Equal(page.beforeCreatedAt) {
		return "", ErrInvalid
	}
	payload := strings.Join([]string{"v1", page.installation, string(request.Kind), request.PublicID, strconv.Itoa(request.Limit),
		strconv.FormatUint(page.cutoff, 10), page.beforeCreatedAt.Format(taskEventCursorTimeFormat), strconv.FormatUint(page.before, 10)}, "|")
	token := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(c.signTaskEventControl([]byte(payload)))
	if len(token) > maxCursorBytes {
		return "", ErrInvalid
	}
	return token, nil
}

func (c *CursorCodec) DecodeTaskEvents(token string, kind TaskKind, publicID string, limit int) (TaskEventPageRequest, error) {
	var zero TaskEventPageRequest
	if c == nil || len(c.key) < 32 || len(token) == 0 || len(token) > maxCursorBytes {
		return zero, ErrInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return zero, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return zero, ErrInvalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != parts[1] || !hmac.Equal(signature, c.signTaskEventControl(payload)) {
		return zero, ErrInvalid
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 8 || fields[0] != "v1" || fields[2] != string(kind) || fields[3] != publicID || fields[4] != strconv.Itoa(limit) {
		return zero, ErrInvalid
	}
	cutoff, err := canonicalUint(fields[5])
	if err != nil {
		return zero, ErrInvalid
	}
	before, err := canonicalUint(fields[7])
	if err != nil {
		return zero, ErrInvalid
	}
	at, err := time.Parse(taskEventCursorTimeFormat, fields[6])
	if err != nil || at.Format(taskEventCursorTimeFormat) != fields[6] {
		return zero, ErrInvalid
	}
	request := TaskEventPageRequest{InstallationID: fields[1], Kind: kind, PublicID: publicID, Limit: limit, CutoffID: cutoff, BeforeID: before, BeforeCreatedAt: at}
	if cutoff == 0 || !validTaskEventRequest(request) {
		return zero, ErrInvalid
	}
	return request, nil
}
