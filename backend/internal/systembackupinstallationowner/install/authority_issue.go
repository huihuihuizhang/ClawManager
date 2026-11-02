package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

func requestWindow(r owner.Record, request *originalRequest, now time.Time) bool {
	return !now.Before(r.NotBefore) && now.Before(r.Until) && !r.NotBefore.Before(request.start) && !r.Until.After(request.end) && !now.Before(request.start) && now.Before(request.end)
}

// IssueCapture freezes original signatures outside SQL locks. It writes no SQL
// source/config/task rows; ImportCapture is the separate exact-CAS operation.
func (i *Installer) IssueCapture(ctx context.Context, password []byte, enrollment EnrollmentPin, draft []byte, draftSHA string, issuerKey []byte, files RequestFiles) ([]byte, error) {
	if len(draft) == 0 || len(draft) > 262144 {
		return nil, ErrInstall
	}
	draft = bytes.Clone(draft)
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil {
		return nil, ErrInstall
	}
	var r owner.Record
	if hash(draft) != draftSHA || decodeExact(draft, &r) != nil || !s.matchesRecord(r) {
		return nil, ErrInstall
	}
	request, e := readRequest(i, files)
	if e != nil {
		return nil, e
	}
	defer request.observer.Close()
	previous, now, e := snapshot(ctx, s)
	if e != nil || !requestWindow(r, request, now) {
		return nil, ErrInstall
	}
	h, e := nextHead(previous, r, now)
	if e != nil {
		return nil, e
	}
	pin := s.pinFor(r, hash(draft), h.Revision)
	if owner.CheckInstallationDraft(draft, pin) != nil || !request.matchesDraft(r) {
		return nil, ErrInstall
	}
	key, e := s.privateKey(issuerKey)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(owner.RecordDomain), draft...))
	if owner.VerifyInstallationRequest(draft, signature, pin, request.grant, request.config) != nil {
		return nil, ErrInstall
	}
	h.RecordSHA256 = hash(draft)
	head, e := owner.EncodeHead(h)
	if e != nil {
		return nil, e
	}
	headSignature := ed25519.Sign(key, append([]byte(owner.HeadDomain), head...))
	observation, e := owner.ObserveInstallationCapture(ctx, draft, signature, pin, request.grant, request.config, request.observer)
	if e != nil {
		return nil, ErrInstall
	}
	if s.authority(ctx, enrollment) != nil || request.recheck(i) != nil {
		return nil, ErrInstall
	}
	again, now, e := snapshot(ctx, s)
	if e != nil || again.cas != previous.cas || !requestWindow(r, request, now) || observation.Check(ctx, now, hash(draft)) != nil || !s.live(ctx) {
		return nil, ErrInstall
	}
	filePins, e := canonical(files)
	if e != nil {
		return nil, e
	}
	return encodeBundle(AuthorityBundle{SchemaVersion: AuthorityBundleVersion, PlanSHA256: i.planHash, Enrollment: enrollment, Expected: previous.cas, RequestFilesSHA256: hash(filePins), Pin: pin, Record: append([]byte(nil), draft...), RecordSignature: signature, Head: head, HeadSignature: headSignature})
}
