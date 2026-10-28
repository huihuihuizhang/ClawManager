package systembackupevidence

import (
	"net/http"
	"strconv"
	"strings"

	"clawreef/internal/systembackupsecurity"
)

func sensitiveDownloadHeaderValues(headers http.Header, name string) []string {
	var values []string
	for key, entries := range headers {
		if strings.EqualFold(key, name) {
			if len(entries) == 0 {
				values = append(values, "")
			} else {
				values = append(values, entries...)
			}
		}
	}
	return values
}

// BindSensitiveDownloadRequest is the shared issuance/verification input
// builder. Callers supply the independently authenticated actor and authorized
// immutable Manifest, never a client manifest hash or identity assertion.
// It neither checks current SQL authority nor grants download access.
func BindSensitiveDownloadRequest(actor systembackupsecurity.RegistrationActor, manifest Manifest, headers http.Header) (systembackupsecurity.SensitiveDownloadRequest, error) {
	bad := func(err error) (systembackupsecurity.SensitiveDownloadRequest, error) {
		return systembackupsecurity.SensitiveDownloadRequest{}, err
	}
	keys := sensitiveDownloadHeaderValues(headers, "Idempotency-Key")
	ranges := sensitiveDownloadHeaderValues(headers, "Range")
	proofs := sensitiveDownloadHeaderValues(headers, systembackupsecurity.StrongAuthProofHeader)
	if len(keys) != 1 || len(ranges) > 1 || len(proofs) > 1 {
		return bad(ErrInvalid)
	}
	if len(ranges) == 1 && ranges[0] == "" {
		return bad(ErrRange)
	}
	frozen, err := snapshotReadManifest(manifest)
	if err != nil {
		return bad(err)
	}
	if !oneOf(frozen.Identity.Classification, "confidential", "sensitive") {
		return bad(ErrDenied)
	}
	rawRange := ""
	if len(ranges) == 1 {
		rawRange = ranges[0]
	}
	// A clamped suffix/end can hide an unsafe original integer. The new signed
	// profile rejects those literals even though the legacy reader can clamp.
	if strings.HasPrefix(rawRange, "bytes=") {
		for _, part := range strings.Split(strings.TrimPrefix(rawRange, "bytes="), "-") {
			if part == "" {
				continue
			}
			n, e := strconv.ParseUint(part, 10, 64)
			if e != nil || n > 9007199254740991 {
				return bad(ErrRange)
			}
		}
	}
	start, end, present, err := parseRange(rawRange, frozen.Identity.ContentSize)
	if err != nil {
		return bad(err)
	}
	bound, err := systembackupsecurity.NewSensitiveDownloadRequest(systembackupsecurity.SensitiveDownloadRequestFacts{
		Installation: frozen.Identity.Installation, EvidenceID: frozen.Identity.ID, Actor: actor,
		ManifestSHA256: hash(canonical(frozen)), ContentSize: frozen.Identity.ContentSize,
		RangeStart: start, RangeEnd: end, RangePresent: present, IdempotencyKey: keys[0],
	})
	if err != nil {
		return bad(ErrInvalid)
	}
	return bound, nil
}

// VerifySensitiveDownloadRequestHeader freezes transport input and invokes
// only the non-consuming A verifier. It cannot implement SensitiveDownloadProof:
// D's sealed prelocked transaction/receipt/audit/nonce boundary is still absent.
// Current authentication/owner/permission checks precede this helper in D's
// protocol; key conflict and nonce replay lookups follow successful validation.
func VerifySensitiveDownloadRequestHeader(actor systembackupsecurity.RegistrationActor, manifest Manifest, headers http.Header, issuer string, cfg systembackupsecurity.VerifyConfig) (systembackupsecurity.SensitiveDownloadProofVerification, error) {
	headers = headers.Clone()
	bound, err := BindSensitiveDownloadRequest(actor, manifest, headers)
	if err != nil {
		return systembackupsecurity.SensitiveDownloadProofVerification{}, err
	}
	proofs := sensitiveDownloadHeaderValues(headers, systembackupsecurity.StrongAuthProofHeader)
	verified, err := bound.VerifyProofHeader(proofs, issuer, cfg)
	if err == systembackupsecurity.ErrSensitiveDownloadRequest {
		return systembackupsecurity.SensitiveDownloadProofVerification{}, ErrInvalid
	}
	return verified, err
}
