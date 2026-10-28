package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SensitiveDownloadProofSelector contains only client business selectors. The
// authorized immutable Manifest, actor, installation and digest come from SQL
// and trusted runtime material, never from this wire input.
type SensitiveDownloadProofSelector struct {
	evidenceID, rawRange string
	rangePresent         bool
}

var downloadProofRange = regexp.MustCompile(`^bytes=([0-9]+-[0-9]*|-[0-9]+)$`)

func DecodeSensitiveDownloadProofSelector(raw []byte) (SensitiveDownloadProofSelector, error) {
	var fields map[string]json.RawMessage
	var selector SensitiveDownloadProofSelector
	if len(raw) > 1024 || !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) || json.Unmarshal(raw, &fields) != nil {
		return selector, ErrSensitiveDownloadRequest
	}
	_, selector.rangePresent = fields["range"]
	validFields := providerFieldSet(fields, "evidence_id")
	if selector.rangePresent {
		validFields = providerFieldSet(fields, "evidence_id", "range")
	}
	if !validFields || json.Unmarshal(fields["evidence_id"], &selector.evidenceID) != nil || !sensitiveDownloadEvidence.MatchString(selector.evidenceID) {
		return SensitiveDownloadProofSelector{}, ErrSensitiveDownloadRequest
	}
	if selector.rangePresent && (json.Unmarshal(fields["range"], &selector.rawRange) != nil || len(selector.rawRange) > 128 || !downloadProofRange.MatchString(selector.rawRange)) {
		return SensitiveDownloadProofSelector{}, ErrSensitiveDownloadRequest
	}
	if selector.rangePresent {
		for _, literal := range strings.Split(strings.TrimPrefix(selector.rawRange, "bytes="), "-") {
			if literal == "" {
				continue
			}
			n, err := strconv.ParseUint(literal, 10, 64)
			if err != nil || n > 9007199254740991 {
				return SensitiveDownloadProofSelector{}, ErrSensitiveDownloadRequest
			}
		}
	}
	return selector, nil
}

func (s SensitiveDownloadProofSelector) EvidenceID() string { return s.evidenceID }
func (s SensitiveDownloadProofSelector) Range() (string, bool) {
	return s.rawRange, s.rangePresent
}

// SensitiveDownloadProofTargets is a trusted runtime adapter. Prepare must
// acquire L0/L1 before credential locks and authorize the current server-loaded
// target in this borrowed transaction. Neither method may commit, reserve a
// download, consume a nonce, acquire L3+ locks or perform provider/network I/O.
type SensitiveDownloadProofTargets interface {
	Prepare(context.Context, *sql.Tx, RegistrationActor, SensitiveDownloadProofSelector, string) (SensitiveDownloadProofTarget, error)
}

type SensitiveDownloadProofTarget interface {
	Request() SensitiveDownloadRequest
	ValidUntil() time.Time
	ValidateProof(context.Context, *sql.Tx, RegistrationActor, Proof, time.Time) error
	Recheck(context.Context, *sql.Tx, RegistrationActor) error
	Close()
}

// VerifySensitiveDownloadAndIssue verifies a fresh, previously enrolled TOTP
// step. The proof is signed only for the independently authorized Manifest and
// normalized range. Issuance grants no download and creates no admission rows.
func (s SQLTOTPService) VerifySensitiveDownloadAndIssue(ctx context.Context, actor RegistrationActor, password, code string, selector SensitiveDownloadProofSelector, key string, targets SensitiveDownloadProofTargets) (Proof, error) {
	if ctx == nil || ctx.Err() != nil || s.DatabaseIdentity == nil || !s.DatabaseIdentity.valid() || !sensitiveDownloadInstallation.MatchString(s.InstallationID) || nilConfigMutationBoundary(targets) {
		return Proof{}, ErrRegistrationUnavailable
	}
	if !sensitiveDownloadEvidence.MatchString(selector.evidenceID) || !validIdempotencyKey(key) || actor.UserID < 1 {
		return Proof{}, ErrSensitiveDownloadRequest
	}
	var target SensitiveDownloadProofTarget
	defer func() {
		if !nilConfigMutationBoundary(target) {
			target.Close()
		}
	}()
	var binding RequestBinding
	var originalTx *sql.Tx
	var originalRequest SensitiveDownloadRequest
	bounds := &totpProofBounds{}
	// Download permission is purpose-specific. Enrollment and other proof
	// endpoints continue to use their existing security_admin callback.
	s.Authorize = func(ctx context.Context, tx *sql.Tx, a RegistrationActor) error {
		if a != actor {
			return ErrRegistrationUnavailable
		}
		if originalTx != nil {
			if tx != originalTx || target.Request() != originalRequest || !target.ValidUntil().Equal(bounds.until) {
				return ErrRegistrationUnavailable
			}
			if err := target.Recheck(ctx, tx, a); err != nil {
				return err
			}
			if target.Request() != originalRequest || !target.ValidUntil().Equal(bounds.until) {
				return ErrRegistrationUnavailable
			}
			return nil
		}
		var err error
		target, err = targets.Prepare(ctx, tx, a, selector, key)
		if err != nil {
			return err
		}
		if nilConfigMutationBoundary(target) {
			return ErrRegistrationUnavailable
		}
		originalTx, originalRequest = tx, target.Request()
		bounds.until = target.ValidUntil()
		_, offset := bounds.until.Zone()
		if !originalRequest.MatchesActor(a) || originalRequest.InstallationID() != s.InstallationID || originalRequest.EvidenceID() != selector.evidenceID || originalRequest.IdempotencyKey() != key ||
			bounds.until.IsZero() || offset != 0 || bounds.until.Year() < 1970 || bounds.until.Year() > 9999 || bounds.until.Nanosecond()%1000 != 0 || s.Issuer.Audience != s.InstallationID {
			return ErrRegistrationUnavailable
		}
		binding, err = originalRequest.ProofBinding(s.Issuer.Key.Issuer)
		return err
	}
	bounds.validate = func(ctx context.Context, tx *sql.Tx, proof Proof, issuedAt time.Time) error {
		if tx != originalTx || target.Request() != originalRequest || !target.ValidUntil().Equal(bounds.until) {
			return ErrRegistrationUnavailable
		}
		if err := target.ValidateProof(ctx, tx, actor, proof, issuedAt); err != nil {
			return err
		}
		if target.Request() != originalRequest || !target.ValidUntil().Equal(bounds.until) {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	return s.verifyAndIssueBounded(ctx, actor, password, code, &binding, true, bounds)
}

type totpProofBounds struct {
	until    time.Time
	validate func(context.Context, *sql.Tx, Proof, time.Time) error
}

type totpProofClock struct{ now, started time.Time }
