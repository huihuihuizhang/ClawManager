package systembackupexecution

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"time"

	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

// Only one bounded range of the exact previously observed native version.
// A provider that ignores Range or substitutes total/version/encoding fails.
func (s *nativePublicationS3) openRange(ctx context.Context, object ArtifactReadObject, offset, size int64, until time.Time) (io.ReadCloser, error) {
	if s == nil || object.Size < 1 || object.Size > s.maxObjectBytes || offset < 0 || offset >= object.Size || size < 1 || size > object.Size-offset {
		return nil, errPublicationUnavailable
	}
	start, end := strconv.FormatInt(offset, 10), strconv.FormatInt(offset+size-1, 10)
	response, err := s.requestWithRange(ctx, "GET", object.Key, object.Version, nil, 0, "", until, false, "", "bytes="+start+"-"+end)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 206 || response.Header.Get("Content-Range") != "bytes "+start+"-"+end+"/"+strconv.FormatInt(object.Size, 10) || response.ContentLength != size || response.Header.Get("x-amz-version-id") != object.Version || response.Header.Get("Content-Encoding") != "" || response.Header.Get("x-amz-delete-marker") == "true" {
		response.Body.Close()
		return nil, errPublicationUnavailable
	}
	return response.Body, nil
}

func (r *ArtifactReadOnlyS3) checkContainerMember(object ArtifactReadObject, member pc.Member, location pc.MemberLocation) error {
	if r == nil || r.store == nil || !r.store.readOnly || r.limits.validate() != nil || object.Size < 1 || object.Size > r.limits.MaxArtifactBytes || !formalCandidateDigest(object.SHA256) || location.ObjectVersion != object.Version || location.Part != member.Part || location.Index != member.Index || location.CipherBytes != member.CipherBytes || location.CipherSHA256 != member.CipherSHA256 || location.EnvelopeBytes != member.EnvelopeBytes || location.EnvelopeSHA256 != member.EnvelopeSHA256 || !formalCandidateDigest(member.CipherSHA256) || !formalCandidateDigest(member.EnvelopeSHA256) || location.CipherOffset < 12 || location.CipherBytes < 1 || location.CipherOffset >= object.Size || location.CipherBytes > object.Size-location.CipherOffset || location.EnvelopeOffset != location.CipherOffset+location.CipherBytes || location.EnvelopeBytes < 1 || location.EnvelopeBytes > 32<<20 || location.EnvelopeOffset >= object.Size || location.EnvelopeBytes > object.Size-location.EnvelopeOffset {
		return errPublicationUnavailable
	}
	keyContext := member.Stream.Request.Context
	key := r.store.config.Root + keyContext.BackupPublicID + "/" + keyContext.AttemptNo + "/parts/" + publicationRequestedPart(member.Operation) + "/container.enc"
	if keyContext.InstallationID != r.store.config.InstallationID || keyContext.Part != member.Part || keyContext.PartIndex != strconv.FormatUint(uint64(member.Index), 10) || object.Key != key || !safePublicationKey(key) {
		return errPublicationUnavailable
	}
	return nil
}

// ReadContainerEnvelope returns only the bounded, hash-checked original
// envelope. The caller obtains its CURRENT independently authorized Unwrapper
// for these exact bytes; no authority or DEK is inferred from container facts.
func (r *ArtifactReadOnlyS3) ReadContainerEnvelope(ctx context.Context, object ArtifactReadObject, member pc.Member, location pc.MemberLocation, until time.Time) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || r.checkContainerMember(object, member, location) != nil {
		return nil, errPublicationUnavailable
	}
	body, err := r.store.openRange(ctx, object, location.EnvelopeOffset, location.EnvelopeBytes, until)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, location.EnvelopeBytes+1))
	closeErr := body.Close()
	if err != nil || closeErr != nil || int64(len(raw)) != location.EnvelopeBytes || hash(raw) != member.EnvelopeSHA256 || ctx.Err() != nil || !time.Now().Before(until) {
		clear(raw)
		return nil, errPublicationUnavailable
	}
	if _, err := w.ParseStreamEnvelope(member.Stream, raw); err != nil {
		clear(raw)
		return nil, err
	}
	if _, err := r.store.credential(false); err != nil {
		clear(raw)
		return nil, err
	}
	return raw, nil
}

// InspectContainerCipher authenticates the complete original C stream and
// invokes the inert plaintext inspector under the caller's CURRENT Unwrapper.
// It returns no proof on unread suffix/AEAD/EOF/hash/provider post-use failure.
// This leaf does not select a business verifier or mint finalization authority.
func (r *ArtifactReadOnlyS3) InspectContainerCipher(ctx context.Context, object ArtifactReadObject, member pc.Member, location pc.MemberLocation, envelope []byte, keys w.Unwrapper, inspect func(io.Reader) error, until time.Time) (w.StreamVerification, error) {
	var zero w.StreamVerification
	if ctx == nil || ctx.Err() != nil || keys == nil || inspect == nil || r.checkContainerMember(object, member, location) != nil || int64(len(envelope)) != member.EnvelopeBytes {
		return zero, errPublicationUnavailable
	}
	// Validate the same owned bytes that the provider and AEAD verifier use.
	ownedEnvelope := bytes.Clone(envelope)
	defer clear(ownedEnvelope)
	if hash(ownedEnvelope) != member.EnvelopeSHA256 {
		return zero, errPublicationUnavailable
	}
	if _, err := w.ParseStreamEnvelope(member.Stream, ownedEnvelope); err != nil {
		return zero, err
	}
	body, err := r.store.openRange(ctx, object, location.CipherOffset, location.CipherBytes, until)
	if err != nil {
		return zero, err
	}
	defer body.Close()
	verified, err := w.InspectWrappedStream(ctx, member.Stream, ownedEnvelope, body, keys, inspect)
	closeErr := body.Close()
	if err != nil {
		return zero, err
	}
	if closeErr != nil || verified.CiphertextBytes() != member.CipherBytes || verified.CiphertextSHA256() != member.CipherSHA256 || ctx.Err() != nil || !time.Now().Before(until) {
		return zero, errPublicationUnavailable
	}
	if _, err := r.store.credential(false); err != nil {
		return zero, err
	}
	return verified, nil
}
