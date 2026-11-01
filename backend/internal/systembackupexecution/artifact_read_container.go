package systembackupexecution

import (
	"context"
	"io"
	"strconv"
	"strings"
	"time"

	pc "clawreef/internal/systembackuppartcontainer"
)

// This deliberately supports only the sequential ReaderAt pattern of Inspect.
// A changed codec that seeks backwards must fail rather than reuse unverified
// bytes. The last read probes the actual HTTP body EOF, beyond the known size.
type publicationSequentialObject struct {
	ctx    context.Context
	body   io.Reader
	offset int64
	eof    bool
}

func (r *publicationSequentialObject) ReadAt(dst []byte, offset int64) (int, error) {
	if r == nil || r.ctx == nil || r.body == nil || offset != r.offset {
		return 0, errPublicationUnavailable
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := io.ReadFull(r.body, dst)
	r.offset += int64(n)
	if err == io.EOF && n == 0 {
		r.eof = true
	}
	if r.ctx.Err() != nil {
		return n, r.ctx.Err()
	}
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

// InspectPartContainer independently reads one fixed native object using only
// artifact_read credentials. It verifies the complete container/hash, member
// ciphertext hashes, original checkpoints and envelopes with bounded streaming
// memory. Returned facts are inert CONTENT: no Unwrap/plaintext/domain proof,
// signing permission, cleanup acceptance or terminal task authority is minted.
// The caller must obtain object hashes/scope/checkpoints from authenticated
// original records and separately verify all C payloads before finalization.
func (r *ArtifactReadOnlyS3) InspectPartContainer(ctx context.Context, object ArtifactReadObject, scope pc.Scope, checkpoints map[string]string, until time.Time) (pc.Facts, error) {
	var zero pc.Facts
	if ctx == nil || ctx.Err() != nil || r == nil || r.store == nil || !r.store.readOnly || r.limits.validate() != nil || scope.Installation != r.store.config.InstallationID || object.Size < 1 || object.Size > r.limits.MaxArtifactBytes || !formalCandidateDigest(object.SHA256) || object.Version == "" || object.Version == "null" || object.Version == "latest" || object.Version == "current" || len(object.Version) > 256 || strings.ContainsAny(object.Version, "\x00\r\n") {
		return zero, errPublicationUnavailable
	}
	key := r.store.config.Root + scope.Backup + "/" + strconv.FormatUint(scope.Attempt, 10) + "/parts/" + scope.Part + "/container.enc"
	if object.Key != key || !safePublicationKey(key) || until.IsZero() || !time.Now().Before(until) {
		return zero, errPublicationUnavailable
	}
	observed, err := r.store.stat(ctx, object.Key, object.Version, until)
	if err != nil || observed.Size != object.Size {
		return zero, errPublicationUnavailable
	}
	body, err := r.store.open(ctx, observed, until)
	if err != nil {
		return zero, err
	}
	defer body.Close()
	stream := &publicationSequentialObject{ctx: ctx, body: body}
	facts, err := pc.Inspect(ctx, pc.FixedObject{Reader: stream, Version: object.Version, SHA256: object.SHA256, Size: object.Size}, scope, checkpoints, r.limits.MaxArtifactBytes, r.limits.MaxIndexBytes)
	closeErr := body.Close()
	if err != nil {
		return zero, err
	}
	if closeErr != nil || stream.offset != object.Size || !stream.eof || ctx.Err() != nil || !time.Now().Before(until) {
		return zero, errPublicationUnavailable
	}
	if _, err := r.store.credential(false); err != nil {
		return zero, err
	}
	return facts, nil
}
