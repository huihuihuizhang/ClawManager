package systembackup

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

// SQL values are data-plane requests, never SQL ownership or admission proof.
// The original installer separately reads/locks the real complete SQL rows.
// No supplied hash/Passed value can mint a PreparedCoverage or source permit.
type OriginalGatewayImageSQLRequest struct {
	ArtifactID, SQLRowSHA256 string
	PlaintextSize            int64
	Key                      []byte
}
type OriginalGatewayImageVersionCorrespondence struct {
	ArtifactID, SQLRowSHA256, KeySHA256, Bucket, Key, VersionID, BodySHA256 string
	Size                                                                    int64
	DeleteMarker                                                            bool
}
type OriginalGatewayImageHistoryCorrespondence struct {
	origin  *OriginalGatewayImageHistoryCorrespondence
	ctx     context.Context
	history *OriginalProtectedMinIOHistory
	objects []OriginalGatewayImageVersionCorrespondence
	until   time.Time
}

func (*OriginalGatewayImageHistoryCorrespondence) MarshalJSON() ([]byte, error) {
	return nil, ErrMinIOReadGate
}

// Actual fixed-version native GET/EOF/SHA plus the existing application AEAD
// format (nonce || GCM body, AAD=actual SQL artifact ID). No plaintext or key is
// persisted, logged or returned. All historical versions/markers are considered.
func (h *OriginalProtectedMinIOHistory) InspectOriginalGatewayImageHistory(ctx context.Context, bucket, prefix string, requests []OriginalGatewayImageSQLRequest) (*OriginalGatewayImageHistoryCorrespondence, error) {
	if h == nil || h.origin != h || h.failed || !originalMinIOHistorySameContext(ctx, h.ctx) || ctx.Err() != nil || !time.Now().Before(h.facts.Until) || bucket == "" || prefix == "" || !strings.HasSuffix(prefix, "/") || len(requests) > 100000 {
		return nil, ErrMinIOReadGate
	}
	g := h.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.origin != g || !g.held || g.restored || g.recovering || g.pending != nil || g.recheckState(ctx, true) != nil {
		return nil, ErrMinIOReadGate
	}
	byKey := map[string]OriginalGatewayImageSQLRequest{}
	ids := map[string]bool{}
	idPattern := regexp.MustCompile(`^img_[a-f0-9]{32}$`)
	hashPattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for _, r := range requests {
		if !idPattern.MatchString(r.ArtifactID) || ids[r.ArtifactID] || len(r.Key) != 32 || r.PlaintextSize <= 0 || r.PlaintextSize > 16<<20 || !hashPattern.MatchString(r.SQLRowSHA256) {
			return nil, ErrMinIOReadGate
		}
		ids[r.ArtifactID] = true
		byKey[prefix+"gateway-images/"+r.ArtifactID] = r
	}
	out := &OriginalGatewayImageHistoryCorrespondence{ctx: ctx, history: h, until: h.facts.Until, objects: []OriginalGatewayImageVersionCorrespondence{}}
	for _, object := range h.facts.Objects {
		r, exists := byKey[object.Key]
		if !exists || object.Bucket != bucket {
			continue
		}
		item := OriginalGatewayImageVersionCorrespondence{r.ArtifactID, r.SQLRowSHA256, minioGateBytesHash(r.Key), object.Bucket, object.Key, object.VersionID, object.BodySHA256, object.Size, object.DeleteMarker}
		if object.DeleteMarker {
			if object.Size != 0 || object.BodySHA256 != "" {
				return nil, ErrMinIOReadGate
			}
			out.objects = append(out.objects, item)
			continue
		}
		if object.Size != r.PlaintextSize+12+16 || object.Size > 16<<20+64 {
			continue // Unmatched original version is retained for private unknown inventory.
		}
		body, e := g.reader.GetObject(ctx, object.Bucket, object.Key, minio.GetObjectOptions{VersionID: object.VersionID})
		if e != nil {
			return nil, ErrMinIOReadGate
		}
		st, e := body.Stat()
		if e != nil || st.VersionID != object.VersionID || st.Size != object.Size || st.ETag != object.ETag || !st.LastModified.Equal(object.ModifiedAt) {
			body.Close()
			return nil, ErrMinIOReadGate
		}
		raw, e := io.ReadAll(io.LimitReader(body, object.Size+1))
		ce := body.Close()
		if e != nil || ce != nil || int64(len(raw)) != object.Size || minioGateBytesHash(raw) != object.BodySHA256 {
			clear(raw)
			return nil, ErrMinIOReadGate
		}
		block, e := aes.NewCipher(r.Key)
		if e != nil {
			clear(raw)
			return nil, ErrMinIOReadGate
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil || len(raw) < gcm.NonceSize()+gcm.Overhead() {
			clear(raw)
			return nil, ErrMinIOReadGate
		}
		plain, e := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(r.ArtifactID))
		clear(raw)
		if e != nil || int64(len(plain)) != r.PlaintextSize {
			clear(plain)
			continue // Bad/older-key ciphertext remains unclassified; never labelled business.
		}
		clear(plain)
		out.objects = append(out.objects, item)
	}
	if g.recheckState(ctx, true) != nil || !time.Now().Before(out.until) {
		return nil, ErrMinIOReadGate
	}
	out.origin = out
	return out, nil
}

// Comparison data only; genuine installer owns independent real SQL row/key
// equality and must bind this exact native handle and original request set.
func (s *OriginalGatewayImageHistoryCorrespondence) OriginalImageHistoryData(ctx context.Context, history *OriginalProtectedMinIOHistory) ([]OriginalGatewayImageVersionCorrespondence, error) {
	if s == nil || s.origin != s || s.history == nil || s.history.origin != s.history || !originalMinIOHistorySameContext(ctx, s.ctx) || ctx.Err() != nil || !time.Now().Before(s.until) || history != s.history {
		return nil, ErrMinIOReadGate
	}
	if _, e := s.history.OriginalHistoryData(ctx); e != nil {
		return nil, ErrMinIOReadGate
	}
	return append([]OriginalGatewayImageVersionCorrespondence(nil), s.objects...), nil
}
