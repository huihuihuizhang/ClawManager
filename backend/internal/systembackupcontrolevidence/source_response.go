package systembackupcontrolevidence

import "time"

// Delivered only over the ORIGINAL mTLS/TokenReview/current-Job key-use pull.
// It is transient input to Rebuild->C encryption, never a Kubernetes object or
// ordinary staging file. Both original streams resolve the same exact bundle.
type SourceResponse struct {
	Version                string               `json:"schema_version"`
	InvocationSHA256       string               `json:"invocation_sha256"`
	KeyUseNonce            string               `json:"key_use_nonce"`
	AuthoritySHA256        string               `json:"authority_sha256"`
	Until                  time.Time            `json:"until"`
	Evidence               []RegisteredEvidence `json:"evidence"`
	FinalizedSource        *RegisteredEvidence  `json:"finalized_source,omitempty"`
	FinalizedLocatorChunks []RegisteredEvidence `json:"finalized_locator_chunks,omitempty"`
}
