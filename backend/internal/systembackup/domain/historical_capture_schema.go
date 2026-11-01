package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Reviewed historical capture pins, not runtime restore-policy aliases. The
// first is baseline 0e797e4e, where materialize jobs were archived but omitted
// from the drill. The second archives the same table set and preserves terminal
// materialize history in the drill. Neither pin authorizes target writes.
const (
	capturePolicyBaselineV1     = "62ec7bc2c2a6f443e6c26adc8dfbc6b43c3123622c45a09cdb92589a0c95055d"
	capturePolicySkillHistoryV1 = "dfc25ae4d1a6744d853b447a36f401b018281c0b53dacc0ac12668dbc39d8bc8"
	captureTableSetV1           = "59f91c3c7b492765b12b2ed49ba4a038ecff8750e2e417038745c079ed6cf3fa"
)

// MatchHistoricalBusinessCaptureSchema compares lossless archived metadata to
// an ORIGINAL, independently authenticated capture descriptor. It does NOT
// authenticate that descriptor, its policy pin, plaintext, EOF, manifest, full-C
// result or target authority. The formal reader must establish all of those
// before consuming this structural result; no restore/acceptance entry point
// is wired here. Raw JSON alone can never supply those external proofs.
//
// Missing old UniqueKeys remain missing. Reconstructing them from today's
// migrations would change the archived schema digest. A target owner adapter
// still needs a separately reviewed old-schema mapping and current target facts.
func MatchHistoricalBusinessCaptureSchema(snapshot Snapshot, original BusinessCaptureSchema) error {
	if original.PolicySHA256 != capturePolicyBaselineV1 && original.PolicySHA256 != capturePolicySkillHistoryV1 {
		return ErrSchema
	}
	// Prevent a future registry expansion from changing either historical
	// contract. New capture versions need explicit review.
	raw, err := json.Marshal(BusinessCaptureTables())
	if err != nil {
		return ErrSchema
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != captureTableSetV1 || original.Validate() != nil || validateSnapshot(snapshot) != nil {
		return ErrSchema
	}
	actual, err := BusinessCaptureSchemaForTables(snapshot.Tables)
	if err != nil || actual.SchemaSHA256 != original.SchemaSHA256 || len(actual.Tables) != len(original.Tables) {
		return ErrSchema
	}
	for i := range actual.Tables {
		if actual.Tables[i] != original.Tables[i] {
			return ErrSchema
		}
	}
	return nil
}
