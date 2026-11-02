package systembackupcontract

import "encoding/json"

// CatalogRecordResource is one original signed registration, not a global
// recovery-catalog or current recoverability assertion. Record is emitted only
// after the concrete reader validates its complete fixed-version bytes.
type CatalogRecordResource struct {
	ID           string          `json:"id"`
	RecordSHA256 string          `json:"record_sha256"`
	Record       json.RawMessage `json:"record"`
}

type CatalogRecordList struct {
	Items       []CatalogRecordResource `json:"items"`
	NextCursor  *string                 `json:"next_cursor"`
	Consistency string                  `json:"consistency"`
}
