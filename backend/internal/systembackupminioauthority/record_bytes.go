package systembackupminioauthority

import "bytes"

// SignedRecords returns owned copies of actual verified ORIGINAL SQL payloads
// for offline tuple resolution/revocation. It is not a readiness capability.
// No record is re-serialized or re-signed to manufacture an original source.
func (s *SQLCurrentSnapshot) SignedRecords() (grant, grantSignature, head, headSignature []byte, refs []SQLSignedReference, err error) {
	if s == nil || s.records == nil {
		err = ErrRecord
		return
	}
	r := s.records
	grant, grantSignature, head, headSignature = bytes.Clone(r.grantRaw), bytes.Clone(r.grantSignature), bytes.Clone(r.headRaw), bytes.Clone(r.headSignature)
	for _, v := range r.signedReferences {
		refs = append(refs, SQLSignedReference{Purpose: v.Purpose, Record: bytes.Clone(v.Record), Signature: bytes.Clone(v.Signature)})
	}
	return
}
