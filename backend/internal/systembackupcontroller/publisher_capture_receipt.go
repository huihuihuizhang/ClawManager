package systembackupcontroller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	security "clawreef/internal/systembackupsecurity"
)

// Constructed only after the controlled reader authenticates the original
// ciphertext and compares the final original SQL snapshot. No public DTO can
// manufacture this receipt or change its selected part/candidate/key-use.
type publisherCaptureReceipt struct {
	records   SQLExecutionRecords
	access    *security.SQLPublisherCaptureAuthority
	part      b.JobPart
	snapshot  publisherHistorySnapshot
	recordSHA string
}

// The actual deployment wrapper checks current local deployment/material
// binding only; it must not contact Kubernetes/provider or open another SQL
// transaction. The publisher concrete authority independently proves its claim.
type PublisherVerifierDeploymentBinding interface {
	CheckPublisherVerifierDeployment(context.Context, security.PublisherCaptureDeployment) error
}

func publisherCaptureRecordHash(record PublisherCaptureRecord) string {
	raw, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	defer clear(raw)
	// encoding/json compacts RawMessage values; additionally frame their EXACT
	// original bytes so even whitespace replacement cannot pass this receipt.
	digest := sha256.New()
	for _, part := range [][]byte{[]byte("system-backup-publisher-capture-output.v1\x00"), raw, record.Input.ConfigSnapshot, record.Plan.CanonicalJSON, record.CandidateJSON, record.PartResult.Checkpoint} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		digest.Write(size[:])
		digest.Write(part)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// RecheckTx validates THIS authenticated output and its exact original rows
// under the caller's same current publisher/KEK transaction. It performs only
// bounded original SQL reads plus the concrete authority's local grant checks.
// Network and record-key/DEK operations remain outside these locks.
func (record PublisherCaptureRecord) RecheckTx(ctx context.Context, tx *sql.Tx, access *security.SQLPublisherCaptureAuthority) error {
	receipt := record.receipt
	if receipt == nil || access == nil || receipt.access != access || tx == nil || absentExecutionDependency(ctx) || ctx.Err() != nil || receipt.recordSHA == "" || publisherCaptureRecordHash(record) != receipt.recordSHA || !record.ValidUntil.Equal(access.ValidUntil()) || !time.Now().Before(record.ValidUntil) {
		return ErrExecutionAuthority
	}
	snapshot, err := receipt.records.publisherReadSnapshotTx(ctx, tx, access, &receipt.part)
	if err != nil || !publisherSameSnapshot(receipt.snapshot, snapshot) {
		return ErrExecutionRecord
	}
	return nil
}
