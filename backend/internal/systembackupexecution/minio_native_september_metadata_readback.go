package systembackupexecution

import (
	mn "clawreef/internal/systembackup/minionative"
	"context"
)

// Preserve the original comparator for all existing exact matches. The only
// extra wire representation admitted is the exact fixed September metadata
// observer document; no generic sourceGatePolicySame behavior changes.
func nativeInstallSeptemberMetadataPolicySame(ctx context.Context, n *minioPermissionHTTP, actual, expected []byte) bool {
	if sourceGatePolicySame(actual, expected) {
		return true
	}
	read := *n
	read.requests = 0
	if _, e := read.serverSeptember(ctx); e != nil {
		return false
	}
	normalized, e := mn.NormalizeSeptemberMetadataObserverReadback(actual)
	return e == nil && sourceGatePolicySame(normalized, expected)
}
