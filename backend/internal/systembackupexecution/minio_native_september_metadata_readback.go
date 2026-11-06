package systembackupexecution

import (
	"bytes"
	"context"

	mn "clawreef/internal/systembackup/minionative"
	ma "clawreef/internal/systembackupminioauthority"
)

// Preserve exact matches and the fixed September metadata projection. Only
// the authenticated DeleteCompat tuple can compare generated policy order.
func nativeInstallPolicyReadbackSame(ctx context.Context, n *minioPermissionHTTP, actual, expected []byte) bool {
	if sourceGatePolicySame(actual, expected) {
		return true
	}
	read := *n
	read.requests = 0
	permission := ma.SeptemberPermissionProfile
	if ma.MatchesDeleteCompatImageID(read.provider.ImageID) {
		permission = ma.DeleteCompatPermissionProfile
	}
	if _, e := read.serverBuiltinFlat(ctx, permission); e != nil {
		return false
	}
	normalized, e := mn.NormalizeSeptemberMetadataObserverReadback(actual)
	if e == nil && sourceGatePolicySame(normalized, expected) {
		return true
	}
	if permission != ma.DeleteCompatPermissionProfile {
		return false
	}
	observed, e := minioPermissionCanonicalPolicyOrder(actual, true)
	if e != nil {
		return false
	}
	intended, e := minioPermissionCanonicalPolicyOrder(expected, true)
	return e == nil && bytes.Equal(observed, intended)
}

// Use the original strict comparison first. On the fixed patched image, the
// exact metadata-only wire projection must still match the original pin/rules.
func (n *minioPermissionHTTP) normalizedBuiltinFlatPolicy(ctx context.Context, raw []byte, pin string, rules []minioPermissionRule) ([]byte, error) {
	value, err := minioPermissionNormalizedPolicyV2(raw, pin, rules)
	if err == nil || !ma.MatchesDeleteCompatImageID(n.provider.ImageID) {
		return value, err
	}
	projected, projectionErr := mn.NormalizeSeptemberMetadataObserverReadback(raw)
	if projectionErr != nil {
		return nil, err
	}
	read := *n
	read.requests = 0
	if _, probeErr := read.serverBuiltinFlat(ctx, ma.DeleteCompatPermissionProfile); probeErr != nil {
		return nil, probeErr
	}
	return minioPermissionNormalizedPolicyV2(projected, pin, rules)
}
