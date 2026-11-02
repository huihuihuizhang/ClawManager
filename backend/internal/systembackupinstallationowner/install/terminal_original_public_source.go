package install

import (
	"context"
	"crypto/ed25519"
)

// Both terminal loaders choose their verification key ONLY through the exact
// locator bytes already authenticated by capture.load. A final current-files
// reread alone cannot detect a substituted locator restored before that tail.
// This helper performs bounded local reads only and returns public source DATA.
func readBootstrapOriginalPublicSource(ctx context.Context, capture *CaptureSigningConsumer, source *consumerCaptureState) (CaptureConsumerFiles, Plan, ed25519.PublicKey, error) {
	var locator CaptureConsumerFiles
	var plan Plan
	fail := func() (CaptureConsumerFiles, Plan, ed25519.PublicKey, error) {
		if source != nil {
			source.finish(ErrInstall)
		}
		return CaptureConsumerFiles{}, Plan{}, nil, ErrInstall
	}
	if capture == nil || source == nil || source.failed.Load() || !consumerSameContext(ctx, source.ctx) || ctx.Err() != nil {
		return fail()
	}
	raw, e := ReadPrivateFile(capture.sourceFile, 262144)
	if e != nil {
		return fail()
	}
	pinned := false
	for _, file := range source.files {
		if file.path == capture.sourceFile && file.sha == hash(raw) {
			pinned = true
		}
	}
	if !pinned || decodeExact(raw, &locator) != nil {
		return fail()
	}
	planRaw, e := ReadPrivateFile(locator.PlanFile, 262144)
	if e != nil {
		return fail()
	}
	plan, e = DecodePlan(planRaw, locator.PlanSHA256)
	if e != nil {
		return fail()
	}
	public, e := ReadPrivateFile(locator.IssuerPublicFile, 32)
	if e != nil || len(public) != ed25519.PublicKeySize || hash(public) != locator.IssuerPublicSHA256 || locator.IssuerPublicSHA256 != plan.IssuerPublicKeySHA256 {
		return fail()
	}
	return locator, plan, public, nil
}
