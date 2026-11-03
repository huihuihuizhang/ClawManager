package install

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// OpenTerminalKubernetes constructs a client from this SAME independently
// pinned enrolled consumer locator and its original Plan. It performs only
// bounded local input reads, no API/SQL/provider call, and grants no owner
// approval. Actual terminal and native owners still authenticate current use.
func (s *CaptureSigningConsumer) OpenTerminalKubernetes(ctx context.Context) (kubernetes.Interface, error) {
	if s == nil || consumerNil(ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	pin, err := ReadPrivateFile(s.sourcePinFile, 64)
	if err != nil || !digestPattern.Match(pin) {
		return nil, ErrInstall
	}
	raw, err := ReadPrivateFile(s.sourceFile, 262144)
	var files CaptureConsumerFiles
	if err != nil || hash(raw) != string(pin) || decodeExact(raw, &files) != nil || files.SchemaVersion != CaptureConsumerVersion {
		return nil, ErrInstall
	}
	planRaw, err := ReadPrivateFile(files.PlanFile, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	plan, err := DecodePlan(planRaw, files.PlanSHA256)
	if err != nil || plan.InstallerDatabaseAccount == plan.Target.DatabaseAccount {
		return nil, ErrInstall
	}
	client, err := openCaptureConsumerKubernetes(plan, files.KubeconfigFile, files.KubeconfigSHA256)
	if err != nil || ctx.Err() != nil {
		return nil, ErrInstall
	}
	for _, original := range []consumerPinnedFile{{s.sourcePinFile, hash(pin), 64}, {s.sourceFile, string(pin), 262144}, {files.PlanFile, files.PlanSHA256, 262144}} {
		current, err := ReadPrivateFile(original.path, original.limit)
		if err != nil || hash(current) != original.sha || ctx.Err() != nil {
			return nil, ErrInstall
		}
	}
	return client, nil
}
