package systembackupexecution

import (
	"context"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

func TestLonghornRecoveryFactoryUsesOriginalCoreWithoutCaptureMaterials(t *testing.T) {
	for _, stale := range []*productionCaptureMaterials{nil, {Version: "stale-forward-materials"}} {
		service := &DeploymentService{ForwardEnabled: false, captureMaterials: stale,
			Config: DeploymentConfig{RuntimeSources: &RuntimeSourceConfig{LonghornHold: &FormalLonghornHoldConfig{}}}}
		owner := &PublicJobOwner{}
		if err := service.attachOriginalLonghornExecution(owner); err != nil || owner.longhornExecutor != nil {
			t.Fatal("recovery startup constructed a forward execution client", err)
		}
		// The original transport config is deliberately incomplete. Recovery
		// must attempt its construction and report it, rather than skip it.
		if err := service.attachLonghornHold(owner); err == nil {
			t.Fatal("recovery silently skipped the configured native owner")
		}
		client := &originalLonghornExecutionClient{service: service, owner: owner}
		if _, err := client.SourceRunner(context.Background(), d.Input{}, plannedLonghornClone{}); err == nil {
			t.Fatal("recovery factory authorized a source snapshot")
		}
		if _, err := client.ContentRunner(context.Background(), d.Input{}, plannedLonghornClone{}, (originalLonghornSource{}).pin()); err == nil {
			t.Fatal("recovery factory authorized retained content creation")
		}
		if service.ForwardEnabled || service.captureMaterials != stale {
			t.Fatal("recovery factory changed the source authorization")
		}
	}
}

func TestLonghornRecoveryFactoryRequiresExplicitOriginalHoldConfig(t *testing.T) {
	service := &DeploymentService{ForwardEnabled: false}
	owner := &PublicJobOwner{}
	if err := service.attachOriginalLonghornExecution(owner); err != nil || owner.longhornExecutor != nil {
		t.Fatal("unconfigured installation received a Longhorn executor", err)
	}
	if err := service.attachLonghornHold(owner); err != nil || owner.longhornCutOwner != nil {
		t.Fatal("unconfigured installation received a native owner", err)
	}
}
