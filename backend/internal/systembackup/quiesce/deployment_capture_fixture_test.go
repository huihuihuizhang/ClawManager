package quiesce

import (
	"k8s.io/client-go/kubernetes/fake"
	"testing"
)

// The integration regression belongs to quiesce_test because systembackup
// consumes quiesce. Keep the original fixture test-only, without exposing a
// production constructor or duplicating its patch/stop/restart behavior.
func NewCaptureDeploymentFixtureForTest(t *testing.T, replicas int32) (*DeploymentWriter, *fake.Clientset) {
	f := newDeploymentFixture(t, replicas)
	return f.writer, f.client
}
