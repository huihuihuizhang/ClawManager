package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"clawreef/internal/models"
	"clawreef/internal/services/k8s"
)

type retryIdentityDeployment struct {
	*fakeRuntimeDeploymentService
	present bool
}

func (d *retryIdentityDeployment) RuntimePodUIDPresent(context.Context, string, string, string) (bool, error) {
	return d.present, nil
}

func TestUnhealthyPodRetainedBindingRetry(t *testing.T) {
	for _, tc := range []struct {
		name                                                                                           string
		oldPresent, agentAlive, recent, missingUID, kubeError, stopped, differentGeneration, noBinding bool
		wantRecovery                                                                                   bool
	}{
		{name: "deleted Pod retries interrupted failover", wantRecovery: true},
		{name: "NotReady old Pod still exists", oldPresent: true},
		{name: "old endpoint still responds", agentAlive: true},
		{name: "heartbeat recent", recent: true},
		{name: "missing original UID", missingUID: true},
		{name: "Kubernetes read failed", kubeError: true},
		{name: "stopped instance", stopped: true},
		{name: "generation changed", differentGeneration: true},
		{name: "historical pool has no binding", noBinding: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			seen := time.Now().UTC().Add(-time.Hour)
			if tc.recent {
				seen = time.Now().UTC()
			}
			uid, endpoint := "old-hermes-uid", "https://old-hermes:8090"
			instances := newFakeRuntimeInstanceRepo()
			instances.byID[3] = &models.Instance{ID: 3, Status: "running", RuntimeGeneration: 8}
			if tc.stopped {
				instances.byID[3].Status = "stopped"
			}
			if tc.differentGeneration {
				instances.byID[3].RuntimeGeneration = 9
			}
			bindings := newFakeRuntimeBindingRepo()
			if !tc.noBinding {
				bindings.bindings[3] = &models.InstanceRuntimeBinding{InstanceID: 3, RuntimePodID: 5, Generation: 8, GatewayID: "gw-3-8", State: "running"}
			}
			old := &models.RuntimePod{ID: 5, RuntimeType: RuntimeTypeHermes, Namespace: "clawmanager-system", PodName: "old-hermes", PodUID: &uid, AgentEndpoint: &endpoint, State: "unhealthy", LastSeenAt: &seen}
			if tc.missingUID {
				old.PodUID = nil
			}
			pods := &fakeRuntimePodRepo{pods: map[int64]*models.RuntimePod{5: old}}
			deployment := &fakeRuntimeDeploymentService{pods: []k8s.RuntimeDeploymentPod{{Namespace: old.Namespace, PodName: "new-hermes", PodUID: "new-hermes-uid", RuntimeType: RuntimeTypeHermes, State: "ready"}}}
			if tc.oldPresent {
				deployment.pods = append(deployment.pods, k8s.RuntimeDeploymentPod{Namespace: old.Namespace, PodName: old.PodName, PodUID: uid, RuntimeType: RuntimeTypeHermes, State: "unhealthy"})
			}
			if tc.kubeError {
				deployment.listErr = context.DeadlineExceeded
			}
			agent := &fakeRuntimeAgentClient{healthErr: errors.New("connection refused")}
			if tc.agentAlive {
				agent.healthErr = nil
			}
			s := NewRuntimeScheduler(instances, pods, bindings, &fakeRuntimeRolloutRepo{}, agent, NewRuntimeEventService(nil), nil, &retryIdentityDeployment{deployment, tc.oldPresent}, time.Second, WithRuntimeSchedulerHeartbeatTimeout(10*time.Second))
			if tc.wantRecovery {
				// The first attempt leaves the pool unhealthy and the binding intact.
				instances.updateRuntimeStateErr = errors.New("transient SQL failure")
				if err := s.failoverStalePods(ctx); err == nil {
					t.Fatal("missing first-attempt failure")
				}
				if bindings.bindings[3] == nil || pods.releases[5] != 0 {
					t.Fatal("failed attempt lost binding")
				}
				instances.updateRuntimeStateErr = nil
			}
			err := s.failoverStalePods(ctx)
			if tc.kubeError {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("wrong Kubernetes error: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if tc.wantRecovery {
				state := instances.runtimeStates[3]
				if bindings.bindings[3] != nil || state.status != "creating" || state.generation != 9 || pods.releases[5] != 1 {
					t.Fatalf("not recovered: state=%+v binding=%+v", state, bindings.bindings[3])
				}
				if err := s.failoverStalePods(ctx); err != nil || pods.releases[5] != 1 {
					t.Fatal("empty historical pool retried")
				}
			} else {
				if (!tc.noBinding && bindings.bindings[3] == nil) || pods.releases[5] != 0 || len(instances.runtimeStates) != 0 {
					t.Fatal("unconfirmed/stopped/changed binding was modified")
				}
			}
		})
	}
}
