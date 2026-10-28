package kube

import (
	"reflect"
	"strings"
	"testing"
)

func TestWorkerEgressIsBoundToExactJobAndEndpoints(t *testing.T) {
	i := Identity{"cm-drill-fixture", "worker", "owner"}
	p, err := WorkerEgressPolicy(i, WorkerEndpoint{"10.2.3.4", 8443}, &WorkerEndpoint{"10.2.3.5", 3306}, []string{"10.2.0.10"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.Ingress) != 0 || len(p.Spec.Egress) != 4 || p.Spec.Egress[0].To[0].IPBlock.CIDR != "10.2.3.4/32" || p.Spec.Egress[1].To[0].IPBlock.CIDR != "10.2.3.5/32" {
		t.Fatal("broad network access")
	}
	j, err := DatabaseJob(DatabaseJobRequest{Identity: i, Image: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", StagingClaim: "input", Operation: "verify-database", DeadlineSeconds: 60, Control: WorkerControl{URL: "https://control", InvocationConfigMap: "request", IdentitySecret: "identity"}})
	if err != nil || !reflect.DeepEqual(j.Spec.Template.Labels, p.Spec.PodSelector.MatchLabels) {
		t.Fatal("network selector does not match worker", err)
	}
	other := i
	other.Name = "another-worker"
	if reflect.DeepEqual(workerLabels(other), p.Spec.PodSelector.MatchLabels) {
		t.Fatal("policy also selects another worker")
	}
	for _, ip := range []string{"0.0.0.0/0", "0.0.0.0", "::", "127.0.0.1", "database.example", "224.0.0.1"} {
		if _, err = WorkerEgressPolicy(i, WorkerEndpoint{ip, 443}, nil, nil); err == nil {
			t.Fatal("unscoped endpoint accepted", ip)
		}
	}
}
