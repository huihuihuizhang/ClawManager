package control

import (
	"context"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ApplicationGate uses downward-API identity and an API-observed container ID.
// It never falls back to a name-only or unowned permit on a configured cluster.
func ApplicationGate(ctx context.Context, store SQLStore) (ProcessGate, error) {
	ns, name, uid, container := os.Getenv("POD_NAMESPACE"), os.Getenv("POD_NAME"), os.Getenv("POD_UID"), os.Getenv("BACKUP_APP_CONTAINER")
	if ns == "" || name == "" || uid == "" || container == "" {
		return ProcessGate{}, ErrNotReady
	}
	cfg, e := rest.InClusterConfig()
	if e != nil {
		return ProcessGate{}, ErrNotReady
	}
	client, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		return ProcessGate{}, ErrNotReady
	}
	for {
		pod, e := client.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if e != nil || string(pod.UID) != uid {
			return ProcessGate{}, ErrNotReady
		}
		node, e := client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		if e != nil {
			return ProcessGate{}, ErrNotReady
		}
		p, e := IdentifyApplication(pod, node, container)
		if e == nil {
			if e = store.RegisterApplication(ctx, p); e != nil {
				return ProcessGate{}, e
			}
			return ProcessGate{Store: store, Process: p}, nil
		}
		if !waitPoll(ctx, 250*time.Millisecond) {
			return ProcessGate{}, ErrNotReady
		}
	}
}
