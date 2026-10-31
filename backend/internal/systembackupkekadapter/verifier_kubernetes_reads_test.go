package systembackupkekadapter

import (
	"context"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func verifierReadFixture(kind string) (VerifierKubernetesReads, ControllerVerifierWorkload, *fake.Clientset) {
	r := VerifierKubernetesReads{Version: VerifierKubernetesReadsVersion, Namespace: "control", NamespaceUID: "ns-uid", PodName: "controller-pod", PodUID: "pod-uid", ServiceAccountName: "controller", ServiceAccountUID: "sa-uid", OwnerKind: kind, OwnerName: "controller-owner", OwnerUID: "owner-uid"}
	w := ControllerVerifierWorkload{Namespace: r.Namespace, PodName: r.PodName, PodUID: r.PodUID, ServiceAccountName: r.ServiceAccountName, ServiceAccountUID: r.ServiceAccountUID, OwnerKind: kind, OwnerUID: r.OwnerUID}
	controller := true
	ref := metav1.OwnerReference{Kind: kind, Name: r.OwnerName, UID: types.UID(r.OwnerUID), Controller: &controller, APIVersion: "apps/v1"}
	objects := []runtime.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: r.Namespace, UID: types.UID(r.NamespaceUID)}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: r.ServiceAccountName, Namespace: r.Namespace, UID: types.UID(r.ServiceAccountUID)}}}
	meta := metav1.ObjectMeta{Name: r.OwnerName, Namespace: r.Namespace, UID: types.UID(r.OwnerUID)}
	switch kind {
	case "Deployment":
		r.ReplicaSetName, r.ReplicaSetUID = "controller-rs", "rs-uid"
		objects = append(objects, &appsv1.Deployment{ObjectMeta: meta}, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: r.ReplicaSetName, Namespace: r.Namespace, UID: types.UID(r.ReplicaSetUID), OwnerReferences: []metav1.OwnerReference{ref}}})
		ref = metav1.OwnerReference{Kind: "ReplicaSet", Name: r.ReplicaSetName, UID: types.UID(r.ReplicaSetUID), Controller: &controller, APIVersion: "apps/v1"}
	case "StatefulSet":
		objects = append(objects, &appsv1.StatefulSet{ObjectMeta: meta})
	case "Job":
		ref.APIVersion = "batch/v1"
		objects = append(objects, &batchv1.Job{ObjectMeta: meta})
	}
	objects = append(objects, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: r.PodName, Namespace: r.Namespace, UID: types.UID(r.PodUID), OwnerReferences: []metav1.OwnerReference{ref}}, Spec: corev1.PodSpec{ServiceAccountName: r.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}})
	return r, w, fake.NewSimpleClientset(objects...)
}

func TestVerifierExactReadsMatchActualOwnerLookups(t *testing.T) {
	for _, kind := range []string{"Deployment", "StatefulSet", "Job"} {
		t.Run(kind, func(t *testing.T) {
			r, w, k := verifierReadFixture(kind)
			if err := r.Check(context.Background(), k, w); err != nil {
				t.Fatal(err)
			}
			want, err := r.RequiredReads(w)
			if err != nil {
				t.Fatal(err)
			}
			var got []VerifierNamedRead
			for _, action := range k.Actions() {
				get, ok := action.(kt.GetAction)
				if !ok || action.GetVerb() != "get" {
					t.Fatal("non-GET lookup", action)
				}
				got = append(got, VerifierNamedRead{action.GetNamespace(), action.GetResource().Group, action.GetResource().Resource, get.GetName()})
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("role inventory differs from actual owner reads: want %#v got %#v", want, got)
			}
		})
	}
}

func TestVerifierExactReadsRejectSubstitutionBeforeOwnerGet(t *testing.T) {
	for _, fault := range []string{"pod-uid", "namespace-uid", "sa-uid", "pod-parent-name", "pod-parent-uid", "rs-parent-name", "rs-parent-uid", "owner-uid", "owner-forbidden", "rs-forbidden"} {
		t.Run(fault, func(t *testing.T) {
			r, w, k := verifierReadFixture("Deployment")
			ctx := context.Background()
			pod, _ := k.CoreV1().Pods(r.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
			switch fault {
			case "pod-uid":
				pod.UID = "other"
				k.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
			case "pod-parent-name":
				pod.OwnerReferences[0].Name = "ungranted-rs"
				k.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
			case "pod-parent-uid":
				pod.OwnerReferences[0].UID = "other"
				k.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
			case "namespace-uid":
				ns, _ := k.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
				ns.UID = "other"
				k.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
			case "sa-uid":
				sa, _ := k.CoreV1().ServiceAccounts(r.Namespace).Get(ctx, r.ServiceAccountName, metav1.GetOptions{})
				sa.UID = "other"
				k.CoreV1().ServiceAccounts(r.Namespace).Update(ctx, sa, metav1.UpdateOptions{})
			case "rs-parent-name", "rs-parent-uid":
				rs, _ := k.AppsV1().ReplicaSets(r.Namespace).Get(ctx, r.ReplicaSetName, metav1.GetOptions{})
				if fault == "rs-parent-name" {
					rs.OwnerReferences[0].Name = "ungranted-owner"
				} else {
					rs.OwnerReferences[0].UID = "other"
				}
				k.AppsV1().ReplicaSets(r.Namespace).Update(ctx, rs, metav1.UpdateOptions{})
			case "owner-uid":
				d, _ := k.AppsV1().Deployments(r.Namespace).Get(ctx, r.OwnerName, metav1.GetOptions{})
				d.UID = "other"
				k.AppsV1().Deployments(r.Namespace).Update(ctx, d, metav1.UpdateOptions{})
			case "owner-forbidden", "rs-forbidden":
				resource := "deployments"
				if fault == "rs-forbidden" {
					resource = "replicasets"
				}
				k.PrependReactor("get", resource, func(action kt.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: resource}, action.(kt.GetAction).GetName(), nil)
				})
			}
			k.ClearActions()
			if err := r.Check(ctx, k, w); err == nil {
				t.Fatal("changed or forbidden actor admitted")
			}
			for _, action := range k.Actions() {
				if action.GetVerb() != "get" {
					t.Fatal("mutation during validation")
				}
				get := action.(kt.GetAction)
				if get.GetName() == "ungranted-rs" || get.GetName() == "ungranted-owner" {
					t.Fatal("ungranted parent fetched")
				}
				if (fault == "rs-parent-name" || fault == "rs-parent-uid") && action.GetResource().Resource == "deployments" {
					t.Fatal("owner fetched after parent mismatch")
				}
				if (fault == "pod-parent-name" || fault == "pod-parent-uid") && action.GetResource().Group == "apps" {
					t.Fatal("owner fetched after Pod parent mismatch")
				}
			}
		})
	}
	r, w, k := verifierReadFixture("Deployment")
	r.NamespaceUID = ""
	if r.Check(context.Background(), k, w) == nil || len(k.Actions()) != 0 {
		t.Fatal("incomplete mapping reached API")
	}
}
