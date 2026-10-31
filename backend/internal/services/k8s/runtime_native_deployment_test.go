package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func nativePoolFixture() (RuntimeDeploymentSpec, []runtime.Object) {
	n := &NativeRuntimeConfig{InstallationID: "installation_fixture", NodeName: "node", NodeUID: "node-uid", Ledger: NativeRuntimePVC{"ledger", "ledger-uid", "ledger-pv", "ledger-pv-uid"}, Workspace: NativeRuntimePVC{"workspace", "workspace-uid", "workspace-pv", "workspace-pv-uid"}, TokenSecret: "tokens", TokenSecretUID: "tokens-uid", TLSSecret: "tls", TLSSecretUID: "tls-uid", AppArmorProfile: "clawmanager-bwrap", SeccompProfile: "clawmanager/bwrap.json"}
	spec := RuntimeDeploymentSpec{Native: n, Name: "new-native", Namespace: "tenant", RuntimeType: "openclaw", Image: "registry/runtime@sha256:" + strings.Repeat("a", 64), Replicas: 1, WorkspacePVCClaimName: n.Workspace.Name, GatewayPortStart: 20000, GatewayPortEnd: 20002}
	objects := []runtime.Object{&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.NodeName, UID: types.UID(n.NodeUID), Labels: map[string]string{corev1.LabelHostname: n.NodeName, corev1.LabelOSStable: "linux"}}}}
	for _, ref := range []NativeRuntimePVC{n.Ledger, n.Workspace} {
		objects = append(objects, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: spec.Namespace, UID: types.UID(ref.UID)}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: ref.VolumeName, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOncePod}}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}})
		objects = append(objects, &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: ref.VolumeName, UID: types.UID(ref.VolumeUID)}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain, ClaimRef: &corev1.ObjectReference{Name: ref.Name, Namespace: spec.Namespace, UID: types.UID(ref.UID)}, PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "test.csi.invalid", VolumeHandle: ref.VolumeName}}}})
	}
	immutable := true
	objects = append(objects, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: n.TokenSecret, Namespace: spec.Namespace, UID: types.UID(n.TokenSecretUID)}, Immutable: &immutable, Data: map[string][]byte{"control": []byte("fixture-control"), "report": []byte("fixture-report")}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: n.TLSSecret, Namespace: spec.Namespace, UID: types.UID(n.TLSSecretUID)}, Immutable: &immutable, Data: map[string][]byte{"tls.crt": []byte("fixture-certificate"), "tls.key": []byte("fixture-private-key")}})
	return spec, objects
}

func TestNativeRuntimeEnsurePersistsOriginalSlotPlanAcrossLostCreateResponse(t *testing.T) {
	spec, objects := nativePoolFixture()
	client := fake.NewSimpleClientset(objects...)
	creates := 0
	client.PrependReactor("create", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
		creates++
		d := a.(kt.CreateAction).GetObject().(*appsv1.Deployment).DeepCopy()
		d.UID, d.ResourceVersion = "new-pool-uid", "1"
		// Builder emits concrete API defaults (including image pull policy,
		// fieldRef version and probes), so an API-defaulted retry compares equal.
		if d.Spec.Template.Spec.DNSPolicy != corev1.DNSClusterFirst || d.Spec.Template.Spec.Containers[0].ImagePullPolicy != corev1.PullIfNotPresent || d.Spec.Template.Spec.Containers[0].ReadinessProbe.SuccessThreshold != 1 {
			t.Fatal("API defaults missing")
		}
		if err := client.Tracker().Add(d); err != nil {
			t.Fatal(err)
		}
		return true, nil, errors.New("create response lost")
	})
	s := NewRuntimeDeploymentService(client)
	if err := s.Ensure(context.Background(), spec); err == nil {
		t.Fatal("lost create reported success")
	}
	if err := s.Ensure(context.Background(), spec); err != nil {
		t.Fatal("retry could not rebind original defaulted template", err)
	}
	if creates != 1 {
		t.Fatal("retry created another pool", creates)
	}
	d, err := client.AppsV1().Deployments(spec.Namespace).Get(context.Background(), spec.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if d.Labels[runtimeSchedulingLabel] != "false" || d.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType || *d.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("candidate started scheduling or mounted API token")
	}
	pool, slot := d.Spec.Template.Spec.Containers[0], d.Spec.Template.Spec.Containers[1]
	if slot.ReadinessProbe != nil || slot.LivenessProbe != nil || slot.StartupProbe != nil || pool.ReadinessProbe.TCPSocket == nil {
		t.Fatal("slot inherited a network health probe")
	}
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.SecurityContext == nil || *c.SecurityContext.Privileged || *c.SecurityContext.AllowPrivilegeEscalation || len(c.SecurityContext.Capabilities.Add) != 0 || c.SecurityContext.AppArmorProfile.Type != corev1.AppArmorProfileTypeLocalhost || c.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeLocalhost {
			t.Fatal("unreviewed privilege expansion")
		}
		requireEnvFieldRef(t, c, "POD_UID", "metadata.uid")
		ledger := false
		for _, m := range c.VolumeMounts {
			if m.Name == "ledger" {
				ledger = true
				if m.SubPath != map[string]string{"pool": "pool", "slot": "slot-0"}[c.Name] {
					t.Fatal("shared ledger directory")
				}
			}
		}
		if !ledger {
			t.Fatal("ledger not persisted")
		}
	}
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Name == "ledger" && (v.PersistentVolumeClaim == nil || v.PersistentVolumeClaim.ClaimName != spec.Native.Ledger.Name) {
			t.Fatal("ephemeral ledger")
		}
	}
	// A failed or unsupported runtime cannot escape through legacy Scale.
	if err = s.Scale(context.Background(), spec.Namespace, spec.Name, 0); err == nil {
		t.Fatal("legacy scale stopped the candidate")
	}
}

func TestNativeRuntimeRejectsMissingPermissionsAndResourceDriftBeforeCreate(t *testing.T) {
	for _, fault := range []string{"denied", "ledger-replaced", "not-exclusive", "alias", "delete-policy", "token-replaced", "mutable-token", "node-replaced", "missing-profile", "mutable-image", "replicas", "plain-token"} {
		t.Run(fault, func(t *testing.T) {
			spec, objects := nativePoolFixture()
			for _, object := range objects {
				switch p := object.(type) {
				case *corev1.PersistentVolumeClaim:
					if p.Name == spec.Native.Ledger.Name {
						if fault == "ledger-replaced" {
							p.UID = "replaced"
						}
						if fault == "not-exclusive" {
							p.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
						}
					}
				case *corev1.PersistentVolume:
					if fault == "alias" {
						p.Spec.CSI.VolumeHandle = "same"
					}
					if fault == "delete-policy" {
						p.Spec.PersistentVolumeReclaimPolicy = corev1.PersistentVolumeReclaimDelete
					}
				case *corev1.Secret:
					if p.Name == spec.Native.TokenSecret {
						if fault == "token-replaced" {
							p.UID = "replaced"
						}
						if fault == "mutable-token" {
							p.Immutable = nil
						}
					}
				case *corev1.Node:
					if fault == "node-replaced" {
						p.UID = "replaced"
					}
				}
			}
			if fault == "missing-profile" {
				spec.Native.AppArmorProfile = ""
			}
			if fault == "mutable-image" {
				spec.Image = "registry/runtime:latest"
			}
			if fault == "replicas" {
				spec.Replicas = 2
			}
			if fault == "plain-token" {
				spec.AgentControlToken = "unsafe"
			}
			client := fake.NewSimpleClientset(objects...)
			if fault == "denied" {
				client.PrependReactor("get", "persistentvolumeclaims", func(kt.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "persistentvolumeclaims"}, "ledger", errors.New("denied"))
				})
			}
			if err := NewRuntimeDeploymentService(client).Ensure(context.Background(), spec); err == nil {
				t.Fatal("unsafe native plan admitted")
			}
			for _, a := range client.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("mutation before refusal", a.GetVerb())
				}
			}
		})
	}
}

func TestNativeRuntimeDoesNotAdoptOrRewriteExistingPool(t *testing.T) {
	for _, fault := range []string{"legacy", "image", "sidecar", "probe", "unsafe-policy", "ledger"} {
		t.Run(fault, func(t *testing.T) {
			spec, objects := nativePoolFixture()
			d, err := BuildNativeRuntimeDeployment(spec, *spec.Native)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "legacy":
				d = BuildRuntimeDeployment(spec)
			case "image":
				d.Spec.Template.Spec.Containers[1].Image = "registry/other:latest"
			case "sidecar":
				d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers, corev1.Container{Name: "extra"})
			case "probe":
				d.Spec.Template.Spec.Containers[1].LivenessProbe = &corev1.Probe{}
			case "unsafe-policy":
				d.Spec.Template.Spec.HostPID = true
			case "ledger":
				d.Spec.Template.Spec.Volumes[1].PersistentVolumeClaim.ClaimName = "other"
			}
			objects = append(objects, d)
			client := fake.NewSimpleClientset(objects...)
			if err = NewRuntimeDeploymentService(client).Ensure(context.Background(), spec); err == nil {
				t.Fatal("adopted or ignored changed pool")
			}
			for _, a := range client.Actions() {
				if a.GetVerb() != "get" {
					t.Fatal("rewrote existing pool", a.GetVerb())
				}
			}
		})
	}
}
