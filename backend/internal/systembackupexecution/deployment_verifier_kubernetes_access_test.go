package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	w "clawreef/internal/systembackupwire"
	authv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func verifierAccessFixture(t *testing.T) (DeploymentConfig, FormalVerifierDeploymentConfig, FormalVerifierInput) {
	t.Helper()
	cfg := captureAccessFixture(t)
	dir := t.TempDir()
	cfg.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(dir, "materials.json")}
	issuer := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	workload := a.ControllerVerifierWorkload{Namespace: cfg.Namespace, PodName: "publisher-pod", PodUID: "publisher-pod-uid", ServiceAccountName: "publisher-controller", ServiceAccountUID: "publisher-sa-uid", OwnerKind: "Deployment", OwnerUID: "publisher-deployment-uid", ControllerOwner: cfg.ControllerOwner, GrantSHA256: strings.Repeat("a", 64), ConfigVersion: 1, ConfigSHA256: strings.Repeat("b", 64)}
	reads := a.VerifierKubernetesReads{Version: a.VerifierKubernetesReadsVersion, Namespace: workload.Namespace, NamespaceUID: "ns-uid", PodName: workload.PodName, PodUID: workload.PodUID, ServiceAccountName: workload.ServiceAccountName, ServiceAccountUID: workload.ServiceAccountUID, OwnerKind: workload.OwnerKind, OwnerName: "publisher-controller", OwnerUID: workload.OwnerUID, ReplicaSetName: "publisher-rs", ReplicaSetUID: "publisher-rs-uid"}
	material := FormalVerifierDeploymentConfig{Version: formalVerifierMaterialsVersion, Database: reg.DatabaseIdentity{ServerUUID: "original-server", Database: "original-database"}, Binding: reg.Binding{InstallationID: cfg.InstallationID, Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("c", 64), RegistryVersion: "r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Provider: reg.ProviderBinding{CAPEMSHA256: strings.Repeat("d", 64)}}, GenerateCapability: a.ProviderCapabilityPin{Issuer: issuer}, UnwrapCapability: a.ProviderCapabilityPin{Issuer: issuer}, InstallationIssuer: issuer, CAFile: filepath.Join(dir, "ca.crt"), JWTFile: filepath.Join(dir, "controller.jwt"), Workload: workload, Grant: a.ControllerVerifierGrantMount{File: filepath.Join(dir, "grant.json"), SHA256: workload.GrantSHA256, Issuer: issuer}, KubernetesReads: &reads}
	if err := material.validate(cfg); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(material)
	if err := os.WriteFile(cfg.FormalVerifier.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return cfg, material, FormalVerifierInput{File: cfg.FormalVerifier.Path, SHA256: hash(raw)}
}

func TestDeploymentVerifierGrantsAndLiveProbeShareExactReadInventory(t *testing.T) {
	cfg, material, input := verifierAccessFixture(t)
	before, _ := json.Marshal(cfg.Writers)
	objects, err := CaptureKubernetesGrants(cfg, material.Workload.ServiceAccountName, input)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := material.KubernetesReads.RequiredReads(material.Workload)
	if err != nil {
		t.Fatal(err)
	}
	var generated []a.VerifierNamedRead
	for _, object := range objects {
		var namespace string
		var rules []rbacv1.PolicyRule
		switch role := object.(type) {
		case *rbacv1.Role:
			namespace, rules = role.Namespace, role.Rules
		case *rbacv1.ClusterRole:
			rules = role.Rules
		default:
			continue
		}
		for _, rule := range rules {
			for _, read := range expected {
				if namespace == read.Namespace && slices.Contains(rule.Resources, read.Resource) && slices.Contains(rule.ResourceNames, read.Name) {
					if !reflect.DeepEqual(rule.Verbs, []string{"get"}) || !reflect.DeepEqual(rule.APIGroups, []string{read.Group}) || len(rule.ResourceNames) != 1 {
						t.Fatal("verifier role widened named GET", rule)
					}
					generated = append(generated, read)
				}
			}
		}
	}
	for _, read := range expected {
		if !slices.Contains(generated, read) {
			t.Fatal("actual verifier lookup absent from generated grants", read)
		}
	}
	after, _ := json.Marshal(cfg.Writers)
	if string(before) != string(after) {
		t.Fatal("controller added to source writers")
	}
	for _, allow := range []bool{true, false} {
		client := fake.NewSimpleClientset()
		var probed []a.VerifierNamedRead
		client.PrependReactor("create", "selfsubjectaccessreviews", func(action kt.Action) (bool, runtime.Object, error) {
			review := action.(kt.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
			attr := review.Spec.ResourceAttributes
			read := a.VerifierNamedRead{Namespace: attr.Namespace, Group: attr.Group, Resource: attr.Resource, Name: attr.Name}
			if slices.Contains(expected, read) {
				if attr.Verb != "get" {
					t.Fatal("verifier mutation probed")
				}
				probed = append(probed, read)
			}
			review.Status.Allowed = true
			if attr.Resource == "replicasets" && attr.Name == material.KubernetesReads.ReplicaSetName {
				review.Status.Allowed = allow
				review.Status.Denied = !allow
			}
			return true, review, nil
		})
		err := CheckDeploymentCaptureKubernetesAccess(context.Background(), client, cfg, material.Workload.ServiceAccountName, &material)
		if (err == nil) != allow {
			t.Fatal("named owner denial ignored", err)
		}
		if allow {
			for _, read := range expected {
				if !slices.Contains(probed, read) {
					t.Fatal("named lookup absent from startup probe", read)
				}
			}
		}
	}
}

func TestDeploymentVerifierAccessMissingOrUnpinnedMaterialsFailsClosed(t *testing.T) {
	cfg, material, input := verifierAccessFixture(t)
	for _, fault := range []string{"missing-input", "wrong-pin", "missing-mapping", "wrong-controller-sa", "wrong-namespace", "bad-owner-kind"} {
		t.Run(fault, func(t *testing.T) {
			m := material
			reads := *m.KubernetesReads
			m.KubernetesReads = &reads
			sa := m.Workload.ServiceAccountName
			switch fault {
			case "missing-input":
				if _, err := CaptureKubernetesGrants(cfg, sa); err == nil {
					t.Fatal("missing independent pin accepted")
				}
				return
			case "wrong-pin":
				bad := input
				bad.SHA256 = strings.Repeat("0", 64)
				if _, err := CaptureKubernetesGrants(cfg, sa, bad); err == nil {
					t.Fatal("wrong independent pin accepted")
				}
				return
			case "missing-mapping":
				m.KubernetesReads = nil
			case "wrong-controller-sa":
				sa = "other-controller"
			case "wrong-namespace":
				m.Workload.Namespace = "other"
				m.KubernetesReads.Namespace = "other"
			case "bad-owner-kind":
				m.Workload.OwnerKind = "Pod"
				m.KubernetesReads.OwnerKind = "Pod"
			}
			client := fake.NewSimpleClientset()
			if err := CheckDeploymentCaptureKubernetesAccess(context.Background(), client, cfg, sa, &m); err == nil || len(client.Actions()) != 0 {
				t.Fatal("invalid mapping reached live readiness API")
			}
		})
	}
}

func TestVerifierOnlyStartupRetainsActualControllerIdentity(t *testing.T) {
	x := newPublicationStartupFixture(t, "publisher@127.0.0.1", "server", "control")
	if err := x.service.bindDeploymentStartupInputs(x.inputs); err != nil {
		t.Fatal(err)
	}
	x.service.Config.PublicationSigners = nil
	x.service.Config.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(t.TempDir(), "verifier.json")}
	if err := x.service.attachPublicationSigners(context.Background(), nil, x.client, x.inputs.ControllerPodName); err != nil {
		t.Fatal("verifier-only startup could not inspect its actual Pod", err)
	}
	if x.service.controllerActor.PodName != x.inputs.ControllerPodName || x.service.controllerActor.PodUID != "controller-pod-uid" || x.service.controllerActor.ServiceAccountName != "controller" || x.service.publicationFactory != nil {
		t.Fatal("verifier-only probe relied on signer feature or material DTO for actual actor", x.service.controllerActor.ServiceAccountName)
	}
	if err := x.service.attachPublicationSigners(context.Background(), nil, x.client, ""); err == nil {
		t.Fatal("verifier-only startup allowed missing real controller Pod name")
	}
}
