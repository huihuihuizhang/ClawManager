package install

import (
	"context"
	"reflect"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ExistingUID selects a real existing account. Empty means create-only; an
// AlreadyExists response never silently adopts somebody else's account.
type OriginalObserverServiceAccountDefinition struct {
	Version, Name, ExistingUID string
}
type OriginalObserverServiceAccountReceipt struct {
	Version, PlanSHA256, DefinitionSHA256, Namespace, NamespaceUID, Name, UID string
	Created                                                                   bool
	AuthorityHead                                                             HeadCAS
}

func (i *Installer) PrepareOriginalObserverServiceAccount(ctx context.Context, password []byte, pin EnrollmentPin, file, digest string) (OriginalObserverServiceAccountReceipt, error) {
	var zero OriginalObserverServiceAccountReceipt
	if i == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
	var selected OriginalObserverServiceAccountDefinition
	if e != nil || decodeExact(raw, &selected) != nil || selected.Version != "original-observer-service-account.v1" || len(validation.IsDNS1123Subdomain(selected.Name)) != 0 || selected.ExistingUID != "" && !namePattern.MatchString(selected.ExistingUID) {
		return zero, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil {
		return zero, ErrInstall
	}
	before, _, e := s.observerPKIOwner(ctx, pin)
	if e != nil {
		return zero, e
	}
	verb := "get"
	if selected.ExistingUID == "" {
		verb = "create"
	}
	attributes := &authorizationv1.ResourceAttributes{Namespace: i.plan.Target.Namespace, Verb: verb, Resource: "serviceaccounts"}
	if verb == "get" {
		attributes.Name = selected.Name
	}
	access, e := i.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: attributes}}, metav1.CreateOptions{})
	if e != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return zero, ErrInstall
	}
	currentBeforeWrite, _, e := s.observerPKIOwner(ctx, pin)
	if e != nil || currentBeforeWrite.cas != before.cas {
		return zero, ErrInstall
	}
	var account *corev1.ServiceAccount
	created := selected.ExistingUID == ""
	if created {
		// This creates an identity, not privileges. No token is automatically
		// mounted and no Role/ClusterRole/Binding is created by this action.
		mount := false
		account, e = i.kube.CoreV1().ServiceAccounts(i.plan.Target.Namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: selected.Name, Namespace: i.plan.Target.Namespace, Annotations: map[string]string{"backup.clawreef.io/original-plan-sha256": i.planHash}}, AutomountServiceAccountToken: &mount}, metav1.CreateOptions{})
	} else {
		account, e = i.kube.CoreV1().ServiceAccounts(i.plan.Target.Namespace).Get(ctx, selected.Name, metav1.GetOptions{})
	}
	if e != nil || account == nil || account.UID == "" || account.Name != selected.Name || account.Namespace != i.plan.Target.Namespace || account.DeletionTimestamp != nil || selected.ExistingUID != "" && string(account.UID) != selected.ExistingUID {
		return zero, ErrInstall
	}
	actual, e := i.kube.CoreV1().ServiceAccounts(i.plan.Target.Namespace).Get(ctx, selected.Name, metav1.GetOptions{})
	if e != nil || actual.UID != account.UID || actual.DeletionTimestamp != nil || created && (!reflect.DeepEqual(actual.AutomountServiceAccountToken, account.AutomountServiceAccountToken) || actual.Annotations["backup.clawreef.io/original-plan-sha256"] != i.planHash) {
		return zero, ErrOriginalObserverPKIUnconfirmed
	}
	current, _, e := s.observerPKIOwner(ctx, pin)
	last, e2 := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
	if e != nil || e2 != nil || current.cas != before.cas || hash(last) != hash(raw) {
		return zero, ErrOriginalObserverPKIUnconfirmed
	}
	return OriginalObserverServiceAccountReceipt{Version: "original-observer-service-account-receipt.v1", PlanSHA256: i.planHash, DefinitionSHA256: digest, Namespace: i.plan.Target.Namespace, NamespaceUID: i.plan.Target.NamespaceUID, Name: actual.Name, UID: string(actual.UID), Created: created, AuthorityHead: current.cas}, nil
}
