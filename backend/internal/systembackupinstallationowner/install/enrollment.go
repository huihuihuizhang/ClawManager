package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EnrollmentPin must be independently retained/deployed from the successful
// trusted-environment enroll result. It is never read from an imported grant.
type EnrollmentPin struct{ ConfigMapUID, DocumentSHA256 string }
type EnrollmentReceipt struct {
	SchemaVersion, InstallationID, EnrollmentID, IssuerID string
	EnrollmentRevision                                    uint64
	Pin                                                   EnrollmentPin
	IssuerPublicKeySHA256                                 string
	Replayed                                              bool
}
type enrollmentDocument struct {
	SchemaVersion string
	Plan          Plan
	AdminUserID   int64
	Issuer        ed25519.PublicKey
}

func (s *authenticatedOperator) enrollmentBytes() ([]byte, error) {
	return canonical(enrollmentDocument{EnrollmentVersion, s.installer.plan, s.userID, s.installer.public})
}
func exactEnrollment(cm *corev1.ConfigMap, s *authenticatedOperator, expected []byte, pin *EnrollmentPin) bool {
	if cm == nil || cm.Name != s.installer.plan.EnrollmentName || cm.Namespace != s.installer.plan.Target.Namespace || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || !bytes.Equal([]byte(cm.Data["enrollment.json"]), expected) {
		return false
	}
	return pin == nil || string(cm.UID) == pin.ConfigMapUID && hash(expected) == pin.DocumentSHA256
}
func (s *authenticatedOperator) readEnrollment(ctx context.Context, pin EnrollmentPin) error {
	if !s.live(ctx) || pin.ConfigMapUID == "" || !digestPattern.MatchString(pin.DocumentSHA256) || s.kubernetes(ctx, "get") != nil {
		return ErrInstall
	}
	raw, e := s.enrollmentBytes()
	if e != nil {
		return e
	}
	cm, e := s.installer.kube.CoreV1().ConfigMaps(s.installer.plan.Target.Namespace).Get(ctx, s.installer.plan.EnrollmentName, metav1.GetOptions{})
	if e != nil || !exactEnrollment(cm, s, raw, &pin) {
		return ErrInstall
	}
	return nil
}

// Enroll performs a real authenticated, create-only Kubernetes registration.
// No candidate signature creates trust; the user explicitly selects the key
// fingerprint and target plan, and independently deploys the returned pin.
// It writes no SQL owner/config/operation rows and never overwrites enrollment.
func (i *Installer) Enroll(ctx context.Context, password []byte) (EnrollmentReceipt, error) {
	var zero EnrollmentReceipt
	uncertain := false
	failure := func(e error) (EnrollmentReceipt, error) {
		if uncertain {
			return zero, ErrCommitUnknown
		}
		return zero, e
	}
	s, e := i.authenticate(ctx, password)
	if e != nil {
		return zero, e
	}
	if s.kubernetes(ctx, "create") != nil {
		return zero, ErrInstall
	}
	raw, e := s.enrollmentBytes()
	if e != nil {
		return zero, e
	}
	cm, e := i.kube.CoreV1().ConfigMaps(i.plan.Target.Namespace).Get(ctx, i.plan.EnrollmentName, metav1.GetOptions{})
	replayed := e == nil
	if apierrors.IsNotFound(e) {
		immutable := true
		var nonce [16]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			return zero, ErrInstall
		}
		token := hex.EncodeToString(nonce[:])
		cm, e = i.kube.CoreV1().ConfigMaps(i.plan.Target.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: i.plan.EnrollmentName, Namespace: i.plan.Target.Namespace, Annotations: map[string]string{enrollmentAttemptAnnotation: token}}, Immutable: &immutable, Data: map[string]string{"enrollment.json": string(raw)}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			replayed = true
			cm, e = i.kube.CoreV1().ConfigMaps(i.plan.Target.Namespace).Get(ctx, i.plan.EnrollmentName, metav1.GetOptions{})
		} else if e != nil {
			if definiteEnrollmentRejection(e) {
				return zero, ErrInstall
			}
			knownUID := ""
			if cm != nil {
				knownUID = string(cm.UID)
			}
			uncertain = true
			// Never repeat the POST. The attempt annotation distinguishes this
			// original write from a foreign same-name/same-data object.
			cm, e = i.kube.CoreV1().ConfigMaps(i.plan.Target.Namespace).Get(ctx, i.plan.EnrollmentName, metav1.GetOptions{})
			if e != nil || !exactEnrollment(cm, s, raw, nil) || cm.Annotations[enrollmentAttemptAnnotation] != token || knownUID != "" && string(cm.UID) != knownUID {
				return zero, ErrCommitUnknown
			}
		} else if cm == nil || cm.Annotations[enrollmentAttemptAnnotation] != token {
			return zero, ErrInstall
		}
	}
	if e != nil || !exactEnrollment(cm, s, raw, nil) {
		return failure(ErrInstall)
	}
	pin := EnrollmentPin{string(cm.UID), hash(raw)}
	if s.kubernetes(ctx, "create") != nil || s.readEnrollment(ctx, pin) != nil {
		return failure(ErrInstall)
	}
	// API I/O is finished. Current admin/credential and independent SQL clock
	// are checked under the original local transaction before exposing a pin.
	tx, e := i.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return failure(ErrInstall)
	}
	defer tx.Rollback()
	if _, e = s.lockAdmin(ctx, tx); e != nil {
		return failure(e)
	}
	if tx.Commit() != nil {
		return zero, ErrCommitUnknown
	}
	if !s.live(ctx) {
		return failure(ErrInstall)
	}
	return EnrollmentReceipt{EnrollmentReceiptVersion, i.plan.Target.InstallationID, i.plan.EnrollmentID, i.plan.IssuerID, i.plan.EnrollmentRevision, pin, i.plan.IssuerPublicKeySHA256, replayed}, nil
}
