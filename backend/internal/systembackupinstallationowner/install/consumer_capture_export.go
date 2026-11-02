package install

import (
	"context"
	"path/filepath"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExportBootstrapCaptureConsumer is a concrete authenticated producer of the
// new consumer input files, not an arbitrary caller-supplied trust-pin writer.
// It exports only the exact current enrolled/committed original source. The
// user independently deploys/selects these files; export is not app admission.
func (i *Installer) ExportBootstrapCaptureConsumer(ctx context.Context, password []byte, enrollment EnrollmentPin, raw []byte, rawSHA string, requestFiles RequestFiles, consumerKubeconfig, consumerKubeSHA, directory string) (AuthorityReceipt, error) {
	var zero AuthorityReceipt
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	bundle, record, _, e := s.decodeBundle(raw, rawSHA, enrollment)
	if e != nil || bundle.SchemaVersion != AuthorityBundleVersion {
		return zero, ErrInstall
	}
	current, now, e := snapshot(ctx, s)
	if e != nil || !exactCommitted(current, bundle) || now.Before(record.NotBefore) || !now.Before(record.Until) || now.Before(current.head.NotBefore) || !now.Before(current.head.Until) {
		return zero, ErrInstall
	}
	request, e := readConsumerCaptureRequest(i, requestFiles)
	if e != nil {
		return zero, e
	}
	defer request.observer.Close()
	requestPins, e := canonical(requestFiles)
	if e != nil || hash(requestPins) != bundle.RequestFilesSHA256 || owner.VerifyInstallationRequest(bundle.Record, bundle.RecordSignature, bundle.Pin, request.grant, request.config) != nil || !requestWindow(record, request, now) {
		return zero, ErrInstall
	}
	kube, e := openCaptureConsumerKubernetes(i.plan, consumerKubeconfig, consumerKubeSHA)
	if e != nil {
		return zero, e
	}
	expectedEnrollment, e := s.enrollmentBytes()
	if e != nil {
		return zero, e
	}
	cm, e := kube.CoreV1().ConfigMaps(i.plan.Target.Namespace).Get(ctx, i.plan.EnrollmentName, metav1.GetOptions{})
	if e != nil || !exactEnrollment(cm, s, expectedEnrollment, &enrollment) {
		return zero, ErrInstall
	}
	planRaw, e := canonical(i.plan)
	if e != nil {
		return zero, e
	}
	pinRaw, e := canonical(bundle.Pin)
	if e != nil {
		return zero, e
	}
	enrollmentRaw, e := canonical(enrollment)
	if e != nil {
		return zero, e
	}
	path := func(name string) string { return filepath.Join(directory, name) }
	document := CaptureConsumerFiles{SchemaVersion: CaptureConsumerVersion, PlanFile: path("owner.plan.json"), PlanSHA256: hash(planRaw), IssuerPublicFile: path("issuer.public"), IssuerPublicSHA256: hash(i.public), TrustPinFile: path("owner.pin.json"), TrustPinSHA256: hash(pinRaw), EnrollmentPinFile: path("owner.enrollment-pin.json"), EnrollmentPinSHA256: hash(enrollmentRaw), KubeconfigFile: consumerKubeconfig, KubeconfigSHA256: consumerKubeSHA, RecordFile: path("owner.record"), SignatureFile: path("owner.signature"), Request: requestFiles}
	docRaw, e := canonical(document)
	if e != nil {
		return zero, e
	}
	if writeNewFiles(directory, map[string][]byte{"owner.plan.json": planRaw, "issuer.public": i.public, "owner.pin.json": pinRaw, "owner.enrollment-pin.json": enrollmentRaw, "owner.record": bundle.Record, "owner.signature": bundle.RecordSignature, "capture-consumer.json": docRaw, "capture-consumer.sha256": []byte(hash(docRaw))}) != nil {
		return zero, ErrInstall
	}
	// Recheck only exact original local bytes then the original SQL source.
	// Failure never repairs/overwrites any output or signs a replacement.
	state := &consumerCaptureState{ctx: ctx, files: []consumerPinnedFile{{consumerKubeconfig, consumerKubeSHA, 262144}}, request: request}
	if state.current(ctx) != nil || !time.Now().Before(s.until) {
		return zero, ErrCommitUnknown
	}
	return s.confirmCommitted(ctx, bundle, false)
}
