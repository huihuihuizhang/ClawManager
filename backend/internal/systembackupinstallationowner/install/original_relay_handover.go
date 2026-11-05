package install

import (
	"context"
	"crypto/ed25519"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"path/filepath"
	"reflect"
	"time"
)

const originalRelayHandoverDomain = "original-readonly-relay-stop.v1\x00"

type originalRelayHandoverIntent struct {
	Source              OriginalRelayHandoverInputs
	ConfigSHA256        string
	ConfigVersion       uint64
	AuthorizedAt, Until time.Time
}
type OriginalRelayHandoverInputs struct {
	Version, OutputDirectory                                 string
	PKIMaterial, PKISignature, ProcessRecord, EnableResponse BootstrapSourceFilePin
	Request                                                  RequestFiles
}
type OriginalRelayHandoverReceipt struct {
	Version, State, PlanSHA256, InstallationID, ConfigSHA256, ServiceUID, Pod, PodUID, ContainerID, ServerCertificateSHA256 string
	ConfigVersion                                                                                                           uint64
	Process                                                                                                                 originalRelayNativeProcess
	Source                                                                                                                  OriginalRelayHandoverInputs
	OriginalListenerAbsent                                                                                                  bool
	RuntimeStarted                                                                                                          bool
	ObservedAt                                                                                                              time.Time
	Result, Signature                                                                                                       BootstrapSourceFilePin
}

func (i *Installer) relayHandoverSource(ctx context.Context, enrollment EnrollmentPin, in OriginalRelayHandoverInputs) (originalRelayPKIManifest, originalRelayProcessRecord, error) {
	var m originalRelayPKIManifest
	var p originalRelayProcessRecord
	raw, e := readBootstrapSourcePin(in.PKIMaterial, 262144)
	if e != nil {
		return m, p, ErrInstall
	}
	sig, e := readBootstrapSourcePin(in.PKISignature, 64)
	if e != nil || !ed25519.Verify(i.public, append([]byte(originalRelayPKIDomain), raw...), sig) || decodeExact(raw, &m) != nil || m.Version != "original-relay-pki-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 || m.EnrollmentConfigMapUID != enrollment.ConfigMapUID {
		return m, p, ErrInstall
	}
	raw, e = readBootstrapSourcePin(in.ProcessRecord, 65536)
	if e != nil || decodeExact(raw, &p) != nil || p.Version != "original-readonly-relay-process.v1" || p.PlanSHA256 != i.planHash || p.PKIMaterialSHA256 != in.PKIMaterial.SHA256 || p.ServiceUID != m.ServiceUID || p.ServerCertificateSHA256 != m.Files["relay-server.pem"].SHA256 || in.ProcessRecord.File != filepath.Join(filepath.Dir(in.PKIMaterial.File), "readonly-relay.process.json") {
		return m, p, ErrInstall
	}
	actor, e := i.originalPublicationActor(ctx, m.Source.ControllerDeployment, p.Pod)
	if e != nil || actor.PodUID != p.PodUID || actor.ServiceAccountUID != m.Controller.ServiceAccountUID {
		return m, p, ErrInstall
	}
	dep, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, m.Source.ControllerDeployment, metav1.GetOptions{})
	if e != nil || string(dep.UID) != m.DeploymentUID {
		return m, p, ErrInstall
	}
	svc, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).Get(ctx, m.Source.Service, metav1.GetOptions{})
	if e != nil || string(svc.UID) != m.ServiceUID {
		return m, p, ErrInstall
	}
	pod, e := i.kube.CoreV1().Pods(i.plan.Target.Namespace).Get(ctx, p.Pod, metav1.GetOptions{})
	if e != nil {
		return m, p, ErrInstall
	}
	found := false
	for _, c := range pod.Status.ContainerStatuses {
		found = found || c.Name == "installation-owner" && c.ContainerID == p.ContainerID && c.State.Running != nil
	}
	if !found {
		return m, p, ErrInstall
	}
	return m, p, nil
}

// Stop is authorized by the real committed FIRST normal enabled-only operation,
// not a JSON flag. Linux pidfd and independent original process checks prevent
// PID-reuse signaling. No grant, source, config or worker state is changed.
func (i *Installer) StopOriginalReadOnlyRelay(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalRelayHandoverInputs, issuerPrivate []byte) (OriginalRelayHandoverReceipt, error) {
	var zero OriginalRelayHandoverReceipt
	if i == nil || ctx == nil || in.Version != "original-readonly-relay-handover-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	enabled, e := i.PrepareOriginalEnabledPublication(ctx, password, enrollment, in.EnableResponse, in.Request)
	if e != nil {
		return zero, e
	}
	defer enabled.Close()
	m, p, e := i.relayHandoverSource(ctx, enrollment, in)
	if e != nil {
		return zero, e
	}
	var admissions uint64
	if i.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_kek_admissions WHERE installation_id=? AND config_version=2 AND config_sha256=?", i.plan.Target.InstallationID, enabled.configSHA).Scan(&admissions) != nil || admissions != 1 || enabled.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	key, e := enabled.operator.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	intent, e := canonical(originalRelayHandoverIntent{Source: in, ConfigSHA256: enabled.configSHA, ConfigVersion: 2, AuthorizedAt: time.Now().UTC(), Until: enabled.until})
	if e != nil || writeNewFiles(in.OutputDirectory, map[string][]byte{"relay-handover.intent.json": intent, "relay-handover.intent.signature": ed25519.Sign(key, append([]byte(originalRelayHandoverDomain+"intent\x00"), intent...))}) != nil {
		return zero, ErrCommitUnknown
	}
	// Real recovery/normal mutation authorization remains bounded; no SQL lock is
	// held while observing, signaling or waiting on this original native process.
	if enabled.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	stopCtx, stopCancel := context.WithDeadline(ctx, enabled.until)
	defer stopCancel()
	absent, e := originalRelaySignalExactProcess(stopCtx, p.Process, p.ServeInputsSHA256, p.PlanSHA256, p.PKIMaterialSHA256)
	if e != nil || !absent {
		return zero, ErrCommitUnknown
	}
	receipt := OriginalRelayHandoverReceipt{Version: "original-readonly-relay-handover-result.v1", State: "original_readonly_listener_absent_normal_runtime_not_started", PlanSHA256: i.planHash, InstallationID: i.plan.Target.InstallationID, ConfigVersion: 2, ConfigSHA256: enabled.configSHA, ServiceUID: m.ServiceUID, Pod: p.Pod, PodUID: p.PodUID, ContainerID: p.ContainerID, ServerCertificateSHA256: p.ServerCertificateSHA256, Process: p.Process, Source: in, OriginalListenerAbsent: true, RuntimeStarted: false, ObservedAt: time.Now().UTC()}
	return i.saveOriginalRelayHandover(in.OutputDirectory, receipt, key)
}
func (i *Installer) saveOriginalRelayHandover(directory string, r OriginalRelayHandoverReceipt, key ed25519.PrivateKey) (OriginalRelayHandoverReceipt, error) {
	raw, e := canonical(r)
	if e != nil {
		return r, ErrInstall
	}
	sig := ed25519.Sign(key, append([]byte(originalRelayHandoverDomain), raw...))
	if writeNewFiles(directory, map[string][]byte{"relay-handover.result.json": raw, "relay-handover.result.signature": sig}) != nil {
		return r, ErrCommitUnknown
	}
	r.Result = BootstrapSourceFilePin{File: filepath.Join(directory, "relay-handover.result.json"), SHA256: hash(raw)}
	r.Signature = BootstrapSourceFilePin{File: filepath.Join(directory, "relay-handover.result.signature"), SHA256: hash(sig)}
	return r, nil
}

// Known signed results remain historical queries; no current signer/enable
// preparation and no repeated signal. Unknown query uses only the original
// process namespace/boot/start identity and fresh original admin enrollment.
func (i *Installer) QueryOriginalReadOnlyRelayHandover(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalRelayHandoverInputs, issuerPrivate []byte) (OriginalRelayHandoverReceipt, error) {
	var zero OriginalRelayHandoverReceipt
	if i == nil || ctx == nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil || privateDirectory(in.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	intent, e := ReadPrivateFile(filepath.Join(in.OutputDirectory, "relay-handover.intent.json"), 262144)
	var original originalRelayHandoverIntent
	if e != nil || decodeExact(intent, &original) != nil || !reflect.DeepEqual(original.Source, in) || original.ConfigVersion != 2 || !digestPattern.MatchString(original.ConfigSHA256) {
		return zero, ErrInstall
	}
	intentSig, e := ReadPrivateFile(filepath.Join(in.OutputDirectory, "relay-handover.intent.signature"), 64)
	if e != nil || !ed25519.Verify(i.public, append([]byte(originalRelayHandoverDomain+"intent\x00"), intent...), intentSig) {
		return zero, ErrInstall
	}
	file := filepath.Join(in.OutputDirectory, "relay-handover.result.json")
	raw, e := ReadPrivateFile(file, 262144)
	if e == nil {
		sig, e := ReadPrivateFile(filepath.Join(in.OutputDirectory, "relay-handover.result.signature"), 64)
		var r OriginalRelayHandoverReceipt
		if e != nil || !ed25519.Verify(i.public, append([]byte(originalRelayHandoverDomain), raw...), sig) || decodeExact(raw, &r) != nil || !reflect.DeepEqual(r.Source, in) || r.PlanSHA256 != i.planHash || !r.OriginalListenerAbsent || r.RuntimeStarted {
			return zero, ErrInstall
		}
		r.Result = BootstrapSourceFilePin{File: file, SHA256: hash(raw)}
		r.Signature = BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "relay-handover.result.signature"), SHA256: hash(sig)}
		return r, nil
	}
	m, p, e := i.relayHandoverSource(ctx, enrollment, in)
	if e != nil {
		return zero, e
	}
	absent, e := originalRelayProcessAbsent(p.Process)
	if e != nil || !absent {
		return zero, ErrCommitUnknown
	}
	// Resolve only the original signed authorization intent and native absence.
	// No current signer/enable preparation is required by this historical query.
	key, e := op.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrCommitUnknown
	}
	defer clear(key)
	r := OriginalRelayHandoverReceipt{Version: "original-readonly-relay-handover-result.v1", State: "original_readonly_listener_absent_normal_runtime_not_started", PlanSHA256: i.planHash, InstallationID: i.plan.Target.InstallationID, ConfigVersion: 2, ConfigSHA256: original.ConfigSHA256, ServiceUID: m.ServiceUID, Pod: p.Pod, PodUID: p.PodUID, ContainerID: p.ContainerID, ServerCertificateSHA256: p.ServerCertificateSHA256, Process: p.Process, Source: in, OriginalListenerAbsent: true, ObservedAt: time.Now().UTC()}
	return i.saveOriginalRelayHandover(in.OutputDirectory, r, key)
}
