package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	authn "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type OriginalArchiveEvidenceRecovery struct {
	Intent, BeforeMetadata BootstrapSourceFilePin
	Previous               *OriginalArchiveEvidencePrevious
}

type OriginalArchiveEvidencePrevious struct {
	Material, Signature BootstrapSourceFilePin
}

type originalArchiveEvidenceIntent struct {
	Version, Plan, Enrollment string
	Source                    OriginalArchiveEvidenceMaterialOptions
	Role                      a.VaultPermissionRole
}

func recoverOriginalArchiveIntent(recovery OriginalArchiveEvidenceRecovery, expected originalArchiveEvidenceIntent, current map[string]string) ([]byte, []byte, error) {
	dir := filepath.Dir(recovery.Intent.File)
	if privateDirectory(dir) != nil ||
		recovery.Intent.File != filepath.Join(dir, "archive-evidence.intent.json") ||
		recovery.BeforeMetadata.File != filepath.Join(dir, "archive-provider-metadata.before.json") {
		return nil, nil, ErrInstall
	}
	if recovery.Previous == nil && expected.Source.OutputDirectory != dir+"-recovery" {
		return nil, nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(recovery.Intent, 262144)
	var prior originalArchiveEvidenceIntent
	if err != nil || decodeExact(raw, &prior) != nil || prior.Source.OutputDirectory != dir {
		return nil, nil, ErrInstall
	}
	prior.Source.OutputDirectory = expected.Source.OutputDirectory
	if !reflect.DeepEqual(prior, expected) {
		return nil, nil, ErrInstall
	}
	sent, err := ReadPrivateFile(filepath.Join(dir, "archive-native.sent.json"), 262144)
	entries, listErr := os.ReadDir(dir)
	if err != nil || listErr != nil || len(entries) != 3 || !bytes.Equal(raw, sent) {
		return nil, nil, ErrInstall
	}
	beforeRaw, err := readBootstrapSourcePin(recovery.BeforeMetadata, 262144)
	var before map[string]string
	if err != nil || decodeExact(beforeRaw, &before) != nil || len(before) == 0 {
		return nil, nil, ErrInstall
	}
	rolePath := "/v1/auth/" + prior.Role.AuthMount + "/role/" + prior.Role.Role
	policyPath := "/v1/sys/policies/acl/" + prior.Role.Policy
	if before[rolePath] != "" || before[policyPath] != "" || current[rolePath] == "" ||
		current[policyPath] == "" || len(current) != len(before)+2 {
		return nil, nil, ErrInstall
	}
	for path, digest := range before {
		if digest == "" || current[path] != digest {
			return nil, nil, ErrInstall
		}
	}
	return raw, beforeRaw, nil
}

func (i *Installer) checkArchiveRenewal(recovery OriginalArchiveEvidenceRecovery, expected originalArchiveEvidenceIntent, originalBaseline, currentMetadata []byte) error {
	previous := recovery.Previous
	if previous == nil {
		return nil
	}
	dir := filepath.Dir(previous.Material.File)
	base := filepath.Dir(recovery.Intent.File) + "-recovery"
	suffix, anchored := strings.CutPrefix(dir, base)
	if !anchored || strings.ReplaceAll(suffix, "-renewal", "") != "" || privateDirectory(dir) != nil ||
		expected.Source.OutputDirectory != dir+"-renewal" ||
		previous.Material.File != filepath.Join(dir, "archive-evidence.material.json") ||
		previous.Signature.File != filepath.Join(dir, "archive-evidence.material.signature") {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(previous.Material, 262144)
	sig, sigErr := readBootstrapSourcePin(previous.Signature, ed25519.SignatureSize)
	var m originalArchiveEvidenceMaterial
	if e != nil || sigErr != nil || !ed25519.Verify(i.public, append([]byte(originalArchiveMaterialDomain), raw...), sig) ||
		decodeExact(raw, &m) != nil || m.Version != "original-archive-evidence-material.v1" ||
		m.PlanSHA256 != expected.Plan || m.EnrollmentSHA256 != expected.Enrollment || m.Source.OutputDirectory != dir ||
		!m.ObservedAt.Before(m.Until) || time.Now().Before(m.Until) ||
		m.BeforeMetadataSHA256 != hash(originalBaseline) || m.AfterMetadataSHA256 != hash(currentMetadata) ||
		!reflect.DeepEqual(m.Vault.Unwrap, expected.Role) {
		return ErrInstall
	}
	m.Source.OutputDirectory = expected.Source.OutputDirectory
	if m.Source != expected.Source {
		return ErrInstall
	}
	return nil
}

// A retained signature identifies the original material for recovery. Live
// authorization is established separately and the old JWT is never reused here.
func (i *Installer) readArchiveC1Source(enrollment EnrollmentPin, o OriginalArchiveEvidenceMaterialOptions) (OriginalC1EvidenceMaterial, error) {
	var m OriginalC1EvidenceMaterial
	raw, err := readBootstrapSourcePin(o.C1Material, 262144)
	sig, sigErr := readBootstrapSourcePin(o.C1Signature, ed25519.SignatureSize)
	if err != nil || sigErr != nil || !ed25519.Verify(i.public, append([]byte(originalC1EvidenceMaterialDomain), raw...), sig) ||
		decodeExact(raw, &m) != nil || m.Version != "original-c1-evidence-material.v1" ||
		m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 ||
		o.C1Material.File != filepath.Join(m.Source.OutputDirectory, "c1-evidence.material.json") ||
		o.C1Signature.File != filepath.Join(m.Source.OutputDirectory, "c1-evidence.material.signature") ||
		!m.ObservedAt.Before(m.Until) || m.Until.After(m.Source.Until) {
		return OriginalC1EvidenceMaterial{}, ErrInstall
	}
	return m, nil
}

func (i *Installer) refreshArchiveWrapJWT(ctx context.Context, directory string, m *OriginalC1EvidenceMaterial, until *time.Time) error {
	actor := m.Binding
	seconds := int64(600)
	token, err := i.kube.CoreV1().ServiceAccounts(actor.Namespace).CreateToken(ctx, actor.ServiceAccountName, &authn.TokenRequest{Spec: authn.TokenRequestSpec{
		Audiences: []string{m.Transit.Audience}, ExpirationSeconds: &seconds,
		BoundObjectRef: &authn.BoundObjectReference{Kind: "Pod", APIVersion: "v1", Name: actor.PodName, UID: types.UID(actor.PodUID)},
	}}, metav1.CreateOptions{})
	if err != nil {
		return ErrInstall
	}
	*until = minTime(*until, token.Status.ExpirationTimestamp.Time.Add(-6*time.Second))
	jwt, err := originalPublicationToken([]byte(token.Status.Token))
	defer clear(jwt)
	const name = "c1-evidence-wrap.jwt"
	if err != nil || !time.Now().Before(*until) || writeNewFiles(directory, map[string][]byte{name: jwt}) != nil {
		return ErrInstall
	}
	m.RuntimeJWT = BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(jwt)}
	m.Transit.TokenFile = m.RuntimeJWT.File
	return nil
}
