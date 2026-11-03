package install

import (
	"bytes"
	"context"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	kek "clawreef/internal/systembackupkekadapter"
	probe "clawreef/internal/systembackupreferenceprobe"
	"k8s.io/client-go/kubernetes"
)

type sixReferenceNative struct {
	identity       string
	started, until time.Time
}

func recheckSixReferenceFiles(d SixReferenceDefinition) error {
	if validateSixReference(d) != nil {
		return ErrInstall
	}
	for _, pin := range []BootstrapSourceFilePin{d.Deployment, d.VaultCA} {
		raw, e := readBootstrapSourcePin(pin, 262144)
		if e != nil {
			return ErrInstall
		}
		if pin == d.VaultCA && !bytes.Equal(raw, d.Vault.Transit.CAPEM) {
			clear(raw)
			return ErrInstall
		}
		clear(raw)
	}
	if probe.RecheckS3Files(d.S3) != nil || kek.RecheckEvidenceVaultFiles(d.Vault) != nil {
		return ErrInstall
	}
	return nil
}

// Concrete native reads, never callbacks, caller booleans or a future task.
// The original interval begins before all provider/Kubernetes I/O.
func observeSixReference(ctx context.Context, kube kubernetes.Interface, target owner.Target, d SixReferenceDefinition) (sixReferenceNative, error) {
	var zero sixReferenceNative
	if ctx == nil || ctx.Err() != nil || kube == nil || validateSixReference(d) != nil || d.S3.Namespace != target.Namespace || d.S3.NamespaceUID != target.NamespaceUID {
		return zero, ErrInstall
	}
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(15 * time.Second)
	if d.Until.Before(until) {
		until = d.Until
	}
	if cut, ok := ctx.Deadline(); ok && cut.Before(until) {
		until = cut
	}
	if started.Before(d.NotBefore) || !started.Before(until) {
		return zero, ErrInstall
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if recheckSixReferenceFiles(d) != nil {
		return zero, ErrInstall
	}
	s3, e := probe.ObserveS3(ctx, kube, d.S3)
	if e != nil {
		return zero, ErrInstall
	}
	vault, e := kek.ObserveEvidenceVault(ctx, d.Vault)
	if e != nil {
		return zero, ErrInstall
	}
	if s3.ValidUntil().Before(until) {
		until = s3.ValidUntil()
	}
	if vault.ValidUntil().Before(until) {
		until = vault.ValidUntil()
	}
	encoded, e := canonical([]string{s3.IdentitySHA256(), vault.IdentitySHA256()})
	if e != nil || ctx.Err() != nil || !time.Now().Before(until) || recheckSixReferenceFiles(d) != nil {
		return zero, ErrInstall
	}
	return sixReferenceNative{identity: hash(encoded), started: started, until: until}, nil
}
