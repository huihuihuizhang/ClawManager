package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/url"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

// These are the same installation-authored files installed on the Node
// owners, with their original byte pins. The controller receives no host FD
// or administrator Kubernetes credential.
type FormalLonghornHoldConfig struct {
	Observer  FormalSharedRuntimeObserverConfig
	Materials []ProductionCaptureInput
}

type deploymentLonghornCutOwner struct {
	owner     *PublicJobOwner
	config    FormalLonghornHoldConfig
	native    *q.SharedRuntimeNodeClient
	materials []q.LonghornExt4Materials
}

func (s *DeploymentService) attachLonghornHold(owner *PublicJobOwner) error {
	if s.Config.RuntimeSources == nil || s.Config.RuntimeSources.LonghornHold == nil {
		if s.captureMaterials != nil && s.captureMaterials.Discovery != nil && len(s.captureMaterials.Discovery.LonghornSources) != 0 {
			return d.ErrNotReady
		}
		return nil
	}
	// Recovery loads the original deployment/file pins even when forward
	// source discovery is revoked. Release separately checks Gate.Recovery.
	if owner == nil || owner.longhornCutOwner != nil {
		return d.ErrNotReady
	}
	cfg := *s.Config.RuntimeSources.LonghornHold
	if len(cfg.Materials) == 0 || len(cfg.Materials) > 128 || len(cfg.Observer.Endpoints) == 0 {
		return d.ErrNotReady
	}
	var material []q.LonghornExt4Materials
	for _, input := range cfg.Materials {
		raw, err := pinnedDeploymentFile(input.File, input.SHA256, 1<<20)
		var current q.LonghornExt4Materials
		if err != nil || decodeMetadataCanonical(raw, &current) != nil || current.Version != q.LonghornExt4Protocol {
			return d.ErrNotReady
		}
		material = append(material, current)
	}
	for _, pin := range []ProductionCaptureInput{{cfg.Observer.CAFile, cfg.Observer.CASHA256}, {cfg.Observer.CertificateFile, cfg.Observer.CertificateSHA256}, {cfg.Observer.KeyFile, cfg.Observer.KeySHA256}} {
		raw, err := pinnedDeploymentFile(pin.File, pin.SHA256, 262144)
		clear(raw)
		if err != nil {
			return err
		}
	}
	certificate, err := tls.LoadX509KeyPair(cfg.Observer.CertificateFile, cfg.Observer.KeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return d.ErrNotReady
	}
	// Recovery still needs the independently authorized SQL recovery action.
	// Reusing this native peer identity avoids another certificate lifecycle.
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return err
	}
	for _, input := range material {
		uri, err := url.Parse(input.RecoveryURI)
		if err != nil || uri.Scheme != "spiffe" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != input.RecoveryURI {
			return d.ErrNotReady
		}
	}
	native, err := q.NewSharedRuntimeNodeClient(cfg.Observer.Endpoints, cfg.Observer.CAFile, cfg.Observer.CertificateFile, cfg.Observer.KeyFile)
	if err != nil {
		return err
	}
	owner.longhornCutOwner = &deploymentLonghornCutOwner{owner: owner, config: cfg, native: native, materials: material}
	return nil
}

func (o *deploymentLonghornCutOwner) checkMaterials() error {
	for index, input := range o.config.Materials {
		raw, err := pinnedDeploymentFile(input.File, input.SHA256, 1<<20)
		var current q.LonghornExt4Materials
		if err != nil || decodeMetadataCanonical(raw, &current) != nil {
			return d.ErrNotReady
		}
		before, _ := json.Marshal(o.materials[index])
		after, _ := json.Marshal(current)
		if string(before) != string(after) {
			return d.ErrNotReady
		}
	}
	return nil
}

func (o *deploymentLonghornCutOwner) ContentRunner(ctx context.Context, in d.Input, plan plannedLonghornClone, pin kube.LonghornSnapshotPin) (kube.Runner, error) {
	if o.owner.longhornExecutor == nil {
		return kube.Runner{}, d.ErrNotReady
	}
	return o.owner.longhornExecutor.ContentRunner(ctx, in, plan, pin)
}
