package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"path/filepath"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	k "clawreef/internal/systembackupkms"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Part of the independently pinned external materials, outside the full core
// deployment/profile hash. Worker materials freeze only DeliveryPin before
// Invocation hashing; no task-specific permit is placed in deployment inputs.
type ProviderPermitDeploymentConfig struct {
	Workload       a.ControllerVerifierWorkload     `json:"workload"`
	Grant          a.ProviderPermitIssuerGrantMount `json:"grant"`
	SigningKeyFile string                           `json:"signing_key_file"`
	DeliveryPin    k.PermitDeliveryPin              `json:"delivery_pin"`
}

type deploymentProviderPermitIssuer struct {
	issuer *a.ProviderPermitIssuer
	pin    k.PermitDeliveryPin
}

func (p ProviderPermitDeploymentConfig) validate(cfg DeploymentConfig) error {
	if !k.ValidPermitDeliveryPin(p.DeliveryPin) || p.Grant.SHA256 != p.DeliveryPin.IssuerGrantSHA256 || p.Workload.GrantSHA256 != p.Grant.SHA256 || p.Workload.ControllerOwner != cfg.ControllerOwner || p.Workload.ServiceAccountUID == cfg.Security.ServiceAccountUID || len(p.Grant.Issuer) != ed25519.PublicKeySize || bytes.Equal(p.Grant.Issuer, p.DeliveryPin.Issuer) {
		return c.ErrExecutionAuthority
	}
	for _, path := range []string{p.Grant.File, p.SigningKeyFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return c.ErrExecutionAuthority
		}
	}
	if p.SigningKeyFile == p.Grant.File || p.SigningKeyFile == cfg.IssuerKey || p.SigningKeyFile == cfg.ServerKey {
		return c.ErrExecutionAuthority
	}
	return nil
}

// NewProviderPermitIssuer performs the original business-owner, key and SQL
// composition checks. This additional signed read binds its exact public key
// to the independently frozen worker pin; no permissive signer port exists.
func (s *DeploymentService) attachProviderPermits(o *PublicJobOwner, capabilities *a.SQLProviderCapabilityPreparation) error {
	v := s.formalVerifier
	if v == nil || v.ProviderPermits == nil {
		return nil
	}
	p := v.ProviderPermits
	if !s.ForwardEnabled || o == nil || o.Identity != s.Forward || p.validate(s.Config) != nil {
		return c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(p.Grant.File, p.Grant.SHA256, 65536)
	if err != nil {
		return err
	}
	var signed a.SignedProviderPermitIssuerGrant
	if decodeProviderDeploymentJSON(raw, &signed) != nil || !ed25519.Verify(p.Grant.Issuer, append([]byte(a.ProviderPermitIssuerGrantDomain), signed.Record...), signed.Signature) {
		return c.ErrExecutionAuthority
	}
	var grant a.ProviderPermitIssuerGrant
	if decodeProviderDeploymentJSON(signed.Record, &grant) != nil || !bytes.Equal(grant.SigningPublicKey, p.DeliveryPin.Issuer) {
		return c.ErrExecutionAuthority
	}
	issuer, err := a.NewProviderPermitIssuer(a.ProviderPermitIssuerConfig{Capabilities: capabilities, Binding: v.Binding, InstallationIssuer: v.InstallationIssuer, Authority: o.Gate.Authority, Records: o.Gate.Records, Kubernetes: o.Client, Workload: p.Workload, CaptureGrantSHA256: s.Forward.GrantSHA256(), GrantMount: p.Grant, SigningKeyFile: p.SigningKeyFile})
	if err != nil {
		return err
	}
	pin := p.DeliveryPin
	pin.Issuer = bytes.Clone(pin.Issuer)
	o.providerPermits = &deploymentProviderPermitIssuer{issuer: issuer, pin: pin}
	return nil
}

func decodeProviderDeploymentJSON(raw []byte, out any) error {
	// Reject duplicate keys as well as unknown fields; use the same canonical
	// JSON gate as other externally pinned deployment materials.
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return c.ErrExecutionAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (o *PublicJobOwner) validProviderPermitPin(inv worker.Invocation) bool {
	if o == nil {
		return false
	}
	if inv.FormalCapture == nil || inv.FormalCapture.PermitDelivery == nil {
		return o.providerPermits == nil
	}
	if o.providerPermits == nil || o.providerPermits.issuer == nil {
		return false
	}
	got, want := *inv.FormalCapture.PermitDelivery, o.providerPermits.pin
	return k.ValidPermitDeliveryPin(got) && got.Version == want.Version && got.IssuerGrantSHA256 == want.IssuerGrantSHA256 && bytes.Equal(got.Issuer, want.Issuer)
}

func (o *PublicJobOwner) prepareProviderPermit(ctx context.Context, in d.Input, job d.JobBinding, pod BoundPod, req worker.ControlRequest) (*a.PreparedProviderPermitIssue, error) {
	if req.Invocation.ProviderKey == nil {
		return nil, nil
	}
	if !o.validProviderPermitPin(req.Invocation) {
		return nil, c.ErrExecutionAuthority
	}
	if o.providerPermits == nil || req.Action == "ready" {
		return nil, nil
	}
	return o.providerPermits.issuer.Prepare(ctx, a.ProviderPermitIssueScope{Input: in, Job: job, Invocation: req.Invocation, WorkerPodName: pod.Name, WorkerIdentity: k.JobIdentity{Namespace: pod.Namespace, PodUID: pod.UID, ServiceAccountUID: pod.ServiceAccountUID, JobUID: job.UID, InvocationSHA256: req.InvocationSHA256, ExecutionGrantSHA256: o.Identity.GrantSHA256()}})
}
