package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"time"

	probe "clawreef/internal/systembackupreferenceprobe"
	sec "clawreef/internal/systembackupsecurity"
)

type OriginalC1S3RenewalInputs struct {
	Version, OutputDirectory    string
	Material, Signature, Config BootstrapSourceFilePin
	Until                       time.Time
}

// RenewOriginalC1S3Material retains the native accounts and policies of a
// completed, signed issue. The final Config fixes their reference identities.
// This operation only issues new local material after native reobservation.
func (i *Installer) RenewOriginalC1S3Material(ctx context.Context, password []byte, enrollment EnrollmentPin, in OriginalC1S3RenewalInputs, issuerPrivate []byte) (OriginalC1S3Receipt, error) {
	receipt := OriginalC1S3Receipt{Version: "original-c1-s3-result.v1", State: "renewal_unverified_no_native_writes"}
	if i == nil || ctx == nil || in.Version != "original-c1-s3-renewal-inputs.v1" || privateDirectory(in.OutputDirectory) != nil {
		return receipt, ErrInstall
	}
	entries, e := os.ReadDir(in.OutputDirectory)
	if e != nil || len(entries) != 0 {
		return receipt, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil {
		return receipt, ErrInstall
	}
	state, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || state.cas != (HeadCAS{}) || !now.Before(in.Until) || in.Until.Sub(now) > 10*time.Minute {
		return receipt, ErrInstall
	}
	issuer, e := op.privateKey(issuerPrivate)
	if e != nil {
		return receipt, ErrInstall
	}
	defer clear(issuer)
	until := minTime(op.until, in.Until)
	raw, e := readBootstrapSourcePin(in.Material, 262144)
	if e != nil {
		return receipt, ErrInstall
	}
	sig, e := readBootstrapSourcePin(in.Signature, ed25519.SignatureSize)
	var m originalC1S3Material
	if e != nil || !ed25519.Verify(i.public, append([]byte(originalC1S3Domain), raw...), sig) || decodeExact(raw, &m) != nil ||
		m.Version != "original-c1-s3-material.v1" || m.PlanSHA256 != i.planHash || m.EnrollmentSHA256 != enrollment.DocumentSHA256 ||
		in.Material.File != filepath.Join(m.Source.OutputDirectory, "c1-s3.material.json") || in.Signature.File != filepath.Join(m.Source.OutputDirectory, "c1-s3.material.signature") ||
		m.ObservedAt.IsZero() || !m.ObservedAt.Before(m.Until) || m.Until.After(m.Source.Until) || now.Before(m.Until) {
		return receipt, ErrInstall
	}
	profileRaw, e := readBootstrapSourcePin(m.Profile, 262144)
	var c probe.S3Profile
	if e != nil || decodeExact(profileRaw, &c) != nil || probe.ValidateS3Profile(c) != nil || c.Installation != i.plan.Target.InstallationID ||
		c.Namespace != i.plan.Target.Namespace || c.NamespaceUID != i.plan.Target.NamespaceUID ||
		c.UploadMaterials != (probe.FilePin{File: m.UploadMaterials.File, SHA256: m.UploadMaterials.SHA256}) {
		return receipt, ErrInstall
	}
	receipt.State = "renewal_config_reference_check"
	configRaw, e := readBootstrapSourcePin(in.Config, 262144)
	if e != nil || !originalC1S3MatchesConfig(configRaw, c) {
		return receipt, ErrInstall
	}
	receipt.State = "renewal_channel_and_credential_check"
	previousChannel, e := readBootstrapSourcePin(m.ChannelMaterial, 262144)
	exactChannel, channelErr := originalC1S3ChannelSelection(c, m.ChannelPrincipal, m.ChannelCredentials, m.Until)
	if e != nil || channelErr != nil || !bytes.Equal(previousChannel, exactChannel) {
		return receipt, ErrInstall
	}
	uploadRaw, e := readBootstrapSourcePin(m.UploadMaterials, 262144)
	var upload originalC1S3Upload
	if e != nil || decodeExact(uploadRaw, &upload) != nil {
		return receipt, ErrInstall
	}
	files := make(map[string][]byte, len(c.Principals)+6)
	defer func() {
		for _, contents := range files {
			clear(contents)
		}
	}()
	pin := func(name string, contents []byte) BootstrapSourceFilePin {
		files[name] = contents
		return BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, name), SHA256: hash(contents)}
	}
	principals := []*probe.Principal{&c.Observer, &m.ChannelPrincipal}
	for n := range c.Principals {
		principals = append(principals, &c.Principals[n])
	}
	uploadMatched := false
	for _, p := range principals {
		old := p.Credential
		credential, e := renewOriginalC1S3Credential(*p, m.Until, now, until)
		if e != nil {
			return receipt, e
		}
		name := p.Purpose + ".credential.json"
		if _, exists := files[name]; exists {
			clear(credential)
			return receipt, ErrInstall
		}
		next := pin(name, credential)
		p.Credential = probe.FilePin{File: next.File, SHA256: next.SHA256}
		if old.File == upload.WriteFile && old.SHA256 == upload.WriteSHA {
			if p.Purpose != "artifact_upload_issuer" || uploadMatched {
				return receipt, ErrInstall
			}
			upload.WriteFile, upload.WriteSHA, uploadMatched = next.File, next.SHA256, true
		}
	}
	if !uploadMatched {
		return receipt, ErrInstall
	}
	transport, e := probe.OriginalS3ChannelCredentials(files[m.ChannelPrincipal.Purpose+".credential.json"])
	if e != nil {
		return receipt, ErrInstall
	}
	m.ChannelCredentials = pin("c1-channel.transport.json", transport)
	uploadRaw, e = canonical(upload)
	if e != nil {
		return receipt, ErrInstall
	}
	m.UploadMaterials = pin("upload.materials.json", uploadRaw)
	c.UploadMaterials = probe.FilePin{File: m.UploadMaterials.File, SHA256: m.UploadMaterials.SHA256}
	profileRaw, e = canonical(c)
	if e != nil || probe.ValidateS3Profile(c) != nil || !originalC1S3MatchesConfig(configRaw, c) {
		return receipt, ErrInstall
	}
	m.Profile = pin("c1-s3.profile.json", profileRaw)
	receipt.State = "renewal_credential_material_prepared"
	if writeNewFiles(in.OutputDirectory, files) != nil {
		return receipt, ErrCommitUnknown
	}
	receipt.State = "renewal_native_readback"
	observation, e := probe.ObserveS3(ctx, i.kube, c)
	if e != nil || observation.IdentitySHA256() == "" || probe.ObserveOriginalS3Channel(ctx, c, m.ChannelPrincipal) != nil {
		return receipt, ErrInstall
	}
	nextState, recheckedAt, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || nextState.cas != state.cas || !recheckedAt.Before(until) || !time.Now().Before(until) {
		return receipt, ErrInstall
	}
	m.Source.OutputDirectory, m.Source.Until = in.OutputDirectory, in.Until
	m.ObservedAt, m.Until = observation.StartedAt(), until
	selection, e := originalC1S3ChannelSelection(c, m.ChannelPrincipal, m.ChannelCredentials, until)
	if e != nil {
		return receipt, e
	}
	m.ChannelMaterial = BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "c1-channel.material.json"), SHA256: hash(selection)}
	material, e := canonical(m)
	if e != nil {
		return receipt, e
	}
	signature := ed25519.Sign(issuer, append([]byte(originalC1S3Domain), material...))
	if writeNewFiles(in.OutputDirectory, map[string][]byte{"c1-s3.material.json": material, "c1-s3.material.signature": signature, "c1-channel.material.json": selection}) != nil {
		return receipt, ErrCommitUnknown
	}
	return i.QueryOriginalC1S3Material(ctx, password, enrollment, in.OutputDirectory)
}

func renewOriginalC1S3Credential(p probe.Principal, previousUntil, now, until time.Time) ([]byte, error) {
	raw, e := probe.ReadPinned(p.Credential, 16384)
	defer clear(raw)
	var c originalC1S3Credential
	if e != nil || decodeExact(raw, &c) != nil || hash([]byte(c.AccessKey)) != p.AccountSHA256 || c.SecretKey == "" ||
		c.SessionToken != "" || c.NotBefore.IsZero() || !c.NotBefore.Before(c.Until) || !c.Until.Equal(previousUntil) || !now.Before(until) {
		return nil, ErrInstall
	}
	c.NotBefore, c.Until = now, until
	return canonical(c)
}

func originalC1S3MatchesConfig(raw []byte, c probe.S3Profile) bool {
	config, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		return false
	}
	refs, e := sixConfigReferences(config)
	if e != nil {
		return false
	}
	selected := make(map[string]sec.BootstrapSecretRef, len(refs))
	for _, ref := range refs {
		selected[ref.Purpose] = ref
	}
	if selected["evidence_store"] != (sec.BootstrapSecretRef{Purpose: "evidence_store", IdentityHash: c.Evidence.Identity, Version: c.Evidence.Version}) {
		return false
	}
	for _, p := range c.Principals {
		if selected[p.Purpose] != (sec.BootstrapSecretRef{Purpose: p.Purpose, IdentityHash: p.AccountSHA256, Version: p.PolicyName}) {
			return false
		}
	}
	return true
}
