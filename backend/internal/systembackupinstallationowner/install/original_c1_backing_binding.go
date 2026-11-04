package install

import (
	ev "clawreef/internal/systembackupevidence"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"time"
)

type OriginalC1BackingReceipt struct {
	Version           string
	Source, Signature BootstrapSourceFilePin
}

// BindOriginalC1BackingStore runs BEFORE capture and BEFORE SQL source locks.
// It accepts only the opaque running owner-channel source, never replacement
// endpoint JSON. It authenticates the same original enrolled installation and
// signs durable backing coordinates separately from ephemeral TLS transport.
// The later producer MUST retain this pointer and receipt; the signed data
// carrier alone cannot recreate either native or SDK authority.
func (p *OriginalC1Production) BindOriginalC1BackingStore(ctx context.Context, source *ev.OriginalC1BackingStoreSource, issuerPrivate []byte) (OriginalC1BackingReceipt, error) {
	var zero OriginalC1BackingReceipt
	if !p.live(ctx) || p.recheckPrepared() != nil || p.backing != nil || source == nil || source.CurrentOriginalOwner(ctx) != nil {
		return zero, ErrInstall
	}
	store, observed, err := source.OriginalStore()
	if err != nil || store.Identity != p.channel.Store.Identity || store.Version != p.channel.Store.Version || store.Root != p.channel.Root || store.Installation != p.request.grant.InstallationID || observed.After(time.Now()) {
		return zero, ErrInstall
	}
	transport, profile, err := source.OriginalChannel()
	if err != nil || !digestPattern.MatchString(profile) || transport.Store.Identity != store.Identity || transport.Store.Version != store.Version || transport.Store.Bucket != store.Bucket || transport.Store.Root != store.Root || transport.Store.Installation != store.Installation {
		return zero, ErrInstall
	}
	const version = "original-enrolled-c1-backing-association.v1"
	raw, err := canonical(struct {
		Version, PlanSHA256, DomainSourceSHA256 string
		Enrollment                              EnrollmentPin
		Channel                                 ev.ProducerEvidenceChannel
		NativeStore                             ev.S3Config
		Transport                               ev.S3STSConfig
		NativeObservedAt                        time.Time
		ProviderProfileSHA256                   string
		NotAfter                                time.Time
	}{version, p.operator.installer.planHash, p.profileSHA, p.enrollment, p.channel, store, transport, observed, profile, p.until})
	if err != nil || len(raw) > 262144 {
		return zero, ErrInstall
	}
	key, err := p.operator.privateKey(issuerPrivate)
	if err != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(version+"\x00"), raw...))
	if p.recheckPrepared() != nil || source.CurrentOriginalOwner(ctx) != nil || writeNewFiles(p.input.OutputDirectory, map[string][]byte{"c1-backing.source.json": raw, "c1-backing.source.signature": signature}) != nil {
		return zero, ErrInstall
	}
	receipt := OriginalC1BackingReceipt{Version: version, Source: BootstrapSourceFilePin{File: filepath.Join(p.input.OutputDirectory, "c1-backing.source.json"), SHA256: hash(raw)}, Signature: BootstrapSourceFilePin{File: filepath.Join(p.input.OutputDirectory, "c1-backing.source.signature"), SHA256: hash(signature)}}
	p.backing, p.backingBinding = source, &receipt
	return receipt, nil
}
