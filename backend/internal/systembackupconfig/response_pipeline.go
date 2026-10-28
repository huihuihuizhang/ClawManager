// Package systembackupconfig composes D config writes with A/C evidence APIs.
// Keeping this composition above both packages prevents a security/evidence cycle.
package systembackupconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
	"time"

	ev "clawreef/internal/systembackupevidence"
	"clawreef/internal/systembackupread"
	sec "clawreef/internal/systembackupsecurity"
)

const configMutationResponseMaxBytes = sec.MaxConfigMutationResponseBytes

// Content is constructed from independent authenticated-writer facts, never a
// policy obtained by parsing untrusted body assertions. It is not write authority.
type ConfigMutationResponseContent struct {
	input                  sec.ConfigMutationResponsePreparation
	identity               ev.Identity
	database               sec.DatabaseIdentity
	store                  sec.BootstrapSecretRef
	kek                    ev.KeyRef
	payload                []byte
	created, retain, until time.Time
}

func (c ConfigMutationResponseContent) Identity() ev.Identity { return c.identity }
func (c ConfigMutationResponseContent) Preparation() sec.ConfigMutationResponsePreparation {
	return c.input
}
func (c ConfigMutationResponseContent) StoreReference() sec.BootstrapSecretRef { return c.store }
func (c ConfigMutationResponseContent) KEKReference() ev.KeyRef                { return c.kek }
func (c ConfigMutationResponseContent) Bytes() []byte                          { return append([]byte(nil), c.payload...) }
func (c ConfigMutationResponseContent) ValidUntil() time.Time                  { return c.until }
func (c ConfigMutationResponseContent) RetainUntil() time.Time                 { return c.retain }
func (ConfigMutationResponseContent) MarshalJSON() ([]byte, error)             { return nil, sec.ErrConfigMutation }

func PrepareConfigMutationResponseContent(ctx context.Context, input sec.ConfigMutationResponsePreparation, publicID string) (ConfigMutationResponseContent, error) {
	fail := func() (ConfigMutationResponseContent, error) {
		return ConfigMutationResponseContent{}, sec.ErrRegistrationUnavailable
	}
	policy := input.ContentPolicy()
	raw := input.Bytes()
	expected, err := sec.CanonicalConfigMutationResponse(policy)
	if ctx == nil || ctx.Err() != nil || !evidenceIDPattern.MatchString(publicID) || !validDatabase(input.Database()) || err != nil || !bytes.Equal(raw, expected) || !sessionAt(input.Actor(), policy.CreatedAt) || input.ValidUntil().IsZero() || len(raw) < 2 || len(raw) > configMutationResponseMaxBytes {
		return fail()
	}
	var store sec.BootstrapSecretRef
	var kek ev.KeyRef
	for _, ref := range input.CurrentConfig().References() {
		if ref.Purpose == "evidence_store" {
			store = ref
		}
		if ref.Purpose == "evidence_kek" {
			kek = ev.KeyRef{Identity: ref.IdentityHash, Version: ref.Version}
		}
	}
	if store.Purpose != "evidence_store" || !hashPattern.MatchString(kek.Identity) || kek.Version == "" {
		return fail()
	}
	i := ev.Identity{Installation: policy.InstallationID, ID: publicID, OwnerType: "system", OwnerID: policy.InstallationID, Type: "diagnostic", Media: "application/json", Classification: "internal", ContentHash: registrationHash(string(raw)), ContentSize: int64(len(raw))}
	return ConfigMutationResponseContent{input, i, input.Database(), store, kek, raw, policy.CreatedAt, input.RetainUntil(), input.ValidUntil()}, nil
}

// This parser validates a decrypted HISTORICAL response only after an exact
// committed manifest/hash read. It cannot create a live ContentAuthorization.
func decodeConfigMutationResponseResource(installation, actorID string, raw []byte) (systembackupread.ConfigResourceDTO, sec.ConfigValues, time.Time, error) {
	fail := func() (systembackupread.ConfigResourceDTO, sec.ConfigValues, time.Time, error) {
		return systembackupread.ConfigResourceDTO{}, sec.ConfigValues{}, time.Time{}, sec.ErrConfigMutation
	}
	if len(raw) < 2 || len(raw) > configMutationResponseMaxBytes || !json.Valid(raw) {
		return fail()
	}
	var dto systembackupread.ConfigResourceDTO
	if json.Unmarshal(raw, &dto) != nil || dto.SchemaVersion != "system-backup-config.v1" || dto.OriginInstallationID != installation || dto.CreatedBy != actorID || dto.RowVersion != 1 || !dto.Active {
		return fail()
	}
	uid, err := strconv.ParseInt(actorID, 10, 64)
	if err != nil || uid < 1 || strconv.FormatInt(uid, 10) != actorID {
		return fail()
	}
	config, err := sec.DecodeConfigValues(dto.Config)
	if err != nil {
		return fail()
	}
	created, err := time.Parse(time.RFC3339Nano, dto.CreatedAt)
	if err != nil {
		return fail()
	}
	policy := sec.ConfigMutationResponseContentPolicy{InstallationID: installation, CreatedBy: uid, Version: int64(dto.Version), Config: config, RedactedReason: dto.ChangeReason, CreatedAt: created, DeploymentEnabled: dto.EffectiveEnabled}
	expected, err := sec.CanonicalConfigMutationResponse(policy)
	if err != nil || !bytes.Equal(raw, expected) {
		return fail()
	}
	return dto, config, created, nil
}

type responseContentAuthority struct {
	upstream                    ev.ContentAuthority
	content                     ConfigMutationResponseContent
	producer                    string
	authorityUntil, policyUntil time.Time
}

func (a *responseContentAuthority) AuthorizeContent(ctx context.Context, i ev.Identity) (ev.ContentAuthorization, error) {
	deny := func() (ev.ContentAuthorization, error) { return ev.ContentAuthorization{}, ev.ErrDenied }
	if ctx == nil || ctx.Err() != nil || i != a.content.identity || !time.Now().Before(a.authorityUntil) || !time.Now().Before(a.policyUntil) {
		return deny()
	}
	v, err := a.upstream.AuthorizeContent(ctx, i)
	if err != nil || v.Identity != i || v.ProducerIdentityHash != a.producer || !v.ValidUntil.Equal(a.authorityUntil) || v.Capability != nil || v.JobLog != nil || v.ConfigResponse == nil {
		return deny()
	}
	p := *v.ConfigResponse
	raw, err := sec.CanonicalConfigMutationResponse(p.Response)
	if err != nil || p.EvidenceID != i.ID || p.Classification != i.Classification || !p.ValidUntil.Equal(a.policyUntil) || !bytes.Equal(raw, a.content.payload) {
		return deny()
	}
	// Own the reason pointer before the dispatcher's subsequent callbacks.
	if p.Response.RedactedReason != nil {
		copy := *p.Response.RedactedReason
		p.Response.RedactedReason = &copy
	}
	v.ConfigResponse = &p
	return v, nil
}

// Encrypt retains A's live diagnostic/config-response dispatcher and immutable
// policy boundaries. It writes only SBEV ciphertext into owned staging. Pending
// publication must commit before provider PUT; this call never publishes.
func (c ConfigMutationResponseContent) Encrypt(ctx context.Context, authority ev.ContentAuthority, keys ev.Keys, dst io.Writer) (ev.Prepared, error) {
	fail := func() (ev.Prepared, error) { return ev.Prepared{}, sec.ErrRegistrationUnavailable }
	if ctx == nil || ctx.Err() != nil || len(c.payload) <= 8192 || isNil(authority) || isNil(keys) || isNil(dst) || !time.Now().Before(c.until) {
		return fail()
	}
	baseline, err := authority.AuthorizeContent(ctx, c.identity)
	if err != nil || baseline.ConfigResponse == nil || !hashPattern.MatchString(baseline.ProducerIdentityHash) {
		return fail()
	}
	until := c.until
	if baseline.ValidUntil.Before(until) {
		until = baseline.ValidUntil
	}
	if baseline.ConfigResponse.ValidUntil.Before(until) {
		until = baseline.ConfigResponse.ValidUntil
	}
	if !time.Now().Before(until) {
		return fail()
	}
	call := &responseContentAuthority{authority, c, baseline.ProducerIdentityHash, baseline.ValidUntil, baseline.ConfigResponse.ValidUntil}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if _, err = call.AuthorizeContent(ctx, c.identity); err != nil {
		return fail()
	}
	dispatcher, err := ev.NewContentDispatcher(call)
	if err != nil {
		return fail()
	}
	source := func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(c.payload)), nil }
	p, err := ev.Prepare(ctx, c.identity, c.kek, source, dispatcher, keys, dst)
	if err != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return fail()
	}
	if _, err = call.AuthorizeContent(ctx, c.identity); err != nil {
		return fail()
	}
	return p, nil
}
