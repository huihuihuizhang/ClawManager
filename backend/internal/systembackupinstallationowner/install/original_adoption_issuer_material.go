package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"time"
)

var ErrOriginalAdoptionIssuerMaterialUnconfirmed = errors.New("original adoption issuer files retained without confirmed owner; inspect before retry")

var originalAdoptionIssuerRoles = []string{"original_sql_census", "immutable_external_snapshot", "original_writer_fence", "historical_backfill", "adoption"}

// Material locators only. No witness/source facts, epoch, scope, Passed, record
// hash or user-supplied revision is accepted as proof by the actual issuer.
type originalAdoptionIssuerMaterial struct {
	Version, PlanSHA256 string
	Enrollment          EnrollmentPin
	Issuers             map[string]originalAdoptionIssuerKey
}

type originalAdoptionIssuerKey struct {
	PrivateKey      BootstrapSourceFilePin
	PublicKeySHA256 string
}

func originalAdoptionSigningAuthority(ctx context.Context, s *authenticatedOperator, enrollment EnrollmentPin, expected *HeadCAS) (time.Time, error) {
	if s == nil || s.kubernetes(ctx, "get") != nil || s.authority(ctx, enrollment) != nil {
		return time.Time{}, ErrInstall
	}
	current, now, err := snapshot(ctx, s)
	if err != nil || expected != nil && current.cas != *expected || current.cas.HeadRevision != 0 && (current.cas.State != "active" || now.Before(current.head.NotBefore) || !now.Before(current.head.Until)) {
		return time.Time{}, ErrInstall
	}
	return now, nil
}

// PrepareOriginalAdoptionIssuerMaterial actually creates five independent owner
// signing keys through the authenticated ORIGINAL installer before source hold.
// These keys confer no history proof; only the later source-consuming issuer
// can produce records. No permission/provider/runtime key is repurposed.
func (i *Installer) PrepareOriginalAdoptionIssuerMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string) (BootstrapSourceFilePin, error) {
	var zero BootstrapSourceFilePin
	s, err := i.authenticate(ctx, password)
	if err != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, nil); err != nil {
		return zero, err
	}
	current, _, err := snapshot(ctx, s)
	if err != nil {
		return zero, ErrInstall
	}
	d := originalAdoptionIssuerMaterial{Version: "original-adoption-owner-issuers.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Issuers: map[string]originalAdoptionIssuerKey{}}
	files := map[string][]byte{}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	for _, role := range originalAdoptionIssuerRoles {
		public, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return zero, ErrInstall
		}
		name := role + ".private"
		files[name], files[role+".public"] = private, public
		d.Issuers[role] = originalAdoptionIssuerKey{PrivateKey: BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(private)}, PublicKeySHA256: hash(public)}
	}
	raw, err := canonical(d)
	if err != nil {
		return zero, ErrInstall
	}
	files["original-adoption-issuers.json"] = raw
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &current.cas); err != nil || writeNewFiles(directory, files) != nil {
		return zero, ErrInstall
	}
	for name, expected := range files {
		actual, e := ReadPrivateFile(filepath.Join(directory, name), int64(len(expected)+1))
		same := e == nil && bytes.Equal(actual, expected)
		clear(actual)
		if !same {
			return zero, ErrOriginalAdoptionIssuerMaterialUnconfirmed
		}
	}
	if _, err = originalAdoptionSigningAuthority(ctx, s, enrollment, &current.cas); err != nil {
		return zero, ErrOriginalAdoptionIssuerMaterialUnconfirmed
	}
	return BootstrapSourceFilePin{File: filepath.Join(directory, "original-adoption-issuers.json"), SHA256: hash(raw)}, nil
}

func readOriginalAdoptionIssuerMaterial(p *PreparedOriginalAdoptionSQLCut, pin BootstrapSourceFilePin) (originalAdoptionIssuerMaterial, map[string]ed25519.PrivateKey, error) {
	var d originalAdoptionIssuerMaterial
	raw, err := readBootstrapSourcePin(pin, 262144)
	if err != nil || decodeExact(raw, &d) != nil || p == nil || p.operator == nil || p.operator.installer == nil || d.Version != "original-adoption-owner-issuers.v1" || d.PlanSHA256 != p.operator.installer.planHash || d.Enrollment != p.enrollment || len(d.Issuers) != 5 {
		return d, nil, ErrInstall
	}
	keys := map[string]ed25519.PrivateKey{}
	ok := false
	defer func() {
		if !ok {
			for _, key := range keys {
				clear(key)
			}
		}
	}()
	seen := map[string]bool{}
	for _, role := range originalAdoptionIssuerRoles {
		selected, exists := d.Issuers[role]
		if !exists || !digestPattern.MatchString(selected.PublicKeySHA256) || seen[selected.PublicKeySHA256] {
			return d, nil, ErrInstall
		}
		seen[selected.PublicKeySHA256] = true
		private, e := readBootstrapSourcePin(selected.PrivateKey, ed25519.PrivateKeySize)
		if e != nil || len(private) != ed25519.PrivateKeySize {
			clear(private)
			return d, nil, ErrInstall
		}
		canonical := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
		valid := bytes.Equal(canonical, private) && hash(canonical[ed25519.SeedSize:]) == selected.PublicKeySHA256
		clear(private)
		if !valid {
			clear(canonical)
			return d, nil, ErrInstall
		}
		keys[role] = canonical
	}
	ok = true
	return d, keys, nil
}
