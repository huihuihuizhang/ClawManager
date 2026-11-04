package systembackupevidence

// Created ONLY after actual native Transit Wrap under the real concrete
// SystemTransitPreparer. This retains provider/ref/key/version/CA/profile
// provenance, never an encryption permission or token/private/clear DEK.
type originalSystemTransitPreparation struct {
	origin                *originalSystemTransitPreparation
	preparer              *SystemTransitPreparer
	manifestHash, profile string
	transit               TransitConfig
}

type OriginalC1KeySource struct {
	Transit        TransitConfig // CAPEM omitted; exact original CA hash remains.
	ProfileSHA256  string
	EnvelopeHeader []byte // Contains wrapped-DEK ciphertext, no secret plaintext.
}

func originalC1KeySource(p Prepared) (OriginalC1KeySource, error) {
	s := p.transitSource
	if s == nil || s.origin != s || s.preparer == nil || s.manifestHash != hash(canonical(p.Manifest())) || s.profile == "" || s.transit.Key != p.manifest.Key || len(p.header) == 0 || hash(p.header) != p.manifest.EnvelopeHash || int64(12+len(p.header)) != p.manifest.HeaderSize {
		return OriginalC1KeySource{}, ErrDenied
	}
	return OriginalC1KeySource{Transit: s.transit, ProfileSHA256: s.profile, EnvelopeHeader: append([]byte(nil), p.header...)}, nil
}
