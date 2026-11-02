package install

import (
	"bytes"
	"context"
	"encoding/json"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// Original grant/config/observer mapping files remain current identity inputs.
// A missing/unusable CA bundle is a CLOSED physical dependency, not permission
// and not a reason to skip original SQL identity authorization for history.
func readConsumerCaptureRequest(i *Installer, files RequestFiles) (*originalRequest, error) {
	raw, e := ReadPrivateFile(files.ConfigFile, 262144)
	if e != nil || hash(raw) != files.ConfigFileSHA256 {
		return nil, ErrInstall
	}
	config, e := sec.DecodeBootstrapConfig(raw)
	if e != nil {
		return nil, ErrInstall
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(config.CanonicalJSON(), &fields) != nil || !bytes.Equal(fields["enabled"], []byte("false")) {
		return nil, ErrInstall
	}
	grantRaw, e := ReadPrivateFile(files.GrantFile, 16384)
	if e != nil || hash(grantRaw) != files.GrantFileSHA256 {
		return nil, ErrInstall
	}
	grant, start, end, e := sec.ReadBootstrapGrantFile(files.GrantFile, files.GrantFileSHA256)
	if e != nil || grant.ConfigSHA256 != config.SHA256() {
		return nil, ErrInstall
	}
	observerRaw, e := ReadPrivateFile(files.ObserverFile, 262144)
	var doc observerDocument
	if e != nil || hash(observerRaw) != files.ObserverFileSHA256 || decodeExact(observerRaw, &doc) != nil {
		return nil, ErrInstall
	}
	request := &originalRequest{files: files, grant: grant, config: config, start: start, end: end, caFile: doc.CAFile, caSHA: doc.CASHA256}
	ca, e := ReadPrivateFile(doc.CAFile, 65536)
	if e != nil || hash(ca) != doc.CASHA256 {
		return request, nil
	}
	// Constructor failure cannot supply a usable observation; it never replaces
	// signature/plan/enrollment/original SQL current-identity checks.
	request.observer, _ = owner.NewCaptureSigningObserver(owner.SigningObserverConfig{Endpoint: doc.Endpoint, CASHA256: doc.CASHA256, CAPEM: ca, ObserverPolicy: doc.ObserverPolicy, ObserverTokenFile: doc.ObserverTokenFile, ObserverTokenSHA256: doc.ObserverTokenSHA256, RuntimeJWTFile: doc.RuntimeJWTFile, Trust: doc.Trust, Kubernetes: i.kube})
	return request, nil
}

func (s *consumerCaptureState) physical(ctx context.Context) error {
	if s.current(ctx) != nil || s.request.observer == nil || s.request.checkPinnedFiles() != nil {
		return s.finish(ErrInstall)
	}
	return nil
}
