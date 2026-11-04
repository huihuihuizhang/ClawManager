package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type OriginalBootstrapCommitInspection struct {
	Version, State, RequestSHA256 string
	Result                        sec.ConfigBootstrapResult
}

// Inputs are exact original producer files, not a submitted success receipt.
// Fresh native admin/enrollment authentication is required before SQL readback.
func (i *Installer) InspectOriginalBootstrapCommit(ctx context.Context, password []byte, enrollment EnrollmentPin, deploymentPin, consumptionPin BootstrapSourceFilePin) (OriginalBootstrapCommitInspection, error) {
	var zero OriginalBootstrapCommitInspection
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(deploymentPin, 262144)
	var deployment sec.BootstrapDeploymentConfig
	if err != nil || decodeExact(raw, &deployment) != nil || deployment.InstallationID != i.plan.Target.InstallationID || deployment.ExpectedServerUUID != i.plan.Target.ServerUUID || deployment.ExpectedDatabase != i.plan.Target.Database {
		return zero, ErrInstall
	}
	grant, _, _, err := sec.ReadBootstrapGrantFile(deployment.GrantFile, deployment.GrantSHA256)
	if err != nil || grant.InstallationID != i.plan.Target.InstallationID || grant.ServerUUID != i.plan.Target.ServerUUID || grant.Database != i.plan.Target.Database || grant.UserID != op.userID || grant.Username != i.plan.LocalAdminUsername {
		return zero, ErrInstall
	}
	configRaw, err := ReadSourceMaterialFile(deployment.ConfigFile)
	if err != nil {
		return zero, ErrInstall
	}
	config, err := sec.DecodeBootstrapConfig(configRaw)
	if err != nil || config.SHA256() != deployment.ConfigSHA256 || config.SHA256() != grant.ConfigSHA256 {
		return zero, ErrInstall
	}
	requestRaw, err := readBootstrapSourcePin(consumptionPin, 8<<20)
	var request pd.BootstrapConsumptionRequest
	if err != nil || decodeOriginalBootstrapRequest(requestRaw, &request) != nil {
		return zero, ErrInstall
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(config.CanonicalJSON(), &values) != nil || !originalBootstrapRequestMatches(grant, request, hash(values["registries"]), hash(values["references"])) {
		return zero, ErrInstall
	}
	digest, err := pd.BootstrapConsumptionHash(request)
	if err != nil {
		return zero, ErrInstall
	}
	result, err := sec.ReadbackOriginalBootstrapCommit(ctx, i.db, grant, config, string(digest))
	if err != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrCommitUnknown
	}
	if current, e := readBootstrapSourcePin(deploymentPin, 262144); e != nil || hash(current) != hash(raw) {
		return zero, ErrCommitUnknown
	}
	if current, e := readBootstrapSourcePin(consumptionPin, 8<<20); e != nil || hash(current) != hash(requestRaw) {
		return zero, ErrCommitUnknown
	}
	return OriginalBootstrapCommitInspection{Version: "original-bootstrap-commit-inspection.v1", State: "original_bootstrap_commit_exact_readback_only_no_new_write", RequestSHA256: string(digest), Result: result}, nil
}

func decodeOriginalBootstrapRequest(raw []byte, request *pd.BootstrapConsumptionRequest) error {
	if len(raw) == 0 || len(raw) > 8<<20 {
		return ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(request) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	roundtrip, err := canonical(*request)
	if err != nil || !bytes.Equal(roundtrip, raw) {
		return ErrInstall
	}
	return nil
}

func originalBootstrapRequestMatches(g sec.OfflineBootstrapGrant, r pd.BootstrapConsumptionRequest, registries, refs string) bool {
	grant, _ := json.Marshal(g)
	return r.Scope == (pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)}) && r.ActorID == pd.Counter(strconv.FormatInt(g.UserID, 10)) && r.Username == g.Username && r.MatrixKey == g.MatrixKey && r.Endpoint == sec.BootstrapConfigEndpoint && r.IdempotencyKey == g.IdempotencyKey && r.ConfigHash == pd.Hash(g.ConfigSHA256) && r.OfflineGrantHash == pd.Hash(hash(grant)) && r.RegistrySetHash == pd.Hash(registries) && r.RefSetHash == pd.Hash(refs)
}
