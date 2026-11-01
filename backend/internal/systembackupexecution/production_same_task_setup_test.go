package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"

	d "clawreef/internal/systembackupdispatch"
)

// These fixture-only callbacks prepare A's real publication declarations and
// materials on the SAME original task. They cannot change capture settings or
// re-sign a core after capture. The original claim/TTL/data/ten workers remain.
type dOriginalSixPartFixtureOptions struct {
	// Actual artifact purpose mapping declared before original config/task
	// admission. No existing JSON, source settings or claim is rewritten.
	PublicationTarget *PublicationTargetMaterials
	// Explicit new pre-capture protocol variant. Legacy ten workers stay ten.
	CaptureDescription       bool
	PublicationForward       bool
	BeforeOriginalConfig     func(context.Context, *testing.T, *dOriginalSixPartTask, map[string]any) error
	BeforeCoreSeal           func(context.Context, *testing.T, *dOriginalSixPartTask, *DeploymentConfig) error
	AfterOwnerReady          func(context.Context, *testing.T, *dOriginalSixPartTask) error
	BeforeRuntimeComposition func(context.Context, *testing.T, *dOriginalSixPartTask) error
	BeforePrepare            func(context.Context, *testing.T, *dOriginalSixPartTask) error
	// Transparent native-driver fault, armed only at a publication boundary.
	// Nil keeps the original production-fixture connection path unchanged.
	ControlCommitACKLoss *atomic.Bool
	// Controlled pre-collector diagnostics only; nil preserves the original
	// connector and continuation. These cannot replace a validated capture.
	ControlBeforeQuery   func(context.Context, string) error
	ControlAfterQuery    func(string, error)
	AfterOriginalPrepare func(context.Context, *testing.T, *dOriginalSixPartTask, d.Plan) error
}

func prepareDOriginalPublicationReferences(values map[string]any, target PublicationTargetMaterials) error {
	if target.validate() != nil {
		return errDOriginalCoreChanged
	}
	refs, ok := values["references"].([]any)
	if !ok {
		return errDOriginalCoreChanged
	}
	found := map[string]bool{}
	for _, value := range refs {
		ref, ok := value.(map[string]any)
		if !ok {
			return errDOriginalCoreChanged
		}
		purpose, _ := ref["purpose"].(string)
		switch purpose {
		case "artifact_read":
			ref["identity_hash"], ref["version"] = target.ReadIdentityHash, target.ReadRefVersion
		case "artifact_write":
			ref["identity_hash"], ref["version"] = target.WriteIdentityHash, target.WriteRefVersion
		case "artifact_ca":
			ref["identity_hash"], ref["version"] = target.CAIdentityHash, target.CARefVersion
		default:
			continue
		}
		if found[purpose] {
			return errDOriginalCoreChanged
		}
		found[purpose] = true
	}
	if len(found) != 3 {
		return errDOriginalCoreChanged
	}
	return nil
}

var errDOriginalCoreChanged = errors.New("original fixture capture core changed outside its pre-seal publication declarations")

// A receives a detached proposed core. Only its four publication declarations
// can differ. Detach the result again so retaining the callback pointer cannot
// mutate the subsequently sealed core or its nested capture/publication data.
func prepareDOriginalCore(core DeploymentConfig, configure func(*DeploymentConfig) error) (DeploymentConfig, error) {
	if configure == nil {
		return core, nil
	}
	original, err := json.Marshal(core)
	if err != nil {
		return DeploymentConfig{}, err
	}
	var proposed DeploymentConfig
	if json.Unmarshal(original, &proposed) != nil {
		return DeploymentConfig{}, errDOriginalCoreChanged
	}
	if err := configure(&proposed); err != nil {
		return DeploymentConfig{}, err
	}
	protected := proposed
	protected.PublicationSigners, protected.PublisherVerifier = core.PublicationSigners, core.PublisherVerifier
	protected.PublicationTarget, protected.PublicationWorker = core.PublicationTarget, core.PublicationWorker
	current, err := json.Marshal(protected)
	if err != nil || !bytes.Equal(original, current) {
		return DeploymentConfig{}, errDOriginalCoreChanged
	}
	raw, err := json.Marshal(proposed)
	var detached DeploymentConfig
	if err != nil || json.Unmarshal(raw, &detached) != nil {
		return DeploymentConfig{}, errDOriginalCoreChanged
	}
	return detached, nil
}

func checkDOriginalCoreUnchanged(service *DeploymentService, sealed []byte) error {
	if service == nil || len(sealed) == 0 || service.ConfigDigest != hash(sealed) {
		return errDOriginalCoreChanged
	}
	current, err := json.Marshal(service.Config)
	if err != nil || !bytes.Equal(sealed, current) {
		return errDOriginalCoreChanged
	}
	raw, err := pinnedDeploymentFile(service.ConfigPath, hash(sealed), 256<<10)
	if err != nil || !bytes.Equal(raw, sealed) {
		return errDOriginalCoreChanged
	}
	return nil
}
