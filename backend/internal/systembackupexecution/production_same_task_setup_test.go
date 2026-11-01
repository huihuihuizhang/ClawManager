package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
)

// These fixture-only callbacks prepare A's real publication declarations and
// materials on the SAME original task. They cannot change capture settings or
// re-sign a core after capture. The original claim/TTL/data/ten workers remain.
type dOriginalSixPartFixtureOptions struct {
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
