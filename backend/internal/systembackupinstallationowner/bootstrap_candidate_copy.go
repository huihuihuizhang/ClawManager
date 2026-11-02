package systembackupinstallationowner

import (
	"encoding/json"

	pd "clawreef/internal/systembackupproducer"
)

func freezeCaptureRequest(request pd.BootstrapConsumptionRequest) (pd.BootstrapConsumptionRequest, error) {
	raw, e := json.Marshal(request)
	if e != nil {
		return pd.BootstrapConsumptionRequest{}, ErrOwner
	}
	var owned pd.BootstrapConsumptionRequest
	if json.Unmarshal(raw, &owned) != nil {
		return pd.BootstrapConsumptionRequest{}, ErrOwner
	}
	return owned, nil
}
