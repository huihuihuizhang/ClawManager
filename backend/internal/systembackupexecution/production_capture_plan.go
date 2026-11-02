package systembackupexecution

import (
	"encoding/json"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

// A plan owns immutable original builder inputs, not authority or a claim that
// any source/publisher dependency is available. It cannot declare public parts.
type productionCapturePlan struct {
	revision       string
	operationsJSON string
}

func newProductionCapturePlan(operations map[string]productionCaptureOperation, revision string) (*productionCapturePlan, error) {
	if revision == "" || len(revision) > 128 || len(operations) < 7 || len(operations) > 9 {
		return nil, d.ErrNotReady
	}
	for _, name := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", ce.Operation} {
		if _, exists := operations[name]; !exists {
			return nil, d.ErrNotReady
		}
	}
	for name := range operations {
		switch name {
		case "capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", "capture-team-objects", ce.Operation, cd.Operation:
		default:
			return nil, d.ErrNotReady
		}
	}
	raw, err := json.Marshal(operations)
	if err != nil || len(raw) > 8<<20 {
		return nil, d.ErrNotReady
	}
	return &productionCapturePlan{revision: revision, operationsJSON: string(raw)}, nil
}

func (p *productionCapturePlan) matches(operations map[string]productionCaptureOperation, revision string) bool {
	if p == nil || p.revision != revision {
		return false
	}
	raw, err := json.Marshal(operations)
	return err == nil && string(raw) == p.operationsJSON
}

func (p *productionCapturePlan) build(in d.Input, source b.SourceInventory, hold time.Time, writers []b.FrozenWriter, node string) (*b.CaptureModules, error) {
	if p == nil || p.revision == "" || p.operationsJSON == "" {
		return nil, d.ErrNotReady
	}
	// Every build owns a fresh deep copy. Neither node placement nor the real
	// constructors may mutate the stored plan or the caller's material objects.
	var operations map[string]productionCaptureOperation
	if json.Unmarshal([]byte(p.operationsJSON), &operations) != nil {
		return nil, d.ErrNotReady
	}
	if node != "" {
		for name, operation := range operations {
			if operation.Workload.NodeName != "" && operation.Workload.NodeName != node {
				return nil, d.ErrNotReady
			}
			operation.Workload.NodeName = node
			operations[name] = operation
		}
	}
	return buildOriginalProductionCaptureModules(in, source, hold, writers, operations, p.revision)
}
