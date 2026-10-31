package publicadapter

import (
	"encoding/json"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/team"
)

// TeamsWorkUnits is the C-owned finite-writer delta. The original D mapping
// must cover every actual platform replica; this list is not that discovery,
// nor does registration certify physical stop, child exit or original resume.
func TeamsWorkUnits() []string {
	return []string{"team.pending_deletions", "team.event_projection", "team.maintenance_sweep", "northbound.operation", "northbound.lifecycle_action", "team.workspace_http"}
}

// ValidateTeamsWriters is invoked by the public runner at admission and every
// capture fence. All Pause/CheckPaused/Resume calls remain on its frozen native
// writers and durable intents. It does not add a gate or synthesize an ACK.
func ValidateTeamsWriters(source SourceInventory, frozen []FrozenWriter) error {
	if source.Teams == nil {
		return nil
	}
	inv := source.Teams
	users, owners, instances := map[int]bool{}, map[int]int{}, map[int]InstanceIdentity{}
	for _, id := range source.Users {
		users[id] = true
	}
	for _, i := range source.Instances {
		owners[i.ID] = i.UserID
		instances[i.ID] = i
	}
	if inv.Validate(users, owners) != nil {
		return &Failure{"writer_registry_drift"}
	}
	// Templates/creation can still be written when no Team is active: the
	// platform delta remains mandatory whenever the C module is enabled.
	if len(inv.Writers) == 0 || len(inv.Writers) > 10000 {
		return &Failure{"writer_registry_drift"}
	}
	originals := map[string]FrozenWriter{}
	for _, w := range frozen {
		if w.ID == "" || originals[w.ID].ID != "" {
			return &Failure{"writer_registry_drift"}
		}
		originals[w.ID] = w
	}
	required, covered, seen := map[int]bool{}, map[int]bool{}, map[string]bool{}
	for _, t := range inv.Teams {
		for _, m := range t.Members {
			if m.InstanceID != 0 {
				required[m.InstanceID] = true
			}
		}
	}
	units := map[string]bool{}
	for _, unit := range TeamsWorkUnits() {
		units[unit] = false
	}
	for _, b := range inv.Writers {
		w, ok := originals[b.ID]
		if !ok || seen[b.ID] || b.UID == "" || b.Generation <= 0 || b.Checkpoint == "" ||
			w.Original.UID != b.UID || w.Original.Generation != b.Generation || w.Original.Running != b.Running || w.Original.Checkpoint != b.Checkpoint {
			return &Failure{"writer_registry_drift"}
		}
		seen[b.ID] = true
		if b.Kind == "platform" {
			if b.InstanceID != 0 || len(b.Units) == 0 || (!strings.HasPrefix(b.ID, "deployment/") && !strings.HasPrefix(b.ID, "pod/")) {
				return &Failure{"writer_registry_drift"}
			}
			local := map[string]bool{}
			for _, unit := range b.Units {
				if _, ok := units[unit]; !ok || local[unit] {
					return &Failure{"writer_registry_drift"}
				}
				local[unit] = true
				units[unit] = true
			}
			continue
		}
		i, exists := instances[b.InstanceID]
		if !exists || !required[b.InstanceID] || covered[b.InstanceID] || len(b.Units) != 0 || !validTeamsRuntimeBinding(b, i) {
			return &Failure{"writer_registry_drift"}
		}
		covered[b.InstanceID] = true
	}
	for _, yes := range units {
		if !yes {
			return &Failure{"writer_registry_drift"}
		}
	}
	for id := range required {
		if !covered[id] {
			return &Failure{"writer_registry_drift"}
		}
	}
	return nil
}

func validTeamsRuntimeBinding(b team.WriterBinding, i InstanceIdentity) bool {
	if b.Kind != "stopped" && i.Status != "running" {
		return false
	}
	switch b.Kind {
	case "stopped":
		return i.Status == "stopped" && !b.Running && b.ID == "stopped/"+strconv.Itoa(i.ID)
	case "gateway":
		original := b.UID
		suffix := "/gw-" + strconv.Itoa(i.ID) + "-" + strconv.Itoa(i.Generation)
		if strings.HasSuffix(original, suffix) {
			original = strings.TrimSuffix(original, suffix)
		}
		return b.Running && b.ID == "gateway/"+original+"/"+strconv.Itoa(i.ID)
	case "pod", "deployment":
		parts := strings.Split(b.ID, "/")
		return b.Running && len(parts) == 3 && parts[0] == b.Kind && parts[1] != "" && parts[2] != "" && (i.Namespace == "" || parts[1] == i.Namespace) && (b.Kind != "pod" || i.Pod == "" || parts[2] == i.Pod)
	}
	return false
}

func validateTeamsDiscovery(x Discovery) error {
	var header map[string]json.RawMessage
	if decodeStrict(x.Source, &header) != nil {
		return &Failure{"writer_registry_drift"}
	}
	// Legacy profiles may use another source format. Only the exact Teams
	// opt-in activates this contract; strict decoding rejects ambiguous aliases.
	var hasTeams bool
	for key, raw := range header {
		if strings.EqualFold(key, "Teams") && key != "Teams" {
			return &Failure{"writer_registry_drift"}
		}
		if strings.EqualFold(key, "Teams") && string(raw) != "null" {
			hasTeams = true
		}
	}
	if !hasTeams {
		return nil
	}
	var source SourceInventory
	if _, ok := header["Teams"]; !ok || decodeStrict(x.Source, &source) != nil || source.Teams == nil {
		return &Failure{"writer_registry_drift"}
	}
	return ValidateTeamsWriters(source, x.Writers)
}
