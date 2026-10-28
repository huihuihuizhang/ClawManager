package recovery

import "sort"

type RecoveryGroup struct{ Origin, Matrix, FailureDomain string }
type PruneArtifact struct {
	ID                                         string
	Group                                      RecoveryGroup
	Terminal                                   bool
	FinishedAt, CommittedAt                    int64
	State                                      string
	HistoricalEligible                         bool
	Locator                                    Locator
	Core                                       Core
	Bytes                                      int64
	ManualHold, PromotionHold, ActiveFinalizer bool
	LeaseUntil, GuardVersion                   int64
	RegistrationID, RegistrationSHA256         string
}
type PrunePlan struct {
	Cutoff     int64
	Config     Reference
	Candidates []PruneArtifact
	SHA256     string
	Shortage   map[string]int
}

func groupKey(g RecoveryGroup) string { b, _ := Marshal(g); return Hash(b) }

// PlanRetention does not use current readability or health to select protected
// recovery points. A temporarily inaccessible historical eligible point stays
// protected. The caller MUST recompute this under the same locks as delete CAS.
func PlanRetention(now, retention int64, minimum int, required []RecoveryGroup, rows []PruneArtifact, config Reference) (PrunePlan, error) {
	if now <= 0 || retention < 0 || retention > now || minimum < 1 || minimum > 100 || !config.valid() {
		return PrunePlan{}, ErrContract
	}
	plan := PrunePlan{Cutoff: now - retention, Config: config, Candidates: []PruneArtifact{}, Shortage: map[string]int{}}
	groups := map[string][]PruneArtifact{}
	seen := map[string]bool{}
	for _, g := range required {
		if !validID(g.Origin) || !validID(g.FailureDomain) || g.Matrix != "k8s-cluster" && g.Matrix != "k3s-cluster" && g.Matrix != "k8s-single-node" && g.Matrix != "k3s-single-node" {
			return plan, ErrContract
		}
		key := groupKey(g)
		if _, ok := groups[key]; ok {
			return plan, ErrContract
		}
		groups[key] = nil
	}
	for _, a := range rows {
		if !validID(a.ID) || seen[a.ID] || a.Bytes < 0 || a.GuardVersion < 0 || !a.Locator.valid() {
			return plan, ErrContract
		}
		seen[a.ID] = true
		if _, ok := groups[groupKey(a.Group)]; !ok || a.CommittedAt < 0 || a.FinishedAt < 0 || a.LeaseUntil < 0 {
			return plan, ErrContract
		}
		if a.RegistrationID != "" && (!validID(a.RegistrationID) || !digest(a.RegistrationSHA256)) {
			return plan, ErrContract
		}
		switch a.State {
		case "staging", "committed", "corrupt", "deleting", "delete_failed", "deleted":
		default:
			return plan, ErrContract
		}
		if a.Terminal && (a.State == "committed" || a.State == "corrupt") && a.CommittedAt > 0 && a.HistoricalEligible {
			groups[groupKey(a.Group)] = append(groups[groupKey(a.Group)], a)
		}
	}
	protected := map[string]bool{}
	for key, items := range groups {
		sort.Slice(items, func(i, j int) bool {
			if items[i].CommittedAt != items[j].CommittedAt {
				return items[i].CommittedAt > items[j].CommittedAt
			}
			return items[i].ID > items[j].ID
		})
		for i, a := range items {
			if i < minimum {
				protected[a.ID] = true
			}
		}
		if len(items) < minimum {
			plan.Shortage[key] = minimum - len(items)
		} else {
			plan.Shortage[key] = 0
		}
	}
	for _, a := range rows {
		if a.Terminal && a.FinishedAt > 0 && a.CommittedAt > 0 && a.CommittedAt < plan.Cutoff && (a.State == "committed" || a.State == "corrupt") && !a.ManualHold && !a.PromotionHold && !a.ActiveFinalizer && a.LeaseUntil <= now && !protected[a.ID] {
			plan.Candidates = append(plan.Candidates, a)
		}
	}
	sort.Slice(plan.Candidates, func(i, j int) bool { return plan.Candidates[i].ID < plan.Candidates[j].ID })
	raw, e := Marshal(struct {
		Cutoff     int64
		Config     Reference
		Candidates []PruneArtifact
	}{plan.Cutoff, config, plan.Candidates})
	if e != nil {
		return plan, e
	}
	plan.SHA256 = Hash(raw)
	return plan, nil
}
