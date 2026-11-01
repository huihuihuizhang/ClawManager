// Package gatewaypolicy holds data-only owner rules shared by SQL restore
// consumers. These transformations do not authenticate source data or authorize
// writes, and never call provider services.
package gatewaypolicy

import "clawreef/internal/systembackup/team"

// DisableRoutingClassifier is the existing isolated-copy rule: select local
// rules and remove the classifier endpoint/credential. Legacy column nullability
// is explicit; current migration 060/061 stores empty strings in both columns.
func DisableRoutingClassifier(row team.Row, nullable map[string]bool) team.Change {
	change := team.Change{Table: "routing_classifier_settings", Before: team.Clone(row), After: team.Clone(row), Reason: "preserved"}
	if _, ok := row["routing_mode"]; ok {
		change.After["routing_mode"] = team.Value("rules")
		change.Reason, change.Quarantined = "restore_disabled", true
	}
	for _, name := range []string{"base_url", "encrypted_api_key"} {
		if _, ok := row[name]; !ok {
			continue
		}
		if _, known := nullable[name]; !known {
			continue
		}
		value := team.Value("")
		if nullable[name] {
			value = team.Null()
		}
		change.After[name] = value
		change.Reason, change.Quarantined = "restore_disabled", true
	}
	return change
}
