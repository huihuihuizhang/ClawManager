package systembackupresources

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"
)

// Private offline candidates. Occupancy, cutoff, row provenance and bindings
// are still unauthenticated inputs until B verifies them under the actual
// restore transaction. Nothing here performs SQL or grants restore eligibility.
type restoreAuditInput struct {
	Audit, Northbound                 restoreFieldTable
	Bindings                          []restoreIDBinding
	OccupiedAudit, OccupiedNorthbound []int64
	SourceAuditMaxID                  *int64
	Budget                            restoreFieldBudget
}

// This association belongs only in protected, authenticated historical evidence.
// It contains neither source body text nor a source-body digest. A target MAX(id)
// cannot reconstruct the source cutoff after IDs have been remapped.
type restoreAuditHistory struct {
	Table                          string
	SourceID, TargetID             int64
	SourceUserID, SourceResourceID *int64
	SourceResourceType             *string
	SourceCreatedAt                *string
}
type restoreAuditCandidate struct {
	Audit, Northbound restoreFieldTable
	SourceAuditMaxID  *int64
	History           []restoreAuditHistory
}

func normalizeRestoreAudit(ctx context.Context, input restoreAuditInput) (restoreAuditCandidate, error) {
	if err := ctx.Err(); err != nil {
		return restoreAuditCandidate{}, err
	}
	if input.Audit.Name != "audit_logs" || input.Northbound.Name != "northbound_settings_audit" || input.Budget.Rows <= 0 || input.Budget.Bytes <= 0 {
		return restoreAuditCandidate{}, errors.New("resources audit input is invalid")
	}
	// Reuse the closed shape/ID/budget boundary without accepting any other
	// domain's rows as part of this two-table candidate.
	var shape []restoreFieldTable
	for table, columns := range restoreFieldColumns() {
		entry := restoreFieldTable{Name: table, Columns: columns}
		if table == input.Audit.Name {
			entry = input.Audit
		}
		if table == input.Northbound.Name {
			entry = input.Northbound
		}
		shape = append(shape, entry)
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return restoreAuditCandidate{}, err
	}
	mapping, err := newRestoreIDMap(input.Bindings)
	if err != nil {
		return restoreAuditCandidate{}, err
	}
	if err = mapping.validateHistoryTargets(restoreAuditID, input.OccupiedAudit); err != nil {
		return restoreAuditCandidate{}, err
	}
	if err = mapping.validateHistoryTargets(restoreNBAuditID, input.OccupiedNorthbound); err != nil {
		return restoreAuditCandidate{}, err
	}
	var sourceMax int64
	for _, row := range input.Audit.Rows {
		id, _ := strconv.ParseInt(*row["id"], 10, 64)
		if id > sourceMax {
			sourceMax = id
		}
	}
	if (sourceMax == 0) != (input.SourceAuditMaxID == nil) || (input.SourceAuditMaxID != nil && *input.SourceAuditMaxID != sourceMax) {
		return restoreAuditCandidate{}, errors.New("resources audit source cutoff differs")
	}
	result := restoreAuditCandidate{
		Audit:      restoreFieldTable{Name: input.Audit.Name, Columns: append([]string(nil), input.Audit.Columns...)},
		Northbound: restoreFieldTable{Name: input.Northbound.Name, Columns: append([]string(nil), input.Northbound.Columns...)},
	}
	if input.SourceAuditMaxID != nil {
		v := *input.SourceAuditMaxID
		result.SourceAuditMaxID = &v
	}
	for _, entry := range []struct {
		source      restoreFieldTable
		target      *restoreFieldTable
		kind        restoreIDKind
		actor       string
		actionLimit int
	}{
		{input.Audit, &result.Audit, restoreAuditID, "user_id", 100},
		{input.Northbound, &result.Northbound, restoreNBAuditID, "actor_user_id", 64},
	} {
		for _, source := range entry.source.Rows {
			if err := ctx.Err(); err != nil {
				return restoreAuditCandidate{}, err
			}
			row := cloneRestoreAuditRow(source)
			id, _ := strconv.ParseInt(*source["id"], 10, 64)
			targetID, err := mapping.nullable(entry.kind, &id)
			if err != nil {
				return restoreAuditCandidate{}, err
			}
			row["id"] = restoreAuditIDText(targetID)
			actor, err := parseRestoreAuditReference(source[entry.actor], restoreUserID)
			if err != nil {
				return restoreAuditCandidate{}, err
			}
			targetActor, err := mapping.nullable(restoreUserID, actor)
			if err != nil {
				return restoreAuditCandidate{}, err
			}
			row[entry.actor] = restoreAuditIDText(targetActor)
			if !validRestoreAuditAction(source["action"], entry.actionLimit) {
				return restoreAuditCandidate{}, errors.New("resources audit action is invalid")
			}
			if !validRestoreAuditTime(source["created_at"], entry.kind == restoreNBAuditID) {
				return restoreAuditCandidate{}, errors.New("resources audit creation time is invalid")
			}
			history := restoreAuditHistory{Table: entry.source.Name, SourceID: id, TargetID: *targetID, SourceUserID: actor, SourceCreatedAt: cloneRestoreAuditValue(source["created_at"])}
			if entry.kind == restoreAuditID {
				kind := source["resource_type"]
				if kind == nil {
					return restoreAuditCandidate{}, errors.New("resources audit resource type is required")
				}
				var resourceKind restoreIDKind
				switch *kind {
				case "user":
					resourceKind = restoreUserID
				case "instance":
					resourceKind = restoreInstanceID
				case "system_backup":
					resourceKind = restoreAuditID
				default:
					return restoreAuditCandidate{}, errors.New("resources audit resource type is unsupported")
				}
				ref, err := parseRestoreAuditReference(source["resource_id"], resourceKind)
				if err != nil {
					return restoreAuditCandidate{}, err
				}
				targetRef, err := mapping.auditReference(*kind, ref)
				if err != nil {
					return restoreAuditCandidate{}, err
				}
				row["resource_id"] = restoreAuditIDText(targetRef)
				if !validRestoreAuditJSON(source["details"]) {
					return restoreAuditCandidate{}, errors.New("resources audit JSON is invalid")
				}
				row["details"] = redactRestoreJSON(source["details"])
				row["ip_address"] = redactRestoreText(source["ip_address"])
				history.SourceResourceType = cloneRestoreAuditValue(kind)
				history.SourceResourceID = ref
			} else {
				// DATETIME(6) is NOT NULL in the northbound audit migration.
				if source["created_at"] == nil {
					return restoreAuditCandidate{}, errors.New("resources audit creation time is required")
				}
				for _, column := range []string{"before_json", "after_json"} {
					if !validRestoreAuditJSON(source[column]) {
						return restoreAuditCandidate{}, errors.New("resources audit JSON is invalid")
					}
					row[column] = redactRestoreJSON(source[column])
				}
			}
			entry.target.Rows = append(entry.target.Rows, row)
			result.History = append(result.History, history)
		}
	}
	// Redaction can expand an empty string. The output must fit the same
	// explicit capacity independently of the source input's retained byte size.
	for i := range shape {
		if shape[i].Name == result.Audit.Name {
			shape[i] = result.Audit
		}
		if shape[i].Name == result.Northbound.Name {
			shape[i] = result.Northbound
		}
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return restoreAuditCandidate{}, err
	}
	if err := ctx.Err(); err != nil {
		return restoreAuditCandidate{}, err
	}
	return result, nil
}

func cloneRestoreAuditValue(value *string) *string {
	if value == nil {
		return nil
	}
	v := *value
	return &v
}
func cloneRestoreAuditRow(source restoreFieldRow) restoreFieldRow {
	result := make(restoreFieldRow, len(source))
	for k, v := range source {
		result[k] = cloneRestoreAuditValue(v)
	}
	return result
}
func restoreAuditIDText(id *int64) *string {
	if id == nil {
		return nil
	}
	v := strconv.FormatInt(*id, 10)
	return &v
}
func parseRestoreAuditReference(raw *string, kind restoreIDKind) (*int64, error) {
	if raw == nil {
		return nil, nil
	}
	id, err := strconv.ParseInt(*raw, 10, 64)
	if err != nil || !validRestoreID(kind, id) || strconv.FormatInt(id, 10) != *raw {
		return nil, errors.New("resources audit reference is invalid")
	}
	return &id, nil
}
func validRestoreAuditAction(value *string, limit int) bool {
	return value != nil && utf8.ValidString(*value) && utf8.RuneCountInString(*value) <= limit
}
func validRestoreAuditJSON(value *string) bool {
	return value == nil || (utf8.ValidString(*value) && json.Valid([]byte(*value)))
}
func validRestoreAuditTime(value *string, required bool) bool {
	if value == nil {
		return !required
	}
	text := *value
	if len(text) != 19 && (len(text) < 21 || len(text) > 26 || text[19] != '.') {
		return false
	}
	if len(text) > 19 {
		for _, digit := range text[20:] {
			if digit < '0' || digit > '9' {
				return false
			}
		}
	}
	_, err := time.Parse("2006-01-02 15:04:05", text)
	return err == nil
}
