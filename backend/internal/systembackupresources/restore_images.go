package systembackupresources

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type restoreImageKey struct{ InstanceType, RuntimeType, Variant string }

// These declarations are not B proofs. B must bind each exact source row/key to
// a non-sensitive name, available target image and an equivalence identity under
// the actual target collation AND runtime alias rules. A valid hash alone does
// not prove that any two different keys are distinct.
type restoreImageTarget struct {
	SourceID           int64
	SourceKey          restoreImageKey
	LogicalKeySHA256   string
	Image, DisplayName string
}
type restoreImageInput struct {
	Source              restoreFieldTable
	Targets             []restoreImageTarget
	OccupiedIDs         []int64
	OccupiedLogicalKeys []string
	Budget              restoreFieldBudget
}

// Private offline candidate only. No service/default/environment lookup, image
// pull, SQL write or activation is performed. IDs and historical times remain
// unchanged; image/name come only from the exact per-source target declaration.
func normalizeRestoreImages(ctx context.Context, input restoreImageInput) (restoreFieldTable, error) {
	if err := ctx.Err(); err != nil {
		return restoreFieldTable{}, err
	}
	if input.Source.Name != "system_image_settings" || input.Budget.Rows <= 0 || input.Budget.Bytes <= 0 {
		return restoreFieldTable{}, errors.New("resources image input is invalid")
	}
	var shape []restoreFieldTable
	for table, columns := range restoreFieldColumns() {
		entry := restoreFieldTable{Name: table, Columns: columns}
		if table == input.Source.Name {
			entry = input.Source
		}
		shape = append(shape, entry)
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return restoreFieldTable{}, err
	}
	if len(input.Targets) != len(input.Source.Rows) {
		return restoreFieldTable{}, errors.New("resources image target mapping is incomplete")
	}
	occupiedIDs := make(map[int64]bool, len(input.OccupiedIDs))
	for _, id := range input.OccupiedIDs {
		if !validRestoreID(restoreInstanceID, id) || occupiedIDs[id] {
			return restoreFieldTable{}, errors.New("resources image target occupancy is invalid")
		}
		occupiedIDs[id] = true
	}
	occupiedKeys := make(map[string]bool, len(input.OccupiedLogicalKeys))
	for _, key := range input.OccupiedLogicalKeys {
		if !sha256Pattern.MatchString(key) || occupiedKeys[key] {
			return restoreFieldTable{}, errors.New("resources image logical occupancy is invalid")
		}
		occupiedKeys[key] = true
	}
	targets := make(map[int64]restoreImageTarget, len(input.Targets))
	identities := make(map[string]bool, len(input.Targets))
	for _, target := range input.Targets {
		if !validRestoreID(restoreInstanceID, target.SourceID) || !sha256Pattern.MatchString(target.LogicalKeySHA256) || identities[target.LogicalKeySHA256] || occupiedKeys[target.LogicalKeySHA256] {
			return restoreFieldTable{}, errors.New("resources image logical mapping is invalid or occupied")
		}
		if _, duplicate := targets[target.SourceID]; duplicate {
			return restoreFieldTable{}, errors.New("resources image mapping is duplicated")
		}
		if !validRestoreImageText(target.DisplayName, 255, true) || !validRestoreImageText(target.Image, 500, true) || strings.Contains(target.Image, "://") {
			return restoreFieldTable{}, errors.New("resources image target projection is invalid")
		}
		for _, r := range target.Image {
			if unicode.IsSpace(r) {
				return restoreFieldTable{}, errors.New("resources image target projection is invalid")
			}
		}
		targets[target.SourceID] = target
		identities[target.LogicalKeySHA256] = true
	}
	result := restoreFieldTable{Name: input.Source.Name, Columns: append([]string(nil), input.Source.Columns...)}
	seenKeys := make(map[restoreImageKey]bool, len(input.Source.Rows))
	for _, source := range input.Source.Rows {
		if err := ctx.Err(); err != nil {
			return restoreFieldTable{}, err
		}
		id, _ := strconv.ParseInt(*source["id"], 10, 64)
		if occupiedIDs[id] {
			return restoreFieldTable{}, errors.New("resources image target ID is occupied")
		}
		key, err := restoreSourceImageKey(source)
		if err != nil {
			return restoreFieldTable{}, err
		}
		if seenKeys[key] {
			return restoreFieldTable{}, errors.New("resources image source logical key is duplicated")
		}
		seenKeys[key] = true
		target, exists := targets[id]
		if !exists || target.SourceKey != key {
			return restoreFieldTable{}, errors.New("resources image target mapping differs")
		}
		if source["image"] == nil || source["display_name"] == nil || !validRestoreImageText(*source["image"], 500, false) || !validRestoreImageText(*source["display_name"], 255, false) {
			return restoreFieldTable{}, errors.New("resources image source projection is invalid")
		}
		if source["is_enabled"] == nil || (*source["is_enabled"] != "0" && *source["is_enabled"] != "1") {
			return restoreFieldTable{}, errors.New("resources image source switch is invalid")
		}
		for _, column := range []string{"created_at", "updated_at"} {
			if !validRestoreAuditTime(source[column], false) {
				return restoreFieldTable{}, errors.New("resources image source time is invalid")
			}
		}
		row := cloneRestoreAuditRow(source)
		image, name, disabled := target.Image, target.DisplayName, "0"
		row["image"] = &image
		row["display_name"] = &name
		row["is_enabled"] = &disabled
		result.Rows = append(result.Rows, row)
	}
	for i := range shape {
		if shape[i].Name == result.Name {
			shape[i] = result
		}
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return restoreFieldTable{}, err
	}
	if err := ctx.Err(); err != nil {
		return restoreFieldTable{}, err
	}
	return result, nil
}

func restoreSourceImageKey(row restoreFieldRow) (restoreImageKey, error) {
	var key restoreImageKey
	for column, limit := range map[string]int{"instance_type": 50, "runtime_type": 7, "runtime_variant": 32} {
		if row[column] == nil || !validRestoreImageText(*row[column], limit, false) {
			return key, errors.New("resources image source key is invalid")
		}
	}
	key = restoreImageKey{*row["instance_type"], *row["runtime_type"], *row["runtime_variant"]}
	if key.InstanceType == "" || (key.RuntimeType != "desktop" && key.RuntimeType != "shell" && key.RuntimeType != "gateway") {
		return restoreImageKey{}, errors.New("resources image source key is unsupported")
	}
	return key, nil
}
func validRestoreImageText(text string, limit int, projection bool) bool {
	if !utf8.ValidString(text) || utf8.RuneCountInString(text) > limit {
		return false
	}
	if projection {
		if text == "" || strings.TrimSpace(text) != text {
			return false
		}
		for _, r := range text {
			if unicode.IsControl(r) {
				return false
			}
		}
	}
	return true
}
