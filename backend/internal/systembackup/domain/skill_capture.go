package domain

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	sh "clawreef/internal/systembackupskillhub"
)

var skillCaptureColumns = map[string][]string{
	"skills":                         {"id", "user_id", "current_version_id"},
	"skill_blobs":                    {"id", "content_hash", "object_key", "size_bytes"},
	"skill_versions":                 {"id", "skill_id", "blob_id"},
	"instance_skills":                {"id", "instance_id", "skill_id", "skill_version_id", "workspace_dir", "observed_hash"},
	"skill_package_materialize_jobs": {"id", "instance_id", "skill_id", "blob_id", "workspace_dir", "content_hash"},
	"skill_scan_results":             {"id"}, "skill_hub_tags": {"id"}, "skill_hub_tag_assignments": {"id"},
}

// ReadSkillCaptureInventory shares the already authenticated discovery SQL RR
// transaction. It reads only finite identity/object/workspace projections;
// archive JSON, findings, history and every raw column remain in the later ONE
// atomic users/instances/Teams/Skills SQL capture.
func ReadSkillCaptureInventory(ctx context.Context, tx *sql.Tx, users map[int]bool, owners map[int]int) (sh.CaptureInventory, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return sh.CaptureInventory{}, ErrIsolation
	}
	tables, err := Catalog(ctx, tx)
	if err != nil {
		return sh.CaptureInventory{}, err
	}
	byName := map[string]Table{}
	for _, table := range tables {
		byName[table.Name] = table
	}
	var snapshot Snapshot
	var rowsTotal, bytesTotal int64
	for _, name := range sh.CaptureTableNames() {
		table, ok := byName[name]
		if !ok || table.Engine != "InnoDB" || len(table.PrimaryKey) != 1 || table.PrimaryKey[0] != "id" {
			return sh.CaptureInventory{}, ErrSchema
		}
		columns := skillCaptureColumns[name]
		quotedColumns := make([]string, len(columns))
		for n, column := range columns {
			quotedColumns[n] = "`" + column + "`"
		}
		rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(quotedColumns, ",")+" FROM `"+name+"` ORDER BY `id`")
		if err != nil {
			return sh.CaptureInventory{}, ErrDatabase
		}
		for rows.Next() {
			if ctx.Err() != nil {
				rows.Close()
				return sh.CaptureInventory{}, ErrIsolation
			}
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for n := range values {
				pointers[n] = &values[n]
			}
			if rows.Scan(pointers...) != nil {
				rows.Close()
				return sh.CaptureInventory{}, ErrDatabase
			}
			row := Row{}
			for n, value := range values {
				cell, err := rawCell(value)
				if err != nil {
					rows.Close()
					return sh.CaptureInventory{}, err
				}
				bytesTotal += int64(len(cell.Bytes)) + 128
				if bytesTotal > 8<<20 {
					rows.Close()
					return sh.CaptureInventory{}, ErrCapacity
				}
				row[columns[n]] = cell
			}
			rowsTotal++
			if rowsTotal > 100000 {
				rows.Close()
				return sh.CaptureInventory{}, ErrCapacity
			}
			table.Rows = append(table.Rows, row)
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil || closeErr != nil || ctx.Err() != nil {
			return sh.CaptureInventory{}, ErrDatabase
		}
		snapshot.Tables = append(snapshot.Tables, table)
	}
	return skillCaptureProjection(snapshot, users, owners)
}

// VerifySkillCapture compares the discovery identities/keyset to the actual
// raw tables captured in the shared SQL transaction. It neither accepts DTOs
// as a SQL dump nor opens another snapshot to approximate those rows.
func VerifySkillCapture(snapshot Snapshot, expected sh.CaptureInventory) error {
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	users, owners := map[int]bool{}, map[int]int{}
	for _, table := range snapshot.Tables {
		if table.Name != "users" && table.Name != "instances" {
			continue
		}
		for _, row := range table.Rows {
			id, err := skillCaptureInt(row, "id", false)
			if err != nil {
				return err
			}
			if table.Name == "users" {
				users[id] = true
			} else {
				owner, err := skillCaptureInt(row, "user_id", false)
				if err != nil {
					return err
				}
				owners[id] = owner
			}
		}
	}
	actual, err := skillCaptureProjection(snapshot, users, owners)
	if err != nil {
		return err
	}
	if actual.SHA256() != expected.SHA256() {
		return ErrData
	}
	return nil
}

func skillCaptureProjection(snapshot Snapshot, users map[int]bool, owners map[int]int) (sh.CaptureInventory, error) {
	result := sh.CaptureInventory{Version: sh.CaptureInventoryVersion, Tables: []sh.CaptureTableKeys{}, Skills: []sh.CaptureSkill{}, Blobs: []sh.CaptureBlob{}, Versions: []sh.CaptureVersion{}, Bindings: []sh.CaptureBinding{}, Jobs: []sh.CaptureMaterializeJob{}}
	tables := map[string]Table{}
	for _, table := range snapshot.Tables {
		if _, wanted := skillCaptureColumns[table.Name]; wanted {
			if _, exists := tables[table.Name]; exists {
				return sh.CaptureInventory{}, ErrSchema
			}
			tables[table.Name] = table
		}
	}
	for _, name := range sh.CaptureTableNames() {
		table, ok := tables[name]
		if !ok {
			return sh.CaptureInventory{}, ErrSchema
		}
		columns := map[string]bool{}
		for _, column := range table.Columns {
			columns[column.Name] = true
		}
		for _, required := range skillCaptureColumns[name] {
			if !columns[required] {
				return sh.CaptureInventory{}, ErrSchema
			}
		}
		keys := sh.CaptureTableKeys{Name: name, SchemaSHA256: SchemaDigest(table), IDs: []int{}}
		for _, row := range table.Rows {
			id, err := skillCaptureInt(row, "id", false)
			if err != nil {
				return sh.CaptureInventory{}, err
			}
			keys.IDs = append(keys.IDs, id)
			integer := func(column string, optional bool) int {
				value, e := skillCaptureInt(row, column, optional)
				if e != nil {
					err = e
				}
				return value
			}
			switch name {
			case "skills":
				result.Skills = append(result.Skills, sh.CaptureSkill{ID: id, UserID: integer("user_id", false), CurrentVersionID: integer("current_version_id", true)})
			case "skill_blobs":
				size, e := strconv.ParseInt(row["size_bytes"].String(), 10, 64)
				if e != nil || size < 0 {
					return sh.CaptureInventory{}, ErrData
				}
				result.Blobs = append(result.Blobs, sh.CaptureBlob{ID: id, ContentHash: row["content_hash"].String(), ObjectKey: row["object_key"].String(), SizeBytes: size})
			case "skill_versions":
				result.Versions = append(result.Versions, sh.CaptureVersion{ID: id, SkillID: integer("skill_id", false), BlobID: integer("blob_id", false)})
			case "instance_skills":
				result.Bindings = append(result.Bindings, sh.CaptureBinding{ID: id, InstanceID: integer("instance_id", false), SkillID: integer("skill_id", false), SkillVersionID: integer("skill_version_id", true), WorkspaceDir: row["workspace_dir"].String(), ObservedHash: row["observed_hash"].String()})
			case "skill_package_materialize_jobs":
				result.Jobs = append(result.Jobs, sh.CaptureMaterializeJob{ID: id, InstanceID: integer("instance_id", false), SkillID: integer("skill_id", false), BlobID: integer("blob_id", false), WorkspaceDir: row["workspace_dir"].String(), ContentHash: row["content_hash"].String()})
			}
			if err != nil {
				return sh.CaptureInventory{}, err
			}
		}
		sort.Ints(keys.IDs)
		result.Tables = append(result.Tables, keys)
	}
	sort.Slice(result.Skills, func(i, j int) bool { return result.Skills[i].ID < result.Skills[j].ID })
	sort.Slice(result.Blobs, func(i, j int) bool { return result.Blobs[i].ID < result.Blobs[j].ID })
	sort.Slice(result.Versions, func(i, j int) bool { return result.Versions[i].ID < result.Versions[j].ID })
	sort.Slice(result.Bindings, func(i, j int) bool { return result.Bindings[i].ID < result.Bindings[j].ID })
	sort.Slice(result.Jobs, func(i, j int) bool { return result.Jobs[i].ID < result.Jobs[j].ID })
	if result.Validate(users, owners) != nil {
		return sh.CaptureInventory{}, ErrData
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 8<<20 {
		return sh.CaptureInventory{}, ErrCapacity
	}
	return result, nil
}
func skillCaptureInt(row Row, column string, optional bool) (int, error) {
	cell, exists := row[column]
	if !exists {
		return 0, ErrSchema
	}
	if cell.Null && optional {
		return 0, nil
	}
	value, err := strconv.ParseInt(cell.String(), 10, 32)
	if err != nil || value < 1 {
		return 0, ErrData
	}
	return int(value), nil
}
