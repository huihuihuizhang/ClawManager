package install

import (
	"context"
	"database/sql"
	"path"
	"reflect"
	"strings"
	"time"

	backup "clawreef/internal/systembackup"
)

// This is an actual original SQL business-owner source, not an exemption for a
// bucket/prefix. Every accepted non-marker version must have the exact key,
// complete body SHA256 and byte length of a genuine current original SkillBlob.
// The original service computes ArchiveHash=SHA256(buildNormalizedZip bytes).
// Unreferenced/orphan/unsupported historical bodies remain unclassified.
type originalMinIOBusinessHistorySource struct {
	origin                               *originalMinIOBusinessHistorySource
	ctx                                  context.Context
	prep                                 *PreparedOriginalAdoptionSQLCut
	hold                                 *OriginalWriterHold
	selectionPin                         BootstrapSourceFilePin
	selection                            BootstrapSourceAuthoringSelection
	files                                []BootstrapSourceFilePin
	bucket, prefix, rowsSHA256, revision string
	rows                                 []originalSkillArchiveRow
	byKey                                map[string][]originalSkillArchiveRow
	until                                time.Time
	lockedTx                             *sql.Tx
	images                               *originalPreColdSQLImageHistory
}

type originalSkillArchiveRow struct {
	ID                                               uint64
	ContentHash, ArchiveSHA256, ObjectKey, MediaType string
	Size                                             int64
	CreatedAt, UpdatedAt                             time.Time
}

type originalBusinessSQLReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readOriginalSkillArchiveRows(ctx context.Context, view originalBusinessSQLReader, p *PreparedOriginalAdoptionSQLCut, lock bool) ([]originalSkillArchiveRow, error) {
	if view == nil || p == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInstall
	}
	var server, database string
	if view.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != p.database.ServerUUID || database != p.database.Database {
		return nil, ErrInstall
	}
	query := "SELECT id,content_hash,archive_hash,object_key,media_type,size_bytes,created_at,updated_at FROM skill_blobs ORDER BY id"
	if lock {
		query += " FOR SHARE"
	}
	rows, e := view.QueryContext(ctx, query)
	if e != nil {
		return nil, ErrInstall
	}
	defer rows.Close()
	result := []originalSkillArchiveRow{}
	var previous uint64
	for rows.Next() {
		var row originalSkillArchiveRow
		if rows.Scan(&row.ID, &row.ContentHash, &row.ArchiveSHA256, &row.ObjectKey, &row.MediaType, &row.Size, &row.CreatedAt, &row.UpdatedAt) != nil || row.ID == 0 || row.ID <= previous || row.Size < 0 || len(result) >= 100000 || row.CreatedAt.IsZero() || row.UpdatedAt.Before(row.CreatedAt) {
			return nil, ErrInstall
		}
		previous = row.ID
		result = append(result, row)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrInstall
	}
	return result, nil
}

func prepareOriginalMinIOBusinessHistory(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, external *originalProtectedMinIOArchive, selectionPin BootstrapSourceFilePin) (*originalMinIOBusinessHistorySource, error) {
	if p == nil || h == nil || h.set == nil || h.set.minioHistory == nil || external == nil || external.origin != external || external.hold != h || external.warm == nil || !consumerSameContext(ctx, p.ctx) || h.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	scope, e := readOriginalMinIOBusinessScope(ctx, h.set.minioHistory, external.warm, selectionPin)
	if e != nil {
		return nil, e
	}
	selected := scope.selection
	f := external.warm.facts
	if h.set.minioHistory.images == nil || h.set.minioHistory.images.origin != h.set.minioHistory.images || h.set.minioHistory.images.warm != external.warm || h.set.minioHistory.images.selection != selectionPin {
		return nil, ErrInstall
	}
	images := h.set.minioHistory.images
	if images.recheckSQL(ctx, p.operator.installer.db, false) != nil {
		return nil, ErrInstall
	}
	rows, e := readOriginalSkillArchiveRows(ctx, p.operator.installer.db, p, false)
	if e != nil {
		return nil, e
	}
	again, e := readOriginalSkillArchiveRows(ctx, p.operator.installer.db, p, false)
	if e != nil || !reflect.DeepEqual(rows, again) {
		return nil, ErrInstall
	}
	until := minTime(p.until, minTime(h.set.owner.until, minTime(external.until, selected.Until)))
	if d, ok := ctx.Deadline(); !ok {
		return nil, ErrInstall
	} else {
		until = minTime(until, d)
	}
	if time.Now().Before(selected.NotBefore) || !time.Now().Before(until) {
		return nil, ErrInstall
	}
	files := scope.files
	out := &originalMinIOBusinessHistorySource{ctx: ctx, prep: p, hold: h, selectionPin: selectionPin, selection: selected, files: files, bucket: scope.bucket, prefix: scope.prefix, rows: rows, rowsSHA256: originalObjectSHA(rows), byKey: map[string][]originalSkillArchiveRow{}, images: images, until: until}
	out.origin = out
	for _, row := range rows {
		if row.ObjectKey == "" {
			continue
		}
		// Match exactly the reviewed service's resolveObjectKey transformation;
		// do not guess a key from a prefix or enumerate only latest objects.
		key := strings.Trim(strings.TrimSpace(row.ObjectKey), "/")
		if key == "" || key != row.ObjectKey || path.IsAbs(key) || path.Clean(key) != key || key == "." || key == ".." || strings.HasPrefix(key, "../") || strings.ContainsAny(key, "\\\x00\r\n") {
			return nil, ErrInstall
		}
		key = out.prefix + key
		out.byKey[key] = append(out.byKey[key], row)
	}
	out.revision = originalObjectSHA(struct{ Version, Operation, Inventory, Selection, Material, SQL, Bucket, Prefix, Native, Images string }{"original-real-sql-skill-archive-ownership.v1", h.set.owner.operation, h.set.inventorySHA, selectionPin.SHA256, selected.MaterialsTemplate.SHA256, out.rowsSHA256, out.bucket, out.prefix, f.SnapshotSHA256, images.revision})
	if out.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	return out, nil
}

func (s *originalMinIOBusinessHistorySource) local(ctx context.Context) bool {
	return s != nil && s.origin == s && consumerSameContext(ctx, s.ctx) && ctx.Err() == nil && s.prep != nil && s.hold != nil && s.hold.set != nil && s.hold.set.owner != nil && !s.until.IsZero() && time.Now().Before(s.until) && s.rowsSHA256 == originalObjectSHA(s.rows) && s.revision != ""
}
func (s *originalMinIOBusinessHistorySource) recheckBeforeSQL(ctx context.Context) error {
	if !s.local(ctx) || s.lockedTx != nil || s.hold.recheckBeforeSQL(ctx) != nil {
		return ErrInstall
	}
	for _, pin := range s.files {
		limit := int64(262144)
		if pin == s.selection.MaterialsTemplate {
			limit = 8 << 20
		}
		raw, e := readBootstrapSourcePin(pin, limit)
		clear(raw)
		if e != nil {
			return ErrInstall
		}
	}
	if observeBootstrapSourceController(ctx, s.prep.operator.installer.kube, s.prep.operator.installer.plan.Target, s.selection.Controller) != nil {
		return ErrInstall
	}
	if s.images == nil || s.images.recheckSQL(ctx, s.prep.operator.installer.db, false) != nil {
		return ErrInstall
	}
	rows, e := readOriginalSkillArchiveRows(ctx, s.prep.operator.installer.db, s.prep, false)
	if e != nil || !reflect.DeepEqual(rows, s.rows) {
		return ErrInstall
	}
	return nil
}
func (s *originalMinIOBusinessHistorySource) lockOriginalSQL(ctx context.Context, tx *sql.Tx) error {
	if !s.local(ctx) || tx == nil || s.lockedTx != nil {
		return ErrInstall
	}
	rows, e := readOriginalSkillArchiveRows(ctx, tx, s.prep, true)
	if e != nil || !reflect.DeepEqual(rows, s.rows) {
		return ErrInstall
	}
	if s.images == nil || s.images.recheckSQL(ctx, tx, true) != nil {
		return ErrInstall
	}
	s.lockedTx = tx
	return nil
}
func (s *originalMinIOBusinessHistorySource) recheckLocked(ctx context.Context, tx *sql.Tx) error {
	if !s.local(ctx) || tx == nil || tx != s.lockedTx {
		return ErrInstall
	}
	if s.images == nil || s.images.recheckLockedSQL(ctx, tx) != nil {
		return ErrInstall
	}
	rows, e := readOriginalSkillArchiveRows(ctx, tx, s.prep, false)
	if e != nil || !reflect.DeepEqual(rows, s.rows) {
		return ErrInstall
	}
	return nil
}

func (s *originalMinIOBusinessHistorySource) classifyNativeObject(ctx context.Context, object backup.OriginalProtectedMinIOObject) (originalMinIOHistoryObjectClass, bool) {
	var zero originalMinIOHistoryObjectClass
	if !s.local(ctx) || object.Bucket != s.bucket {
		return zero, false
	}
	if s.images != nil && s.images.origin == s.images {
		for _, native := range s.images.objects {
			if native.Bucket != object.Bucket || native.Key != object.Key || native.VersionID != object.VersionID || native.Size != object.Size || native.DeleteMarker != object.DeleteMarker || native.BodySHA256 != object.BodySHA256 {
				continue
			}
			for _, row := range s.images.rows {
				if row.ID == native.ArtifactID && row.KeySHA256 == native.KeySHA256 && originalObjectSHA(row) == native.SQLRowSHA256 && object.Key == s.prefix+"gateway-images/"+row.ID {
					kind := "original_sql_gateway_image_actual_aead"
					if object.DeleteMarker {
						kind = "original_sql_gateway_image_delete_marker"
					}
					return originalMinIOHistoryObjectClass{object.Bucket, object.Key, object.VersionID, object.BodySHA256, kind, originalObjectSHA(struct{ Source, SQL, Native string }{s.revision, s.images.rowsSHA256, originalObjectSHA(native)})}, true
				}
			}
		}
	}
	owners := s.byKey[object.Key]
	if len(owners) == 0 {
		return zero, false
	}
	if object.DeleteMarker {
		if object.Size != 0 || object.BodySHA256 != "" {
			return zero, false
		}
		return originalMinIOHistoryObjectClass{object.Bucket, object.Key, object.VersionID, "", "original_sql_skill_archive_delete_marker", originalObjectSHA(struct {
			Revision string
			Owners   []originalSkillArchiveRow
		}{s.revision, owners})}, true
	}
	for _, owner := range owners {
		if digestPattern.MatchString(owner.ArchiveSHA256) && owner.ArchiveSHA256 == object.BodySHA256 && owner.Size == object.Size {
			return originalMinIOHistoryObjectClass{object.Bucket, object.Key, object.VersionID, object.BodySHA256, "original_sql_skill_archive_exact_body", originalObjectSHA(struct {
				Revision string
				Owner    originalSkillArchiveRow
			}{s.revision, owner})}, true
		}
	}
	return zero, false
}
