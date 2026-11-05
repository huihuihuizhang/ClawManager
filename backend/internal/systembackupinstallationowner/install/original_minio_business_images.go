package install

import (
	backup "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	"context"
	"database/sql"
	"encoding/json"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"
)

type originalMinIOBusinessScope struct {
	selection      BootstrapSourceAuthoringSelection
	bucket, prefix string
	files          []BootstrapSourceFilePin
}

func readOriginalMinIOBusinessScope(ctx context.Context, r *originalMinIOHistoryLifecycle, warm *OriginalProtectedMinIOWarmHistory, selectionPin BootstrapSourceFilePin) (originalMinIOBusinessScope, error) {
	var zero originalMinIOBusinessScope
	if r == nil || r.set == nil || r.set.minioHistory != r || r.set.owner == nil || warm == nil || warm.origin != warm || warm.set != r.set || !consumerSameContext(ctx, warm.ctx) || r.warm != warm {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(selectionPin, 262144)
	var selected BootstrapSourceAuthoringSelection
	if e != nil || decodeExact(raw, &selected) != nil || validateBootstrapSourceAuthoring(selected, r.set.owner.operator.installer.plan.Target) != nil || selected.ApplicationScope != r.set.selection.ApplicationScope {
		return zero, ErrInstall
	}
	selectedRaw, e := json.Marshal(selected)
	var material struct{ SourceSelectionSHA256 string }
	sourceRaw, se := readBootstrapSourcePin(r.material, 262144)
	if e != nil || se != nil || json.Unmarshal(sourceRaw, &material) != nil || material.SourceSelectionSHA256 != hash(selectedRaw) {
		return zero, ErrInstall
	}
	// This is the same original native reader/controller and actual producer
	// selection that constructed the gate materials, not new bucket arguments.
	if observeBootstrapSourceController(ctx, r.set.owner.operator.installer.kube, r.set.owner.operator.installer.plan.Target, selected.Controller) != nil {
		return zero, ErrInstall
	}
	raw, e = readBootstrapSourcePin(selected.MaterialsTemplate, 8<<20)
	var m struct {
		Version, InstallationID, DeploymentConfigSHA256, SkillBucket, SkillPrefix string
		Objects                                                                   worker.FormalSourceMount
	}
	if e != nil || json.Unmarshal(raw, &m) != nil || m.Version != "original-six-part-capture-materials.v1" || m.InstallationID != r.set.owner.operator.installer.plan.Target.InstallationID || m.DeploymentConfigSHA256 != selected.Deployment.SHA256 || m.Objects.Objects == nil || m.SkillBucket == "" || m.SkillPrefix == "" || path.IsAbs(m.SkillPrefix) || path.Clean(m.SkillPrefix) != m.SkillPrefix || m.SkillPrefix == "." || m.SkillPrefix == ".." || strings.HasPrefix(m.SkillPrefix, "../") || strings.ContainsAny(m.SkillPrefix, "\\*?\x00\r\n") || len(m.Objects.ObjectPrefixes) != 1 || m.Objects.ObjectPrefixes[0].Bucket != m.SkillBucket || m.Objects.ObjectPrefixes[0].Prefix != m.SkillPrefix+"/" {
		return zero, ErrInstall
	}
	f := warm.facts
	if f.Endpoint != "https://"+m.Objects.Objects.Address || f.CASHA256 != m.Objects.Objects.CASHA256 {
		return zero, ErrInstall
	}
	foundObjects, foundSQL := false, false
	for _, c := range selected.Connections {
		if c.Purpose == "source_objects" {
			if foundObjects || c.Endpoint != f.Endpoint || c.CA.SHA256 != f.CASHA256 || c.CA.File != m.Objects.Objects.CAFile {
				return zero, ErrInstall
			}
			foundObjects = true
		}
		if c.Purpose == "source_sql" {
			if foundSQL || c.ServerUUID != r.set.owner.operator.installer.plan.Target.ServerUUID || c.Database != r.set.owner.operator.installer.plan.Target.Database {
				return zero, ErrInstall
			}
			foundSQL = true
		}
	}
	if !foundObjects || !foundSQL {
		return zero, ErrInstall
	}
	foundBucket := false
	for _, bucket := range f.Buckets {
		foundBucket = foundBucket || bucket.Name == m.SkillBucket
	}
	if !foundBucket {
		return zero, ErrInstall
	}

	files := []BootstrapSourceFilePin{selectionPin, selected.MaterialsTemplate, selected.Deployment, selected.ExecutionProfile}
	for _, c := range selected.Connections {
		files = append(files, c.CA, c.Credential)
	}
	return originalMinIOBusinessScope{selected, m.SkillBucket, m.SkillPrefix + "/", files}, nil
}

type originalGatewayImageSQLRow struct {
	ID                              string
	UserID, ModelID                 uint64
	InstanceID, GatewayKeyID        sql.NullInt64
	RequestID, MediaType, KeySHA256 string
	ByteSize                        int64
	Ready                           bool
	CreatedAt, ExpiresAt            time.Time
	key                             []byte // NEVER canonicalized, written or returned; cleared after native AEAD
}

func clearOriginalGatewayImageKeys(rows []originalGatewayImageSQLRow) {
	for _, row := range rows {
		clear(row.key)
	}
}
func readOriginalGatewayImageSQLRows(ctx context.Context, view originalBusinessSQLReader, i *Installer, lock bool) ([]originalGatewayImageSQLRow, error) {
	if ctx == nil || view == nil || i == nil {
		return nil, ErrInstall
	}
	var server, database string
	if view.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != i.plan.Target.ServerUUID || database != i.plan.Target.Database {
		return nil, ErrInstall
	}
	query := "SELECT id,user_id,instance_id,gateway_key_id,model_id,request_id,media_type,byte_size,encryption_key,ready,created_at,expires_at FROM gateway_image_artifacts ORDER BY id"
	if lock {
		query += " FOR SHARE"
	}
	result := []originalGatewayImageSQLRow{}
	success := false
	defer func() {
		if !success {
			clearOriginalGatewayImageKeys(result)
		}
	}()
	rows, e := view.QueryContext(ctx, query)
	if e != nil {
		return nil, ErrInstall
	}
	defer rows.Close()
	previous := ""
	idPattern := regexp.MustCompile(`^img_[a-f0-9]{32}$`)
	for rows.Next() {
		var row originalGatewayImageSQLRow
		if rows.Scan(&row.ID, &row.UserID, &row.InstanceID, &row.GatewayKeyID, &row.ModelID, &row.RequestID, &row.MediaType, &row.ByteSize, &row.key, &row.Ready, &row.CreatedAt, &row.ExpiresAt) != nil {
			clear(row.key)
			return nil, ErrInstall
		}
		if !idPattern.MatchString(row.ID) || row.ID <= previous || row.UserID == 0 || row.ModelID == 0 || row.ByteSize <= 0 || row.ByteSize > 16<<20 || len(row.key) != 32 || row.CreatedAt.IsZero() || !row.ExpiresAt.After(row.CreatedAt) || len(result) >= 100000 {
			clear(row.key)
			return nil, ErrInstall
		}
		row.KeySHA256 = hash(row.key)
		result = append(result, row)
		previous = row.ID
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrInstall
	}
	success = true
	return result, nil
}

type originalPreColdSQLImageHistory struct {
	origin               *originalPreColdSQLImageHistory
	ctx                  context.Context
	lifecycle            *originalMinIOHistoryLifecycle
	warm                 *OriginalProtectedMinIOWarmHistory
	selection            BootstrapSourceFilePin
	scope                originalMinIOBusinessScope
	rows                 []originalGatewayImageSQLRow
	rowsSHA256, revision string
	correspondence       *backup.OriginalGatewayImageHistoryCorrespondence
	objects              []backup.OriginalGatewayImageVersionCorrespondence
}

// Real original SQL keys are used ONLY before ordinary MinIO stops. The native
// source returns sealed data correspondence, not SQL ownership; later actual
// cold owner independently reads and range-locks the complete ORIGINAL rows.
func (r *originalMinIOHistoryLifecycle) prepareOriginalGatewayImageHistory(ctx context.Context, warm *OriginalProtectedMinIOWarmHistory) (*originalPreColdSQLImageHistory, error) {
	var zero *originalPreColdSQLImageHistory
	if r == nil || r.check(ctx) != nil || warm == nil || warm != r.warm {
		return zero, ErrInstall
	}
	scope, e := readOriginalMinIOBusinessScope(ctx, r, warm, r.businessSelection)
	if e != nil {
		return nil, e
	}
	i := r.set.owner.operator.installer
	rows, e := readOriginalGatewayImageSQLRows(ctx, i.db, i, false)
	if e != nil {
		return nil, e
	}
	defer clearOriginalGatewayImageKeys(rows)
	again, e := readOriginalGatewayImageSQLRows(ctx, i.db, i, false)
	if e != nil {
		return nil, e
	}
	defer clearOriginalGatewayImageKeys(again)
	if !sameOriginalImageSQLMetadata(rows, again) {
		return nil, ErrInstall
	}
	requests := []backup.OriginalGatewayImageSQLRequest{}
	for _, row := range rows {
		requests = append(requests, backup.OriginalGatewayImageSQLRequest{ArtifactID: row.ID, SQLRowSHA256: originalObjectSHA(row), PlaintextSize: row.ByteSize, Key: row.key})
	}
	native, e := warm.protected.InspectOriginalGatewayImageHistory(ctx, scope.bucket, scope.prefix, requests)
	if e != nil {
		return nil, e
	}
	objects, e := native.OriginalImageHistoryData(ctx, warm.protected)
	if e != nil {
		return nil, e
	}
	out := &originalPreColdSQLImageHistory{ctx: ctx, lifecycle: r, warm: warm, selection: r.businessSelection, scope: scope, rows: rows, rowsSHA256: originalObjectSHA(rows), correspondence: native, objects: objects}
	out.origin = out
	out.revision = originalObjectSHA(struct{ Version, Operation, Inventory, Selection, SQL, Native string }{"original-real-sql-gateway-image-aead-history.v1", r.set.owner.operation, r.set.inventorySHA, r.businessSelection.SHA256, out.rowsSHA256, originalObjectSHA(objects)})
	if warm.protected.RecheckProtectedBeforeCold(ctx) != nil || r.check(ctx) != nil {
		return nil, ErrInstall
	}
	return out, nil
}
func sameOriginalImageSQLMetadata(a, b []originalGatewayImageSQLRow) bool {
	// Key bytes are never public; exact SHA256 commits them and every real row
	// field. Canonical metadata ignores the private raw key buffers by design.
	return originalObjectSHA(a) == originalObjectSHA(b)
}
func (s *originalPreColdSQLImageHistory) recheckSQL(ctx context.Context, view originalBusinessSQLReader, lock bool) error {
	if s == nil || s.origin != s || !consumerSameContext(ctx, s.ctx) || s.lifecycle == nil || s.warm == nil || s.lifecycle.images != s || s.correspondence == nil || s.rowsSHA256 != originalObjectSHA(s.rows) {
		return ErrInstall
	}
	rows, e := readOriginalGatewayImageSQLRows(ctx, view, s.lifecycle.set.owner.operator.installer, lock)
	if e != nil {
		return ErrInstall
	}
	defer clearOriginalGatewayImageKeys(rows)
	if !sameOriginalImageSQLMetadata(rows, s.rows) {
		return ErrInstall
	}
	if !lock {
		objects, e := s.correspondence.OriginalImageHistoryData(ctx, s.warm.protected)
		if e != nil || !reflect.DeepEqual(objects, s.objects) {
			return ErrInstall
		}
	}
	return nil
}

func (s *originalPreColdSQLImageHistory) recheckLockedSQL(ctx context.Context, tx *sql.Tx) error {
	if s == nil || s.origin != s || !consumerSameContext(ctx, s.ctx) || tx == nil || s.lifecycle == nil || s.lifecycle.images != s || s.rowsSHA256 != originalObjectSHA(s.rows) {
		return ErrInstall
	}
	rows, e := readOriginalGatewayImageSQLRows(ctx, tx, s.lifecycle.set.owner.operator.installer, false)
	if e != nil {
		return ErrInstall
	}
	defer clearOriginalGatewayImageKeys(rows)
	if !sameOriginalImageSQLMetadata(rows, s.rows) {
		return ErrInstall
	}
	return nil
}
