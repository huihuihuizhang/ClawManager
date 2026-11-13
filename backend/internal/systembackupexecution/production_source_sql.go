package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

type productionSQLSourceMetadata struct {
	DatabaseHostname         string                              `json:",omitempty"`
	CurrentStoppedProStorage map[int]currentStoppedProSQLStorage `json:",omitempty"`
	Schema                   domain.BusinessCaptureSchema
	Census                   domain.BusinessSchemaCensusObjects
	Images                   map[int]string
	WorkBuddy                map[int]domain.WorkBuddyUIDIdentity
}

func (x *originalSourceMetadataAuthority) sqlMetadata(ctx context.Context, source b.SourceInventory) (productionSQLSourceMetadata, error) {
	var zero productionSQLSourceMetadata
	if x.Recheck(ctx) != nil || x.service.Source == nil {
		return zero, d.ErrNotReady
	}
	tx, err := x.service.Source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, d.ErrNotReady
	}
	defer tx.Rollback()
	if x.service.checkSourceIdentity(ctx, tx) != nil {
		return zero, d.ErrNotReady
	}
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil || !reflect.DeepEqual(instances, source.Instances) {
		return zero, d.ErrNotReady
	}
	metadata, err := readProductionSQLMetadata(ctx, x.service, tx, instances)
	if err != nil || tx.Commit() != nil || x.Recheck(ctx) != nil {
		return zero, d.ErrNotReady
	}
	return metadata, nil
}

// Shared actual read-only SQL reader. Callers retain their own mandatory
// authority before and after this transaction; it cannot approve any task.
func readProductionSQLMetadata(ctx context.Context, s *DeploymentService, tx *sql.Tx, instances []b.InstanceIdentity) (productionSQLSourceMetadata, error) {
	var zero productionSQLSourceMetadata
	if s == nil || tx == nil || s.captureMaterials == nil || ctx == nil || ctx.Err() != nil {
		return zero, d.ErrNotReady
	}
	template := s.captureMaterials.Operations["capture-database"].Request.Database
	if template == nil || template.SchemaCensus == nil {
		return zero, d.ErrNotReady
	}
	census, err := domain.ObserveBusinessSchemaCensus(ctx, tx, *template.SchemaCensus)
	if err != nil {
		return zero, d.ErrNotReady
	}
	catalog, err := domain.Catalog(ctx, tx)
	if err != nil {
		return zero, d.ErrNotReady
	}
	schema, err := domain.BusinessCaptureSchemaForTables(catalog)
	if err != nil || !reflect.DeepEqual(schema.Tables, census.Business) {
		return zero, d.ErrNotReady
	}
	metadata := productionSQLSourceMetadata{Schema: schema, Census: census, Images: map[int]string{}, WorkBuddy: map[int]domain.WorkBuddyUIDIdentity{}}
	if s.Config.DatabaseWorkload != nil {
		if tx.QueryRowContext(ctx, "SELECT @@hostname").Scan(&metadata.DatabaseHostname) != nil || metadata.DatabaseHostname == "" {
			return zero, d.ErrNotReady
		}
	}
	byID := map[int]b.InstanceIdentity{}
	for _, instance := range instances {
		byID[instance.ID] = instance
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,os_version,image_registry,image_tag FROM instances ORDER BY id")
	if err != nil {
		return zero, d.ErrNotReady
	}
	for rows.Next() {
		var id int
		var osVersion, registry, tag *string
		if rows.Scan(&id, &osVersion, &registry, &tag) != nil || id <= 0 || byID[id].ID != id || metadata.Images[id] != "" || len(metadata.Images) >= 9998 {
			rows.Close()
			return zero, d.ErrNotReady
		}
		metadata.Images[id] = productionImageReference(byID[id], osVersion, registry, tag)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil || len(metadata.Images) != len(instances) {
		return zero, d.ErrNotReady
	}
	hasWorkBuddy := false
	for _, instance := range instances {
		hasWorkBuddy = hasWorkBuddy || workBuddyUIDSource(instance)
	}
	if hasWorkBuddy {
		contract := domain.WorkBuddyUIDSchema()
		foundIdentity, foundAllocator := false, false
		for _, table := range catalog {
			if table.Name == "workbuddy_linux_identities" {
				foundIdentity = domain.SchemaDigest(table) == contract.SHA256
			}
			if table.Name == "workbuddy_linux_identity_allocator" {
				foundAllocator = domain.SchemaDigest(table) == contract.AllocatorSHA256
			}
		}
		if !foundIdentity || !foundAllocator {
			return zero, d.ErrNotReady
		}
		rows, err = tx.QueryContext(ctx, "SELECT instance_id,user_id,linux_uid FROM workbuddy_linux_identities ORDER BY instance_id")
		if err != nil {
			return zero, d.ErrNotReady
		}
		seen := map[int]bool{}
		maximum := 0
		for rows.Next() {
			var identity domain.WorkBuddyUIDIdentity
			identity.Schema = 1
			if rows.Scan(&identity.InstanceID, &identity.UserID, &identity.UID) != nil || identity.InstanceID <= 0 || identity.UserID <= 0 || identity.UID < 10000 || identity.UID > 65533 || seen[identity.UID] || len(metadata.WorkBuddy) >= 100000 {
				rows.Close()
				return zero, d.ErrNotReady
			}
			identity.GID = identity.UID
			seen[identity.UID] = true
			metadata.WorkBuddy[identity.InstanceID] = identity
			if identity.UID > maximum {
				maximum = identity.UID
			}
		}
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			return zero, d.ErrNotReady
		}
		var count, id, next int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM workbuddy_linux_identity_allocator").Scan(&count) != nil || count != 1 || tx.QueryRowContext(ctx, "SELECT id,next_uid FROM workbuddy_linux_identity_allocator").Scan(&id, &next) != nil || id != 1 || next < 10000 || next > 65534 || next <= maximum {
			return zero, d.ErrNotReady
		}
		for _, instance := range instances {
			identity, exists := metadata.WorkBuddy[instance.ID]
			if workBuddyUIDSource(instance) {
				if !exists || identity.UserID != instance.UserID {
					return zero, d.ErrNotReady
				}
				var storage sql.NullString
				if tx.QueryRowContext(ctx, "SELECT workbuddy_storage_identity FROM instances WHERE id=?", instance.ID).Scan(&storage) != nil || storage.Valid {
					return zero, d.ErrNotReady
				}
			} else if exists {
				return zero, d.ErrNotReady
			}
		}
	}
	metadata.CurrentStoppedProStorage, err = readCurrentStoppedProSQLStorage(ctx, tx, instances, configuredRuntimeTestScope(s.Config))
	if err != nil {
		return zero, err
	}
	if s.checkSourceIdentity(ctx, tx) != nil || ctx.Err() != nil {
		return zero, d.ErrNotReady
	}
	return metadata, nil
}

// Keep the original nullable inputs and runtime tuple. In particular a NULL
// registry can select a variant default where an empty non-NULL registry does
// not. The independent source owner resolves defaults/managed settings into
// the immutable policy image; this reader never guesses a Docker reference.
type productionRuntimeImageSource struct {
	Version                  string
	Runtime                  scope.Runtime
	OSVersion, Registry, Tag *string
}

const productionRuntimeImageSourceVersion = "original-runtime-image-source.v1"

func productionImageReference(instance b.InstanceIdentity, osVersion, registry, tag *string) string {
	raw, _ := json.Marshal(productionRuntimeImageSource{Version: productionRuntimeImageSourceVersion, Runtime: scope.Runtime{Type: instance.Type, Mode: instance.Mode, Backend: instance.Backend, Variant: instance.Variant, OS: instance.OS}, OSVersion: osVersion, Registry: registry, Tag: tag})
	return string(raw)
}

func productionImageMatches(reference string, policy worker.RuntimePolicy, aliases map[string]string) bool {
	var source productionRuntimeImageSource
	if decodeMetadataCanonical([]byte(reference), &source) != nil || source.Version != productionRuntimeImageSourceVersion || source.Runtime != policy.Runtime {
		return false
	}
	// The original common buildRuntimeConfig branch accepts a full registry
	// reference only when the tag is absent/blank. A tag alone is never an image.
	if source.Registry != nil && strings.TrimSpace(*source.Registry) == policy.Image && (source.Tag == nil || strings.TrimSpace(*source.Tag) == "") {
		return true
	}
	return aliases[reference] == policy.Image
}

func productionInstanceSubPath(s *DeploymentService, instance b.InstanceIdentity) (string, error) {
	// This original installation profile already verifies all live PVC/NFS
	// aliases and nested mounts. It never substitutes a guessed source volume.
	root := s.Config.RuntimeSources.WorkspaceRoot
	if s.Config.Workspace.NFS != nil && len(s.Config.Workspace.NFS.OriginalPaths) > 0 {
		return originalNFSInstanceSubPath(s.Config.Workspace, root, instance)
	}
	if s.Config.Workspace.NFS != nil {
		root = path.Join(root, s.Config.Workspace.SubPath)
	}
	if root == "" || !strings.HasPrefix(instance.Workspace, root+"/") || path.Clean(instance.Workspace) != instance.Workspace {
		return "", d.ErrNotReady
	}
	return path.Join(s.Config.Workspace.SubPath, strings.TrimPrefix(instance.Workspace, root+"/")), nil
}
