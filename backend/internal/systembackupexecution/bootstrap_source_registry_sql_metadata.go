package systembackupexecution

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackupinstallationowner/install"
)

// Exact actual metadata projection from the existing pure source SQL helper.
// Only the private original-source reader/actual native SQL identity replaces
// its service parameter; old observer and clock source files are unchanged.
func (x *bootstrapSourceRegistryReader) readSourceSQLMetadata(ctx context.Context, tx *sql.Tx, instances []b.InstanceIdentity, binding install.BootstrapSourceConnection, verified *atomic.Bool, floor *time.Time) (productionSQLSourceMetadata, error) {
	var zero productionSQLSourceMetadata
	if x == nil || tx == nil || ctx == nil || ctx.Err() != nil || x.access.Check(x.ctx) != nil {
		return zero, install.ErrInstall
	}
	template := x.materials.Operations["capture-database"].Request.Database
	if template == nil || template.SchemaCensus == nil {
		return zero, install.ErrInstall
	}
	census, err := domain.ObserveBusinessSchemaCensus(ctx, tx, *template.SchemaCensus)
	if err != nil {
		return zero, install.ErrInstall
	}
	catalog, err := domain.Catalog(ctx, tx)
	if err != nil {
		return zero, install.ErrInstall
	}
	schema, err := domain.BusinessCaptureSchemaForTables(catalog)
	if err != nil || !reflect.DeepEqual(schema.Tables, census.Business) {
		return zero, install.ErrInstall
	}
	metadata := productionSQLSourceMetadata{Schema: schema, Census: census, Images: map[int]string{}, WorkBuddy: map[int]domain.WorkBuddyUIDIdentity{}}
	byID := map[int]b.InstanceIdentity{}
	for _, instance := range instances {
		byID[instance.ID] = instance
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,os_version,image_registry,image_tag FROM instances ORDER BY id")
	if err != nil {
		return zero, install.ErrInstall
	}
	for rows.Next() {
		var id int
		var osVersion, registry, tag *string
		if rows.Scan(&id, &osVersion, &registry, &tag) != nil || id <= 0 || byID[id].ID != id || metadata.Images[id] != "" || len(metadata.Images) >= 9998 {
			rows.Close()
			return zero, install.ErrInstall
		}
		metadata.Images[id] = productionImageReference(byID[id], osVersion, registry, tag)
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil || len(metadata.Images) != len(instances) {
		return zero, install.ErrInstall
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
			return zero, install.ErrInstall
		}
		rows, err = tx.QueryContext(ctx, "SELECT instance_id,user_id,linux_uid FROM workbuddy_linux_identities ORDER BY instance_id")
		if err != nil {
			return zero, install.ErrInstall
		}
		seen := map[int]bool{}
		maximum := 0
		for rows.Next() {
			var identity domain.WorkBuddyUIDIdentity
			identity.Schema = 1
			if rows.Scan(&identity.InstanceID, &identity.UserID, &identity.UID) != nil || identity.InstanceID <= 0 || identity.UserID <= 0 || identity.UID < 10000 || identity.UID > 65533 || seen[identity.UID] || len(metadata.WorkBuddy) >= 100000 {
				rows.Close()
				return zero, install.ErrInstall
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
			return zero, install.ErrInstall
		}
		var count, id, next int
		if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM workbuddy_linux_identity_allocator").Scan(&count) != nil || count != 1 || tx.QueryRowContext(ctx, "SELECT id,next_uid FROM workbuddy_linux_identity_allocator").Scan(&id, &next) != nil || id != 1 || next < 10000 || next > 65534 || next <= maximum {
			return zero, install.ErrInstall
		}
		for _, instance := range instances {
			identity, exists := metadata.WorkBuddy[instance.ID]
			if workBuddyUIDSource(instance) {
				if !exists || identity.UserID != instance.UserID {
					return zero, install.ErrInstall
				}
				var storage sql.NullString
				if tx.QueryRowContext(ctx, "SELECT workbuddy_storage_identity FROM instances WHERE id=?", instance.ID).Scan(&storage) != nil || storage.Valid {
					return zero, install.ErrInstall
				}
			} else if exists {
				return zero, install.ErrInstall
			}
		}
	}
	if x.checkSQLIdentity(ctx, tx, binding, verified, floor) != nil || ctx.Err() != nil {
		return zero, install.ErrInstall
	}
	return metadata, nil
}
