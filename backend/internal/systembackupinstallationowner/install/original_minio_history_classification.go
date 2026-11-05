package install

import (
	"bytes"
	"context"
	"sort"
)

// Logical classification is separate from physical inclusion in an encrypted
// raw archive. Each accepted native version needs actual source provenance.
type originalMinIOHistoryObjectClass struct {
	Bucket, Key, VersionID, BodySHA256, Kind, SourceSHA256 string
}

type originalUnclassifiedMinIOVersion struct {
	Bucket, Key, VersionID string
	DeleteMarker           bool
}

// This closed profile admits genuine C1/catalog and exact original SQL-owned
// skill archive and AEAD image versions/markers from the private actual business source. Every
// unsupported/orphan/foreign version remains unclassified and refuses adoption;
// a configured prefix or a raw archive never substitutes for logical ownership.
func (r *originalMixedHistorySource) classifyActualOriginalMinIOObjects(ctx context.Context, installed *OriginalRuntimeC1Installed, directory string) error {
	if r == nil || r.origin != r || installed == nil || installed.origin != installed || installed.production == nil || !consumerSameContext(ctx, installed.ctx) || r.retained == nil || r.retained.receipt == nil || r.retained.receipt.receipt.Snapshot.C1 == nil || r.business == nil || !r.business.local(ctx) || privateDirectory(directory) != nil {
		return ErrInstall
	}
	facts := r.external.warm.facts
	objects := map[string]int{}
	matched := map[int]bool{}
	for index, object := range facts.Objects {
		key := object.Bucket + "\x00" + object.Key + "\x00" + object.VersionID
		if _, duplicate := objects[key]; duplicate {
			return ErrInstall
		}
		objects[key] = index
	}
	for _, source := range r.retained.receipt.receipt.Snapshot.C1.Sources {
		store, record := source.NativeStore, source.Record
		if store.Installation != r.prep.reservation.InstallationID || store.Endpoint != facts.Endpoint || store.Region != facts.Region || store.CASHA256 != facts.CASHA256 || record.Ref.Identity != store.Identity || record.Ref.Version != store.Version {
			return ErrInstall
		}
		index, found := objects[store.Bucket+"\x00"+record.Ref.RelativeKey+"\x00"+record.Ref.ImmutableVersion]
		if !found || matched[index] {
			return ErrInstall
		}
		actual := facts.Objects[index]
		if actual.DeleteMarker || actual.Size != record.Manifest.ObjectSize || actual.BodySHA256 != record.Manifest.ObjectHash {
			return ErrInstall
		}
		matched[index] = true
		r.objectClasses = append(r.objectClasses, originalMinIOHistoryObjectClass{actual.Bucket, actual.Key, actual.VersionID, actual.BodySHA256, "original_c1_retained_evidence", originalObjectSHA(source)})
	}
	catalogs := 0
	for _, batch := range append([]*OriginalC1SigningProduction{installed.production}, installed.production.children...) {
		if batch == nil || batch.origin != batch || batch.run == nil || batch.run.native == nil {
			return ErrInstall
		}
		native := batch.run.native
		if native.kind != "catalog-original-immutable-initial-checkpoint" {
			continue
		}
		if native.origin != native || native.parent != installed.production.run.parent || native.catalog == nil || len(native.catalogEnvelope) == 0 {
			return ErrInstall
		}
		location := native.catalog
		actualEnvelope, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: location.EnvelopeFile, SHA256: location.EnvelopeSHA256}, 4096)
		var signed SignedCatalogInitialInventory
		if e != nil || !bytes.Equal(actualEnvelope, native.catalogEnvelope) || decodeExact(actualEnvelope, &signed) != nil {
			return ErrInstall
		}
		record, e := InspectCatalogInitialInventory(signed, r.prep.operator.installer.public)
		if e != nil || record.Installation != r.prep.reservation.InstallationID || record.NamespaceUID != facts.NamespaceUID || record.Bucket != location.Bucket || record.Key != location.Key || record.DefinitionSHA256 != location.DefinitionSHA256 || record.ConfigSHA256 != installed.production.run.parent.request.config.SHA256() || record.Count != 0 {
			return ErrInstall
		}
		foundReference := false
		for _, reference := range installed.production.run.parent.request.config.References() {
			if reference == record.Reference {
				foundReference = true
			}
		}
		if !foundReference {
			return ErrInstall
		}
		index, found := objects[location.Bucket+"\x00"+location.Key+"\x00"+location.VersionID]
		if !found || matched[index] {
			return ErrInstall
		}
		actual := facts.Objects[index]
		if actual.DeleteMarker || actual.Size != int64(len(actualEnvelope)) || actual.BodySHA256 != hash(actualEnvelope) {
			return ErrInstall
		}
		// The real signed object is public catalog JSON, not an unexplained
		// encrypted payload. No fictitious KEK reference is created for it.
		matched[index] = true
		catalogs++
		r.objectClasses = append(r.objectClasses, originalMinIOHistoryObjectClass{actual.Bucket, actual.Key, actual.VersionID, actual.BodySHA256, "original_signed_empty_catalog_checkpoint", location.EnvelopeSHA256})
	}
	if catalogs != 1 {
		return ErrInstall
	}
	// Actual original SQL business ownership is separate from C1/catalog. Each
	// full native version is considered, including old versions and markers;
	// a configured bucket/prefix alone never classifies a body.
	for index, object := range facts.Objects {
		if matched[index] {
			continue
		}
		if class, owned := r.business.classifyNativeObject(ctx, object); owned {
			matched[index] = true
			r.objectClasses = append(r.objectClasses, class)
		}
	}
	unknown := make([]originalUnclassifiedMinIOVersion, 0)
	for index, object := range facts.Objects {
		if !matched[index] {
			unknown = append(unknown, originalUnclassifiedMinIOVersion{object.Bucket, object.Key, object.VersionID, object.DeleteMarker})
		}
	}
	if len(unknown) != 0 {
		// Private fixed-name actual inventory retained for source-owner review;
		// do not print original keys/object names to ordinary CLI diagnostics.
		raw, e := canonical(struct {
			Version, Operation, SnapshotSHA256 string
			Objects                            []originalUnclassifiedMinIOVersion
		}{"original-unclassified-minio-versions.v1", r.prep.reservation.OperationID, facts.SnapshotSHA256, unknown})
		if e != nil || writeNewFiles(directory, map[string][]byte{"unclassified-original-minio-versions.json": raw}) != nil {
			return ErrInstall
		}
		return ErrInstall
	}
	sort.Slice(r.objectClasses, func(i, j int) bool {
		a, b := r.objectClasses[i], r.objectClasses[j]
		if a.Bucket != b.Bucket {
			return a.Bucket < b.Bucket
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.VersionID < b.VersionID
	})
	return nil
}
