package systembackupoffline

import (
	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/worker"
	adapter "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// TemplateDocument emits empty DTOs with protocol/purpose constants only.
// Missing authority, UIDs, keys, versions, hashes and timestamps stay missing.
// It never signs, fills a fake identity or sets a scan-completion bit.
func TemplateDocument(kind string) (any, error) {
	t, b := Templates()
	switch kind {
	case "trust":
		return t, nil
	case "bundle":
		return b, nil
	case "secret-policy":
		return root.SecretCapturePolicy{SchemaVersion: root.SecretCapturePolicyVersion, RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []root.SecretCapturePolicyEntry{{Required: true}}}, nil
	case "signing-record":
		r := sec.InstallationSigningRecord{}
		for _, p := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
			r.Keys = append(r.Keys, sec.ArtifactSigningPublicKey{Purpose: p})
			r.Permissions = append(r.Permissions, sec.InstallationSigningPermission{Binding: sec.TransitSigningBinding{Purpose: p}})
		}
		return r, nil
	case "source-grant":
		return worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion}, nil
	case "original-kek-record":
		return adapter.OriginalRecord{}, nil
	case "coverage-inventory":
		return reg.Snapshot{}, nil
	case "source-rules":
		return RulesMaterial{}, nil
	case "source-sql":
		return SQLMaterial{}, nil
	case "capability-policy":
		return sec.CapabilityPolicy{}, nil
	default:
		return nil, ErrInput
	}
}
