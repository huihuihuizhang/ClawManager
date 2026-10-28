package systembackupdispatch

// ValidateBackupSpec validates the explicit admitted task projection. It does
// not decode a create request, apply defaults, authorize resources or prove
// profile coverage. Partial parts require the original explicit test purpose.
func ValidateBackupSpec(b *BackupSpec) error {
	if b == nil || b.DatasourceTopology != "in_cluster" || (b.TaskPurpose != "acceptance" && b.TaskPurpose != "functional_test") || len(b.RequestedParts) == 0 || len(b.RequestedParts) > 6 {
		return ErrNotReady
	}
	want := ""
	switch b.SourceOrchestrator {
	case "kubernetes":
		if b.Runner != "k8s" {
			return ErrNotReady
		}
		want = "k8s-"
	case "k3s":
		if b.Runner != "k3s" {
			return ErrNotReady
		}
		want = "k3s-"
	default:
		return ErrNotReady
	}
	if (b.SourceProfile != "cluster" && b.SourceProfile != "single-node") || b.MatrixKey != want+b.SourceProfile {
		return ErrNotReady
	}
	seen := map[string]bool{}
	for _, part := range b.RequestedParts {
		switch part {
		case "mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle":
		default:
			return ErrNotReady
		}
		if seen[part] {
			return ErrNotReady
		}
		seen[part] = true
	}
	if b.TaskPurpose == "acceptance" && len(seen) != 6 {
		return ErrNotReady
	}
	return nil
}
