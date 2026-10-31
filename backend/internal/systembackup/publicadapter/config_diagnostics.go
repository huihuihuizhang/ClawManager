package publicadapter

// Diagnostics contain fixed codes/field names and numeric source IDs only.
// Never include request values, snapshot digests, errors, paths, refs or secrets.
type ModuleConfigIssue struct {
	Code       string `json:"code"`
	Field      string `json:"field"`
	Receiver   string `json:"receiver"`
	InstanceID int    `json:"instance_id,omitempty"`
	MountIndex int    `json:"mount_index"` // -1 for non-mount issues
}

type ModuleConfigDiagnostics struct {
	Issues    []ModuleConfigIssue `json:"issues"`
	Truncated bool                `json:"truncated"`
}

const MaxModuleConfigIssues = 128

// DiagnoseUsersInstancesConfig is bounded local configuration preflight. An
// empty result is NOT admission, provenance verification, release approval or
// proof that storage/writers are complete. NewUsersInstancesModule remains the
// constructor authority; task/context/Job checks still run in BuildParts.
func DiagnoseUsersInstancesConfig(cfg UsersInstancesModuleConfig) ModuleConfigDiagnostics {
	out := ModuleConfigDiagnostics{Issues: []ModuleConfigIssue{}}
	add := func(code, field, receiver string, id, index int) {
		if len(out.Issues) >= MaxModuleConfigIssues {
			out.Truncated = true
			return
		}
		if id <= 0 || id > 2147483647 {
			id = 0
		}
		out.Issues = append(out.Issues, ModuleConfigIssue{code, field, receiver, id, index})
	}
	if len(cfg.Source.Users) > 100000 || len(cfg.Source.Instances) > 9998 || len(cfg.Workspaces) > 9999 {
		add("capacity_exceeded", "config", "B", 0, -1)
		return out
	}
	if cfg.Revision == "" {
		add("required", "revision", "B", 0, -1)
	}
	if cfg.Source.Database == "" {
		add("required", "source.database", "D", 0, -1)
	}
	if cfg.Source.ServerUUID == "" {
		add("required", "source.server_uuid", "D", 0, -1)
	}
	if len(cfg.Source.Users) == 0 {
		add("required", "source.users", "D", 0, -1)
	}
	database := cfg.Database.Invocation.Request.Database
	if database == nil {
		add("required", "database.invocation.database", "D", 0, -1)
	} else {
		if database.Name != cfg.Source.Database || database.ServerUUID != cfg.Source.ServerUUID {
			add("source_mismatch", "database.invocation.database", "D", 0, -1)
		}
		if database.Address == "" {
			add("required", "database.invocation.database.address", "D", 0, -1)
		}
		if database.TLSServerName == "" || len(database.RootCA) == 0 {
			add("required", "database.invocation.database.tls", "A", 0, -1)
		}
		if database.MaxRows <= 0 || database.MaxMemoryBytes <= 0 {
			add("invalid_limits", "database.invocation.database.limits", "B", 0, -1)
		}
	}
	checkWork := func(r CapturePartRequest, prefix string, id, index int) {
		if r.Generation == 0 {
			add("required", prefix+".generation", "D", id, index)
		}
		if r.Workload.Image == "" || !immutableImage.MatchString(r.Workload.Image) {
			add("immutable_image_required", prefix+".workload.image", "D", id, index)
		}
		if r.Workload.ServiceAccount == "" {
			add("required", prefix+".workload.service_account", "A", id, index)
		}
		if r.Workload.StagingClaim == "" {
			add("required", prefix+".workload.staging_claim", "D", id, index)
		}
		control := r.Workload.WorkerControl
		if control == nil {
			add("required", prefix+".workload.worker_control", "D", id, index)
		} else {
			if !control.BoundPodIdentity {
				add("pod_binding_required", prefix+".workload.worker_control.bound_pod_identity", "A", id, index)
			}
			if control.URL == "" || control.InvocationConfigMap == "" || control.IdentitySecret == "" {
				add("required", prefix+".workload.worker_control.refs", "D", id, index)
			}
		}
		b := r.Invocation.Request.Binding
		if b.BackupID == "" || b.Attempt == "" || b.Path == "" || b.EnvelopeID == "" || !hexHash.MatchString(b.CaptureContextHash) {
			add("binding_required", prefix+".invocation.binding", "D", id, index)
		}
		if r.Invocation.Request.Deadline.IsZero() {
			add("required", prefix+".invocation.deadline", "D", id, index)
		}
		if r.Invocation.Request.ArtifactName == "" {
			add("required", prefix+".invocation.artifact_name", "B", id, index)
		}
	}
	checkWork(cfg.Database, "database", 0, -1)
	instances := map[int]InstanceIdentity{}
	for _, i := range cfg.Source.Instances {
		instances[i.ID] = i
	}
	primary := map[int]bool{}
	outputs := map[string]bool{}
	output := func(r CapturePartRequest, id, index int) {
		names := []string{r.Invocation.Request.ArtifactName}
		if r.Invocation.FormalCapture != nil {
			names = append(names, r.Invocation.FormalCapture.EnvelopeName)
		}
		for _, name := range names {
			key := r.Workload.Identity.Namespace + "/" + r.Workload.StagingClaim + "/" + name
			if outputs[key] {
				add("output_collision", "workspaces.request.invocation.artifact_name", "B", id, index)
			}
			outputs[key] = true
		}
	}
	output(cfg.Database, 0, -1)
	for n, m := range cfg.Workspaces {
		if out.Truncated {
			break
		}
		i, exists := instances[m.InstanceID]
		if !exists {
			add("unknown_instance", "workspaces.instance_id", "D", m.InstanceID, n)
		}
		if m.MountID == "workspace" {
			primary[m.InstanceID] = true
		}
		checkWork(m.Request, "workspaces.request", m.InstanceID, n)
		output(m.Request, m.InstanceID, n)
		v := m.Request.Workload.Source
		validSource := v.Name != "" && ((v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName != "") || (v.NFS != nil && v.NFS.Server != "" && v.NFS.Path != "") || (v.HostPath != nil && v.HostPath.Path != "" && m.Request.Workload.NodeName != ""))
		if !validSource {
			add("source_mount_required", "workspaces.request.workload.source", "D", m.InstanceID, n)
		}
		p := m.Request.Invocation.Request.RuntimePolicy
		if p == nil || p.Validate() != nil {
			add("runtime_policy_required", "workspaces.request.invocation.runtime_policy", "B", m.InstanceID, n)
		}
		if isWorkBuddySource(i) {
			identity := m.Request.Invocation.Request.WorkBuddyIdentity
			if identity == nil {
				add("workbuddy_identity_required", "workspaces.request.invocation.workbuddy_identity", "B", m.InstanceID, n)
			} else if identity.Schema != 1 || identity.UserID != i.UserID || identity.InstanceID != i.ID || identity.UID < 10000 || identity.UID > 65533 || identity.GID != identity.UID {
				add("workbuddy_identity_mismatch", "workspaces.request.invocation.workbuddy_identity", "B", m.InstanceID, n)
			}
		} else if m.Request.Invocation.Request.WorkBuddyIdentity != nil {
			add("workbuddy_identity_mismatch", "workspaces.request.invocation.workbuddy_identity", "B", m.InstanceID, n)
		}
	}
	for _, i := range cfg.Source.Instances {
		if !primary[i.ID] {
			add("primary_mount_required", "workspaces", "D", i.ID, -1)
		}
		if out.Truncated {
			break
		}
	}
	// Preserve the original constructor's strict validation. Do not replicate
	// its schema/release/coverage rules into a looser diagnostic-only authority.
	if !out.Truncated && len(out.Issues) == 0 {
		if _, err := NewUsersInstancesModule(cfg); err != nil {
			add("module_config_invalid", "config", "B", 0, -1)
		}
	}
	return out
}
