package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/scope"
)

// ConfigNormalizer is supplied by the shared versioned Secret/config registry.
// It must preserve definitions while stubbing credentials and disabling outbound
// actions. An absent adapter cannot be replaced with an identity function.
type ConfigNormalizer interface {
	NormalizeConfig(context.Context, string, string, Cell) (Cell, error)
}
type Placement struct {
	Workspace, MountPath, PVC, Namespace, StorageClass string
}
type Policy struct {
	Placements     map[string]Placement // source instance ID -> observed drill storage
	Configs        ConfigNormalizer
	WorkBuddy      *WorkBuddySchema
	Dependencies   map[string]TableAdapter
	TeamPlacements map[string]Placement // separately restored/verified Team shared volumes
}
type RestorePlan struct {
	Data             Snapshot
	Users, Instances int
}

// Explicit versioned column inventory. New model fields do not automatically
// become safe to restore just because they acquired a Go struct tag.
var columns = map[string]string{
	"users":                         "id username email password_hash role is_active created_at updated_at last_login auth_provider login_alias external_id",
	"user_quotas":                   "id user_id max_instances max_cpu_cores max_memory_gb max_storage_gb max_gpu_count created_at updated_at",
	"instances":                     "id user_id owner name alias description type runtime_type runtime_variant instance_mode status cpu_cores memory_gb disk_gb gpu_enabled gpu_type gpu_count os_type os_version image_registry image_tag environment_overrides_json storage_class pvc_name mount_path workspace_path workspace_usage_bytes runtime_generation runtime_error_message provisioning_operation_id pod_name pod_namespace pod_ip access_url access_token agent_bootstrap_token openclaw_config_snapshot_id created_at updated_at started_at stopped_at workbuddy_storage_identity",
	"persistent_volumes":            "id instance_id pvc_name pvc_namespace storage_size_gb storage_class mount_path status created_at updated_at",
	"backup_schedules":              "id instance_id schedule_name cron_expression retention_days is_active created_at updated_at",
	"instance_usage":                "id instance_id cpu_usage_percent memory_usage_gb disk_usage_gb gpu_usage_percent uptime_seconds recorded_at",
	"instance_desired_state":        "id instance_id desired_power_state desired_config_revision_id desired_runtime_action updated_by updated_at created_at",
	"instance_browser_workers":      "instance_id enabled status resource_profile display_width display_height retain_profile browser_image cdp_proxy_image generation observed_generation last_error created_at updated_at",
	"instance_commands":             "id instance_id agent_id command_type payload_json status idempotency_key issued_by issued_at dispatched_at started_at finished_at timeout_seconds result_json error_message created_at updated_at",
	"instance_config_revisions":     "id instance_id source_snapshot_id source_bundle_id revision_no content_json checksum status published_by published_at activated_at created_at updated_at",
	"instance_external_access":      "id instance_id enabled auth_mode public_slug public_token_hash short_code_hash api_key_hash password_value api_key_prefix expires_at created_by last_used_at created_at updated_at",
	"workspace_file_audits":         "id instance_id user_id action relative_path bytes created_at",
	"openclaw_config_resources":     "id user_id resource_type resource_key name description enabled version tags_json content_json created_at updated_at",
	"openclaw_config_bundles":       "id user_id name description enabled version created_at updated_at",
	"openclaw_config_bundle_items":  "id bundle_id resource_id sort_order required created_at",
	"openclaw_config_bundle_skills": "id bundle_id skill_id sort_order required created_at",
	"openclaw_injection_snapshots":  "id instance_id user_id mode bundle_id selected_resource_ids_json resolved_resources_json rendered_manifest_json rendered_env_json secret_name status error_message created_at updated_at activated_at",
	"enterprise_auth_settings":      "id provider enabled allow_local_fallback sync_role ldap_host ldap_port ldap_use_tls ldap_start_tls ldap_skip_tls_verify ldap_tls_ca_file ldap_tls_server_name ldap_bind_dn ldap_bind_password_ciphertext ldap_base_dn ldap_user_filter ldap_username_attribute ldap_email_attribute ldap_group_base_dn ldap_group_filter ldap_admin_group_dns ldap_default_role version updated_by created_at updated_at",
}

func validateSnapshot(s Snapshot) error {
	if s.Version != Version {
		return ErrSchema
	}
	seen := map[string]bool{}
	known := rules()
	for _, t := range s.Tables {
		if _, ok := known[t.Name]; !ok || seen[t.Name] || t.Engine != "InnoDB" || len(t.Columns) == 0 || len(t.PrimaryKey) == 0 {
			return ErrSchema
		}
		seen[t.Name] = true
		cols := map[string]Column{}
		for _, c := range t.Columns {
			if !identifier.MatchString(c.Name) {
				return ErrSchema
			}
			if _, ok := cols[c.Name]; ok {
				return ErrSchema
			}
			cols[c.Name] = c
		}
		keys := map[string]bool{}
		for _, r := range t.Rows {
			if len(r) != len(cols) {
				return ErrData
			}
			for name, c := range cols {
				v, ok := r[name]
				if !ok || (v.Null && (!c.Nullable || len(v.Bytes) > 0)) {
					return ErrData
				}
			}
			var key string
			for _, k := range t.PrimaryKey {
				v, ok := r[k]
				if !ok || v.Null {
					return ErrData
				}
				key += strconv.Itoa(len(v.Bytes)) + ":" + v.String()
			}
			if keys[key] {
				return ErrData
			}
			keys[key] = true
		}
	}
	if !seen["users"] || !seen["instances"] || !seen["user_quotas"] {
		return ErrSchema
	}
	return nil
}

// Normalize is pure with respect to source/target databases. Source rows remain
// untouched for encrypted archival; only the returned plan contains drill data.
func Normalize(ctx context.Context, source Snapshot, target []Table, policy Policy) (RestorePlan, error) {
	if err := validateSnapshot(source); err != nil {
		return RestorePlan{}, err
	}
	if policy.WorkBuddy.uidLayout() {
		if err := validateWorkBuddyUID(source, policy.WorkBuddy); err != nil {
			return RestorePlan{}, err
		}
	}
	if err := validateRelationshipsWithHistory(source, policy.WorkBuddy.uidLayout()); err != nil {
		return RestorePlan{}, err
	}
	if err := validateWorkBuddy(source, policy.WorkBuddy); err != nil {
		return RestorePlan{}, err
	}
	targets := map[string]Table{}
	for _, t := range target {
		if _, ok := targets[t.Name]; ok {
			return RestorePlan{}, ErrSchema
		}
		targets[t.Name] = t
	}
	if policy.WorkBuddy.uidLayout() {
		if err := validateWorkBuddyUIDTarget(targets, policy.WorkBuddy); err != nil {
			return RestorePlan{}, err
		}
	}
	plan := RestorePlan{Data: Snapshot{Version: Version}}
	registry := rules()
	for _, t := range source.Tables {
		if err := ctx.Err(); err != nil {
			return RestorePlan{}, err
		}
		rule := registry[t.Name]
		preserveAllocator := t.Name == workBuddyAllocator && policy.WorkBuddy.uidLayout()
		if rule.RestoreAction == "drop" || (rule.RestoreAction == "reference_only" && !preserveAllocator) || t.Name == "instance_agents" || t.Name == "instance_runtime_status" {
			continue
		}
		// Empty tables absent on the target need no writes. Nonempty unknown
		// identity schemas require a deliberate version adapter, not field loss.
		if len(t.Rows) == 0 && !(policy.WorkBuddy.uidLayout() && t.Name == workBuddyIdentities) {
			continue
		}
		dest, ok := targets[t.Name]
		if !ok || dest.Engine != "InnoDB" {
			return RestorePlan{}, ErrSchema
		}
		allowed := map[string]bool{}
		for _, c := range strings.Fields(columns[t.Name]) {
			allowed[c] = true
		}
		for _, c := range strings.Fields(dependencyColumns[t.Name]) {
			allowed[c] = true
		}
		for _, c := range strings.Fields(teamColumns[t.Name]) {
			allowed[c] = true
		}
		for _, c := range strings.Fields(crossDomainColumns[t.Name]) {
			allowed[c] = true
		}
		adapter, adapted := policy.Dependencies[t.Name]
		if adapted {
			if rule.Domain == scope.Users || rule.Domain == scope.Instances || adapter.validate(t) != nil || adapter.validate(dest) != nil {
				return RestorePlan{}, ErrSchema
			}
			for c := range adapter.Columns {
				allowed[c] = true
			}
		}
		if t.Name == "workbuddy_linux_identities" {
			var err error
			allowed, err = policy.WorkBuddy.columns(t)
			if err != nil || SchemaDigest(dest) != policy.WorkBuddy.SHA256 {
				return RestorePlan{}, ErrSchema
			}
		}
		if preserveAllocator {
			allowed = map[string]bool{"id": true, "next_uid": true}
		}
		targetCols := map[string]Column{}
		for _, c := range dest.Columns {
			targetCols[c.Name] = c
			if !allowed[c.Name] {
				return RestorePlan{}, ErrSchema
			}
		}
		for _, c := range t.Columns {
			d, ok := targetCols[c.Name]
			if !allowed[c.Name] || !ok || c.Type != d.Type || strings.Contains(strings.ToUpper(d.Extra), "GENERATED") {
				return RestorePlan{}, ErrSchema
			}
		}
		out := t
		out.Rows = nil
		out.ForeignKeys = dest.ForeignKeys
		// Explicit legacy users adaptation: source did not have auth_provider.
		if t.Name == "users" {
			if c, ok := targetCols["auth_provider"]; ok && !hasColumn(t, "auth_provider") {
				out.Columns = append(append([]Column(nil), t.Columns...), c)
			}
		}
		for _, c := range dest.Columns {
			// Do not silently introduce a new target default (possibly an
			// executable state). Only absent nullable NULL columns are harmless.
			if !hasColumn(out, c.Name) && (!c.Nullable || c.Default != nil) {
				return RestorePlan{}, ErrSchema
			}
		}
		for _, r := range t.Rows {
			n := cloneRow(r)
			if adapted {
				if err := applyAdapter(ctx, n, adapter); err != nil {
					return RestorePlan{}, err
				}
			}
			if t.Name == "users" && hasColumn(out, "auth_provider") && !hasColumn(t, "auth_provider") {
				n["auth_provider"] = Text("local")
			}
			if err := normalizeRow(ctx, t.Name, n, policy); err != nil {
				return RestorePlan{}, err
			}
			for _, c := range out.Columns {
				if n[c.Name].Null && !targetCols[c.Name].Nullable {
					return RestorePlan{}, ErrSchema
				}
			}
			out.Rows = append(out.Rows, n)
		}
		if t.Name == "users" {
			plan.Users = len(out.Rows)
		}
		if t.Name == "instances" {
			plan.Instances = len(out.Rows)
		}
		plan.Data.Tables = append(plan.Data.Tables, out)
	}
	if err := validateDependencyLinks(plan.Data); err != nil {
		return RestorePlan{}, err
	}
	ordered, err := sortedTables(plan.Data.Tables)
	if err != nil {
		return RestorePlan{}, err
	}
	plan.Data.Tables = ordered
	return plan, nil
}
func hasColumn(t Table, name string) bool {
	for _, c := range t.Columns {
		if c.Name == name {
			return true
		}
	}
	return false
}
func set(r Row, name string, value Cell) {
	if _, ok := r[name]; ok {
		r[name] = value
	}
}
func clearFields(r Row, names string) {
	for _, n := range strings.Fields(names) {
		set(r, n, Cell{Null: true})
	}
}

func normalizeRow(ctx context.Context, table string, r Row, p Policy) error {
	normalizeCrossDomain(table, r)
	if err := normalizeTeam(table, r, p); err != nil {
		return err
	}
	switch table {
	case "llm_models":
		set(r, "is_active", Text("0"))
		set(r, "api_key", Text("drill-disabled"))
		clearFields(r, "api_key_secret_ref")
		set(r, "base_url", Text("https://disabled.invalid"))
	case "chat_messages":
		clearFields(r, "invocation_id")
	case "skills", "skill_blobs":
		clearFields(r, "last_scan_result_id last_scanned_at")
	case "instance_skills":
		clearFields(r, "install_path last_seen_at")
		set(r, "status", Text("removed"))
	case "users":
		set(r, "last_login", Cell{Null: true})
	case "instances":
		placement, ok := p.Placements[r["id"].String()]
		if !ok || !safeRoot(placement.Workspace) || !safeRoot(placement.MountPath) || placement.Namespace == "" {
			return ErrNormalization
		}
		set(r, "status", Text("stopped"))
		set(r, "workspace_path", Text(placement.Workspace))
		set(r, "mount_path", Text(placement.MountPath))
		set(r, "storage_class", Text(placement.StorageClass))
		clearFields(r, "pvc_name pod_name pod_namespace pod_ip access_url access_token agent_bootstrap_token runtime_error_message provisioning_operation_id started_at stopped_at")
		if placement.PVC != "" {
			set(r, "pvc_name", Text(placement.PVC))
		}
		set(r, "runtime_generation", Text("1"))
	case "persistent_volumes":
		v, ok := p.Placements[r["instance_id"].String()]
		if !ok || v.PVC == "" || v.Namespace == "" {
			return ErrNormalization
		}
		set(r, "pvc_name", Text(v.PVC))
		set(r, "pvc_namespace", Text(v.Namespace))
		set(r, "storage_class", Text(v.StorageClass))
		set(r, "mount_path", Text(v.MountPath))
		set(r, "status", Text("bound"))
	case "enterprise_auth_settings":
		set(r, "enabled", Text("0"))
		set(r, "allow_local_fallback", Text("1"))
		set(r, "ldap_bind_password_ciphertext", Text(""))
		set(r, "ldap_host", Text(""))
	case "backup_schedules":
		set(r, "is_active", Text("0"))
	case "instance_desired_state":
		set(r, "desired_power_state", Text("stopped"))
		clearFields(r, "desired_runtime_action")
	case "instance_browser_workers":
		set(r, "enabled", Text("0"))
		set(r, "status", Text("disabled"))
		set(r, "generation", Text("1"))
		set(r, "observed_generation", Text("0"))
		clearFields(r, "last_error")
	case "instance_commands":
		// History remains in the artifact. Target records are terminal even if
		// a scheduler accidentally reads them after the drill.
		switch r["status"].String() {
		case "succeeded", "failed", "cancelled":
		case "pending", "dispatched", "running":
			set(r, "status", Text("failed"))
			set(r, "error_message", Text("disabled by isolated restore"))
		default:
			return ErrNormalization
		}
		clearFields(r, "agent_id")
	case "instance_external_access":
		set(r, "enabled", Text("0"))
		clearFields(r, "public_slug public_token_hash short_code_hash api_key_hash password_value api_key_prefix expires_at last_used_at")
	case "openclaw_config_resources", "openclaw_config_bundles":
		set(r, "enabled", Text("0"))
	case "openclaw_injection_snapshots":
		set(r, "status", Text("archived"))
		clearFields(r, "secret_name activated_at")
	case "instance_config_revisions":
		set(r, "status", Text("archived"))
		clearFields(r, "activated_at")
	}
	for _, column := range []string{"environment_overrides_json", "content_json", "resolved_resources_json", "rendered_manifest_json", "rendered_env_json", "payload_json", "result_json", "spec_json", "artifact_refs_json", "manifest_json", "provider_models_json", "request_payload", "response_payload", "quick_analyzers_json", "deep_analyzers_json", "scope_json", "summary_json"} {
		v, ok := r[column]
		if !ok || v.Null || len(v.Bytes) == 0 {
			continue
		}
		if p.Configs == nil {
			return ErrNormalization
		}
		n, err := p.Configs.NormalizeConfig(ctx, table, column, v)
		if err != nil {
			return ErrNormalization
		}
		r[column] = n
	}
	if table == "instance_config_revisions" {
		if v, ok := r["content_json"]; ok && !v.Null {
			sum := sha256.Sum256(v.Bytes)
			set(r, "checksum", Text("sha256:"+hex.EncodeToString(sum[:])))
		}
	}
	return nil
}
func safeRoot(s string) bool {
	return path.IsAbs(s) && s != "/" && path.Clean(s) == s && !strings.ContainsAny(s, "\\\x00\r\n:")
}

func validateRelationships(s Snapshot) error {
	return validateRelationshipsWithHistory(s, false)
}
func validateRelationshipsWithHistory(s Snapshot, validatedUIDHistory bool) error {
	users := map[string]bool{}
	instances := map[string]bool{}
	admin := false
	for _, t := range s.Tables {
		if t.Name != "users" {
			continue
		}
		for _, r := range t.Rows {
			id := r["id"].String()
			if !positiveID(id) || users[id] {
				return ErrData
			}
			users[id] = true
			provider := r["auth_provider"].String()
			if provider != "" && provider != "local" && provider != "ldap" {
				return ErrData
			}
			if (provider == "" || provider == "local") && len(r["password_hash"].Bytes) == 0 {
				return ErrData
			}
			if r["username"].String() == "admin" && r["role"].String() == "admin" && r["is_active"].String() == "1" {
				admin = true
			}
		}
	}
	if !admin {
		return ErrData
	}
	for _, t := range s.Tables {
		if t.Name != "instances" {
			continue
		}
		for _, r := range t.Rows {
			id := r["id"].String()
			if !positiveID(id) || instances[id] || !users[r["user_id"].String()] {
				return ErrData
			}
			instances[id] = true
			_, err := scope.PlanRuntime(scope.Runtime{Type: r["type"].String(), Mode: r["instance_mode"].String(), Backend: r["runtime_type"].String(), Variant: r["runtime_variant"].String(), OS: r["os_type"].String()})
			if err != nil {
				return err
			}
		}
	}
	for _, t := range s.Tables {
		for _, r := range t.Rows {
			if validatedUIDHistory && t.Name == workBuddyIdentities {
				continue
			}
			if v, ok := r["user_id"]; ok && !v.Null && !users[v.String()] {
				return ErrData
			}
			if v, ok := r["instance_id"]; ok && !v.Null && !instances[v.String()] {
				return ErrData
			}
		}
	}
	return nil
}
func positiveID(s string) bool {
	v, e := strconv.ParseInt(s, 10, 64)
	return e == nil && v > 0 && strconv.FormatInt(v, 10) == s
}
