package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	c "clawreef/internal/systembackupcontroller"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// These are existing file/directory coordinates and recovery policy choices.
// No caller supplies Deployment/Pod/Node UIDs, source rows, an observed native
// result, permission JSON, a held flag, epoch, inventory hash or capture head.
type OriginalWriterSelectionOptions struct {
	RuntimeStartupImages                                  BootstrapSourceFilePin
	runtimeStartupInputs                                  []OriginalRuntimeStartupImageInput
	runtimeStartupProfiles                                map[string]*originalRuntimeStartupImage
	DeploymentConfig, ObserverDefinition, ObserverReceipt BootstrapSourceFilePin
	GatewayOriginalKey                                    BootstrapSourceFilePin
	GatewayOriginalDirectory, JournalDirectory            string
	ParticipantWriters                                    map[string]string
	Policy                                                c.GatePolicy
}

type OriginalWriterSelectionReceipt struct {
	Version, State                                 string
	Selection                                      BootstrapSourceFilePin
	SourceCoordinates                              BootstrapSourceFilePin
	SourceCount, DeploymentCount, ParticipantCount int
}

// Operational coordinates derived from the same complete original owner
// reads. These are not a held writer, freshness proof, source grant, or native
// completion DTO. Downstream owners must authenticate and re-read every source.
type OriginalInitialSourceCoordinates struct {
	Version, InstallationID, Namespace, NamespaceUID, ApplicationScope string
	WriterSelection                                                    BootstrapSourceFilePin
	Instances                                                          []domain.SourceInstance
	Deployments                                                        []OriginalDeploymentSelection
	Participants                                                       []OriginalMaintenanceParticipant
	RuntimeStartupImages                                               []OriginalRuntimeStartupImageInput
	Volumes                                                            []originalPhysicalVolumePin
	Census                                                             originalMaintenanceKubernetesCensus
	Storage                                                            []OriginalInitialInstanceStorage `json:",omitempty"`
	StoppedProLayouts                                                  []OriginalStoppedProSelection    `json:",omitempty"`
	NodeUIDs                                                           map[string]string                `json:",omitempty"`
	ApplicationScopes                                                  []string                         `json:",omitempty"`
	SharedRuntime                                                      originalSharedRuntimeSQL
	Layouts                                                            []OriginalInitialSourceLayout     `json:",omitempty"`
	Dependencies                                                       []OriginalInitialSourceDependency `json:",omitempty"`
}

// This finite projection is ordinary SOURCE configuration, not a final Forward
// grant, enabled config, signed source observation or reconstructed Pod spec.
type originalWriterSourceConfig struct {
	InstallationID   string `json:"installation_id"`
	Namespace        string `json:"namespace"`
	NamespaceUID     string `json:"namespace_uid"`
	ApplicationScope string `json:"application_scope"`
	RuntimeSources   *struct {
		SharedRuntimeProtocol    string                        `json:"shared_runtime_protocol,omitempty"`
		WorkspaceRoot            string                        `json:"workspace_root"`
		AgentTokenFile           string                        `json:"agent_token_file"`
		AgentCAFile              string                        `json:"agent_ca_file"`
		AgentCASHA256            string                        `json:"agent_ca_sha256"`
		CurrentStoppedProLayouts []OriginalStoppedProSelection `json:"current_stopped_pro_layouts"`
	} `json:"runtime_sources"`
}

// ProduceOriginalWriterSelection creates the complete base selection from TWO
// actual original SQL/Kubernetes reads. It neither opens a maintenance journal
// nor acquires a gate, invokes a native writer or manufactures stop evidence.
// The real PrepareOriginalWriterSet consumer repeats its unfiltered census and
// native preflight. Native Redis/MinIO keeper and kept-Vault material producers
// must augment this base through their real producer actions before adoption.
func (i *Installer) ProduceOriginalWriterSelection(ctx context.Context, password []byte, enrollment EnrollmentPin, options OriginalWriterSelectionOptions, directory string) (OriginalWriterSelectionReceipt, error) {
	var zero OriginalWriterSelectionReceipt
	if i == nil || ctx == nil || ctx.Err() != nil || options.Policy.Validate() != nil || privateDirectory(directory) != nil || privateDirectory(options.JournalDirectory) != nil || filepath.Clean(directory) == filepath.Clean(options.JournalDirectory) {
		return zero, ErrInstall
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrInstall
	}
	for _, d := range []string{directory, options.JournalDirectory} {
		entries, e := os.ReadDir(d)
		if e != nil || len(entries) != 0 {
			return zero, ErrInstall
		}
	}
	p, err := i.PrepareOriginalWriterMaintenance(ctx, password, enrollment, options.Policy)
	if err != nil {
		return zero, err
	}
	configRaw, err := readBootstrapSourcePin(options.DeploymentConfig, 262144)
	var config originalWriterSourceConfig
	if err != nil || json.Unmarshal(configRaw, &config) != nil || config.InstallationID != i.plan.Target.InstallationID || config.Namespace != i.plan.Target.Namespace || config.NamespaceUID != i.plan.Target.NamespaceUID || config.ApplicationScope == "" || len(config.ApplicationScope) > 128 {
		return zero, ErrInstall
	}
	options.runtimeStartupInputs, err = loadOriginalRuntimeImageInputs(ctx, options.RuntimeStartupImages)
	if err != nil {
		return zero, OriginalWriterSourceFailure{Dependency: "runtime_authenticated_startup_image_inputs_required"}
	}
	options.runtimeStartupProfiles, err = readOriginalRuntimeImageSet(ctx, options.runtimeStartupInputs)
	if err != nil {
		return zero, err
	}
	first, firstCensus, firstVolumes, err := p.collectOriginalWriterSelection(ctx, options, config)
	if err != nil {
		return zero, err
	}
	last, lastCensus, lastVolumes, err := p.collectOriginalWriterSelection(ctx, options, config)
	if err != nil || !reflect.DeepEqual(first, last) || !reflect.DeepEqual(firstCensus, lastCensus) || !reflect.DeepEqual(firstVolumes, lastVolumes) || p.checkInstances(ctx) != nil || p.check(ctx) != nil {
		return zero, ErrInstall
	}
	// Only this real source inventory determines the generated recovery keys.
	// A post-export failure leaves material for review, never a partly admitted
	// selection or a fabricated original journal. Existing files are not repaired.
	files := map[string][]byte{}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	for n := range last.RunningPro {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			clear(key)
			return zero, ErrInstall
		}
		name := originalSelectionProKeyName(last.RunningPro[n].InstanceID)
		files[name] = key
		last.RunningPro[n].RecoveryKey = BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(key)}
	}
	raw, err := canonical(last)
	if err != nil || len(raw) > 262144 {
		return zero, ErrInstall
	}
	files["original-writer-selection.json"] = raw
	coordinates := OriginalInitialSourceCoordinates{Version: "original-initial-source-coordinates.v1", InstallationID: i.plan.Target.InstallationID,
		Namespace: i.plan.Target.Namespace, NamespaceUID: i.plan.Target.NamespaceUID, ApplicationScope: last.ApplicationScope,
		WriterSelection: BootstrapSourceFilePin{File: filepath.Join(directory, "original-writer-selection.json"), SHA256: hash(raw)},
		Instances:       append([]domain.SourceInstance(nil), p.instances...), Deployments: last.Deployments, Participants: last.Participants,
		RuntimeStartupImages: options.runtimeStartupInputs, Volumes: lastVolumes, Census: lastCensus}
	coordinateRaw, err := canonical(coordinates)
	if err != nil || len(coordinateRaw) > 8<<20 {
		return zero, ErrInstall
	}
	files["original-source-coordinates.json"] = coordinateRaw
	// Re-read all externally selected bytes immediately before writing. The
	// receipt itself is DATA; it cannot extend this original authority/window.
	if originalRuntimeInputDefinitionStill(options.RuntimeStartupImages, options.runtimeStartupInputs) != nil || originalSelectionPinStill(options.DeploymentConfig, configRaw) != nil || p.check(ctx) != nil || p.checkInstances(ctx) != nil || writeNewFiles(directory, files) != nil {
		return zero, ErrInstall
	}
	for name, expected := range files {
		var actual []byte
		var e error
		if name == "original-source-coordinates.json" {
			actual, e = ReadSourceMaterialFile(filepath.Join(directory, name))
		} else {
			actual, e = ReadPrivateFile(filepath.Join(directory, name), int64(len(expected)+1))
		}
		same := e == nil && bytes.Equal(actual, expected)
		clear(actual)
		if !same {
			return zero, ErrInstall
		}
	}
	// A final fresh full read follows export. Generated Pro keys are normalized
	// away only for comparison; the consumer independently checks the real pins.
	after, afterCensus, afterVolumes, err := p.collectOriginalWriterSelection(ctx, options, config)
	if err != nil || !reflect.DeepEqual(first, after) || !reflect.DeepEqual(firstCensus, afterCensus) || !reflect.DeepEqual(firstVolumes, afterVolumes) || originalSelectionPinStill(options.DeploymentConfig, configRaw) != nil || p.checkInstances(ctx) != nil || p.check(ctx) != nil {
		return zero, ErrInstall
	}
	return OriginalWriterSelectionReceipt{Version: "original-writer-selection-materials.v1", State: "actual_original_complete_base_selection_materialized_no_hold", Selection: BootstrapSourceFilePin{File: filepath.Join(directory, "original-writer-selection.json"), SHA256: hash(raw)}, SourceCoordinates: BootstrapSourceFilePin{File: filepath.Join(directory, "original-source-coordinates.json"), SHA256: hash(coordinateRaw)}, SourceCount: len(p.instances), DeploymentCount: len(last.Deployments), ParticipantCount: len(last.Participants)}, nil
}

func originalSelectionPinStill(pin BootstrapSourceFilePin, expected []byte) error {
	raw, err := readBootstrapSourcePin(pin, 262144)
	defer clear(raw)
	if err != nil || !bytes.Equal(raw, expected) {
		return ErrInstall
	}
	return nil
}

func (p *OriginalWriterMaintenance) collectOriginalWriterSelection(ctx context.Context, options OriginalWriterSelectionOptions, config originalWriterSourceConfig) (OriginalWriterSetSelection, originalMaintenanceKubernetesCensus, []originalPhysicalVolumePin, error) {
	var zero OriginalWriterSetSelection
	census, pods, deployments, _, err := p.readKubernetesCensus(ctx)
	if err != nil {
		return zero, census, nil, err
	}
	if len(census.StatefulSets)+len(census.DaemonSets)+len(census.Jobs)+len(census.CronJobs)+len(census.Autoscalers) != 0 {
		return zero, census, nil, OriginalWriterSourceFailure{Dependency: "complete_non_deployment_reconciler_gate_required"}
	}
	s := OriginalWriterSetSelection{RuntimeStartupImages: append([]OriginalRuntimeStartupImageInput{}, options.runtimeStartupInputs...), Version: OriginalWriterSetSelectionVersion, Policy: options.Policy, ApplicationScope: config.ApplicationScope, JournalDirectory: options.JournalDirectory, Deployments: []OriginalDeploymentSelection{}, Gateways: []OriginalGatewaySelection{}, RunningPro: []OriginalProPodSelection{}, StoppedPro: []OriginalStoppedProSelection{}, Participants: []OriginalMaintenanceParticipant{}}
	if err = p.originalSelectionObservers(ctx, options, &s); err != nil {
		return zero, census, nil, err
	}
	i := p.operator.installer
	roles := map[string]OriginalDeploymentSelection{}
	for _, d := range deployments {
		if d.DeletionTimestamp != nil || d.UID == "" || roles[d.Name].UID != "" {
			return zero, census, nil, ErrInstall
		}
		roles[d.Name] = OriginalDeploymentSelection{Name: d.Name, UID: string(d.UID), Role: "writer"}
	}
	var hostname string
	if i.db.QueryRowContext(ctx, "SELECT @@hostname").Scan(&hostname) != nil || hostname == "" {
		return zero, census, nil, ErrInstall
	}
	byPod := map[string]corev1.Pod{}
	database := ""
	for _, pod := range pods {
		byPod[pod.Name] = pod
		if pod.Name != hostname && pod.Spec.Hostname != hostname {
			continue
		}
		dep, e := p.originalSelectionPodDeployment(ctx, &pod, roles)
		if e != nil || database != "" || pod.Status.Phase != corev1.PodRunning {
			return zero, census, nil, ErrInstall
		}
		database = dep
		d := roles[dep]
		d.Role = "database"
		roles[dep] = d
	}
	if database == "" {
		return zero, census, nil, ErrInstall
	}
	physical := &PreparedOriginalWriterSet{owner: p}
	usedLayouts := map[int]bool{}
	agentPinsRead := false
	sharedAliases := map[string]string{}
	if config.RuntimeSources != nil && config.RuntimeSources.SharedRuntimeProtocol != "" {
		var sharedErr error
		sharedAliases, sharedErr = p.collectOriginalSharedAgentSelection(ctx, options, config, &s, pods, roles, physical, database)
		if sharedErr != nil {
			return zero, census, nil, sharedErr
		}
		agentPinsRead = true
	}
	for _, source := range p.instances {
		// Complete original lite rows are retained by p.instances and rechecked
		// by the actual shared factory; no per-instance slot custody is authored.
		if s.SharedRuntimeProtocol != "" && source.Mode == "lite" {
			continue
		}
		plan, e := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
		if e != nil {
			return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "unsupported_actual_runtime"}
		}
		if plan.Mode == "lite" {
			if config.RuntimeSources == nil {
				return zero, census, nil, ErrInstall
			}
			if !agentPinsRead {
				s.AgentCredential, e = originalSelectionCurrentPin(config.RuntimeSources.AgentTokenFile, 262144)
				if e != nil {
					return zero, census, nil, e
				}
				s.AgentCA = BootstrapSourceFilePin{File: config.RuntimeSources.AgentCAFile, SHA256: config.RuntimeSources.AgentCASHA256}
				ca, e := readBootstrapSourcePin(s.AgentCA, 262144)
				clear(ca)
				if e != nil {
					return zero, census, nil, e
				}
				agentPinsRead = true
			}
			tx, e := i.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
			if e != nil {
				return zero, census, nil, ErrInstall
			}
			row, e := readOriginalGatewayRow(ctx, tx, source.ID)
			rollback := tx.Rollback()
			if e != nil || rollback != nil || row.UID == "" || row.Generation != source.Generation || row.Workspace != source.Workspace || row.State != source.Status || row.Namespace != census.Namespace || row.Gateway != originalSelectionGatewayName(source.ID, source.Generation) {
				return zero, census, nil, ErrInstall
			}
			pod, ok := byPod[row.Pod]
			if !ok || string(pod.UID) != row.UID || pod.Status.Phase != corev1.PodRunning || len(pod.Spec.Containers) != 1 || pod.DeletionTimestamp != nil {
				return zero, census, nil, ErrInstall
			}
			dep, e := p.originalSelectionPodDeployment(ctx, &pod, roles)
			if e != nil || dep != row.Deployment || dep == database {
				return zero, census, nil, ErrInstall
			}
			d := roles[dep]
			d.Role = "agent"
			roles[dep] = d
			workspace, e := originalSelectionLiteralDirectory(pod.Spec.Containers[0], "RUNTIME_WORKSPACE_ROOT")
			if e != nil || workspace != config.RuntimeSources.WorkspaceRoot {
				return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "actual_agent_literal_workspace_root_required"}
			}
			data, e := originalSelectionRuntimeDataDirectory(options.runtimeStartupProfiles, &pod)
			if e != nil {
				return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "actual_agent_literal_data_directory_required"}
			}
			roots, e := physical.actualPodPersistentRoots(ctx, &pod)
			if e != nil || len(roots) == 0 {
				return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "actual_gateway_persistent_roots_required"}
			}
			gateway, e := originalSelectionGatewayCustody(ctx, i.plan.Target.InstallationID, source, row, options.GatewayOriginalDirectory, options.GatewayOriginalKey)
			if e != nil {
				return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "original_gateway_create_request_custody_required"}
			}
			gateway.WorkspaceRoot, gateway.AgentDataDir, gateway.SourcePaths = workspace, data, roots
			if _, ok := s.GatewayEndpoints[pod.Spec.NodeName]; !ok {
				return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "actual_gateway_node_observer_endpoint_required"}
			}
			s.Gateways = append(s.Gateways, gateway)
			s.GatewayRecoveryMode = OriginalGatewaySameIncarnationRecovery
		} else if source.Status == "stopped" {
			if config.RuntimeSources == nil {
				return zero, census, nil, ErrInstall
			}
			found := false
			for _, layout := range config.RuntimeSources.CurrentStoppedProLayouts {
				if layout.InstanceID != source.ID {
					continue
				}
				if found || !originalStoppedLayoutValid(layout) {
					return zero, census, nil, ErrInstall
				}
				if _, e := p.prepareStoppedProLayout(ctx, layout); e != nil {
					return zero, census, nil, e
				}
				s.StoppedPro = append(s.StoppedPro, layout)
				found = true
				usedLayouts[source.ID] = true
			}
			if !found {
				return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "current_stopped_pro_complete_layout_required"}
			}
		} else if source.Status == "running" && plan.Mode == "pro" {
			pod, ok := byPod[source.Pod]
			if !ok || source.Namespace != census.Namespace || pod.UID == "" || pod.Status.Phase != corev1.PodRunning || len(pod.OwnerReferences) != 0 || pod.DeletionTimestamp != nil {
				return zero, census, nil, ErrInstall
			}
			s.RunningPro = append(s.RunningPro, OriginalProPodSelection{InstanceID: source.ID})
		} else {
			return zero, census, nil, OriginalWriterSourceFailure{source.ID, source.Mode, source.Status, "unsupported_actual_runtime"}
		}
	}
	if config.RuntimeSources != nil {
		for _, layout := range config.RuntimeSources.CurrentStoppedProLayouts {
			if !usedLayouts[layout.InstanceID] {
				return zero, census, nil, ErrInstall
			}
		}
	}
	for n := range pods {
		pod := &pods[n]
		if len(pod.OwnerReferences) > 0 {
			if _, e := p.originalSelectionPodDeployment(ctx, pod, roles); e != nil {
				return zero, census, nil, e
			}
		} else if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
			known := false
			for _, selected := range s.RunningPro {
				for _, source := range p.instances {
					known = known || selected.InstanceID == source.ID && source.Namespace == pod.Namespace && source.Pod == pod.Name
				}
			}
			if !known {
				return zero, census, nil, OriginalWriterSourceFailure{Dependency: "unregistered_standalone_pod_writer"}
			}
		}
		if pod.Spec.NodeName != "" && pod.Status.Phase == corev1.PodRunning && pod.Name != hostname && pod.Spec.Hostname != hostname {
			if _, ok := s.WholePodEndpoints[pod.Spec.NodeName]; !ok {
				return zero, census, nil, OriginalWriterSourceFailure{Dependency: "actual_whole_pod_node_observer_endpoint_required"}
			}
		}
	}
	for _, d := range roles {
		s.Deployments = append(s.Deployments, d)
	}
	sort.Slice(s.Deployments, func(a, b int) bool { return s.Deployments[a].Name < s.Deployments[b].Name })
	// Resolve every SQL participant against a physically stoppable ACTUAL writer.
	// Arbitrary missing mappings are a concrete prerequisite, never guessed from
	// participant naming, controller labels or a successful lease-only check.
	if err = p.originalSelectionParticipants(ctx, options.ParticipantWriters, &s, sharedAliases); err != nil {
		return zero, census, nil, err
	}
	if p.checkInstances(ctx) != nil || p.check(ctx) != nil {
		return zero, census, nil, ErrInstall
	}
	return s, census, physical.volumes, nil
}

func (p *OriginalWriterMaintenance) originalSelectionPodDeployment(ctx context.Context, pod *corev1.Pod, selected map[string]OriginalDeploymentSelection) (string, error) {
	if pod == nil || len(pod.OwnerReferences) != 1 {
		return "", ErrInstall
	}
	parent := pod.OwnerReferences[0]
	if parent.Kind != "ReplicaSet" || parent.Controller == nil || !*parent.Controller {
		return "", ErrInstall
	}
	rs, e := p.operator.installer.kube.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil || rs.UID != parent.UID || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
		return "", ErrInstall
	}
	root := rs.OwnerReferences[0]
	if root.Kind != "Deployment" || root.Controller == nil || !*root.Controller || selected[root.Name].UID != string(root.UID) {
		return "", ErrInstall
	}
	return root.Name, nil
}

func (p *OriginalWriterMaintenance) originalSelectionParticipants(ctx context.Context, mappings map[string]string, s *OriginalWriterSetSelection, sharedAliases ...map[string]string) error {
	known := map[string]bool{}
	for _, agent := range s.SharedRuntimeAgents {
		known["shared-runtime/"+agent.PodUID] = true
	}
	for _, d := range s.Deployments {
		if d.Role == "writer" {
			known["deployment/"+p.operator.installer.plan.Target.Namespace+"/"+d.Name] = true
		}
	}
	for _, g := range s.Gateways {
		for _, source := range p.instances {
			if source.ID == g.InstanceID {
				tx, e := p.operator.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
				if e != nil {
					return ErrInstall
				}
				r, e := readOriginalGatewayRow(ctx, tx, source.ID)
				re := tx.Rollback()
				if e != nil || re != nil {
					return ErrInstall
				}
				known["gateway/"+r.UID+"/"+originalSelectionNumber(source.ID)] = true
			}
		}
	}
	for _, r := range s.RunningPro {
		for _, source := range p.instances {
			if source.ID == r.InstanceID {
				known["pod/"+source.Namespace+"/"+source.Pod] = true
			}
		}
	}
	for _, r := range s.StoppedPro {
		baseline, e := p.prepareStoppedProLayout(ctx, r)
		if e != nil {
			return e
		}
		known[baseline.baseline.SourceKey] = true
	}
	rows, e := p.operator.installer.db.QueryContext(ctx, "SELECT participant_id,state,resume_result FROM system_backup_participants WHERE scope=? ORDER BY participant_id", s.ApplicationScope)
	if e != nil {
		return ErrInstall
	}
	defer rows.Close()
	used := map[string]bool{}
	for rows.Next() {
		var id, state, result string
		if rows.Scan(&id, &state, &result) != nil || id == "" || len(id) > 128 || used[id] || state != "running" || result != "none" && result != "succeeded" && result != "forced" {
			return ErrInstall
		}
		writer := mappings[id]
		if writer == "" && known[id] {
			writer = id
		}
		for _, aliases := range sharedAliases {
			if writer == "" {
				writer = aliases[id]
			} else if actual := aliases[writer]; actual != "" {
				writer = actual
			}
		}
		if !known[writer] {
			return OriginalWriterSourceFailure{Dependency: "actual_sql_participant_to_physical_writer_mapping_required"}
		}
		s.Participants = append(s.Participants, OriginalMaintenanceParticipant{ID: id, WriterID: writer})
		used[id] = true
	}
	if rows.Err() != nil {
		return ErrInstall
	}
	for id := range mappings {
		if !used[id] {
			return ErrInstall
		}
	}
	return nil
}
