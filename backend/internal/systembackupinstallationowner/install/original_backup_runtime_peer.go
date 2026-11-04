package install

import (
	"bytes"
	"context"
	"reflect"
	"sort"
	"strings"
	"time"
	"unicode"

	corev1 "k8s.io/api/core/v1"
)

func originalRuntimeStartupSensitive(name string) bool {
	return strings.HasPrefix(name, "S6_") || strings.HasPrefix(name, "FILE__") || strings.HasPrefix(name, "DOCKER_MODS") || strings.HasPrefix(name, "MODMANAGER_") || name == "PATH" || name == "ENV" || name == "BASH_ENV" || name == "LD_PRELOAD" || name == "LD_LIBRARY_PATH" || name == "SHELLOPTS" || name == "RUNTIME_AGENT_CONTROL_TOKEN" || name == "RUNTIME_AGENT_REPORT_TOKEN" || name == "CLAWMANAGER_AGENT_CONTROL_TOKEN" || name == "CLAWMANAGER_AGENT_REPORT_TOKEN" || name == "RUNTIME_AGENT_DATA_DIR" || name == "RUNTIME_WORKSPACE_ROOT"
}
func originalRuntimeToken(value string) bool {
	return len(value) >= 32 && len(value) <= 8192 && strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || r == 0 }) < 0
}

// Pure interpretation of authenticated image content plus the actual immutable
// captured Pod literals. It returns comparison DATA only. ValueFrom/envFrom for
// startup selectors requires an actual loaded-environment adapter; this finite
// branch refuses it rather than treating current API Secret bytes as loaded.
func decodeOriginalRuntimeStartup(image *originalRuntimeStartupImage, spec *corev1.PodSpec, c *corev1.Container) (string, map[string]string, error) {
	if image == nil || spec == nil || c == nil || len(spec.Containers) != 1 || len(spec.InitContainers) != 0 || len(spec.EphemeralContainers) != 0 || len(c.EnvFrom) != 0 || !reflect.DeepEqual(spec.Containers[0], *c) {
		return "", nil, ErrInstall
	}
	if c.WorkingDir != "" && c.WorkingDir != "/" {
		return "", nil, ErrInstall
	}
	env := map[string]string{}
	for k, v := range image.defaults {
		env[k] = v
	}
	seen := map[string]bool{}
	for _, v := range c.Env {
		if v.Name == "" || seen[v.Name] {
			return "", nil, ErrInstall
		}
		seen[v.Name] = true
		if !originalRuntimePodEnvName(v.Name) {
			return "", nil, OriginalWriterSourceFailure{Dependency: "runtime_fixed_startup_environment_override_unsupported"}
		}
		if v.ValueFrom != nil {
			if originalRuntimeStartupSensitive(v.Name) {
				return "", nil, OriginalWriterSourceFailure{Dependency: "runtime_actual_loaded_startup_environment_adapter_required"}
			}
			continue
		}
		if strings.Contains(v.Value, "$(") && originalRuntimeStartupSensitive(v.Name) {
			return "", nil, ErrInstall
		}
		env[v.Name] = v.Value
	}
	// The source ABI selects the same raw tokens as the two fixed service guards.
	// Native cap/hold verification below is additional and mandatory.
	if !originalRuntimeToken(env["RUNTIME_AGENT_CONTROL_TOKEN"]) || !originalRuntimeToken(env["RUNTIME_AGENT_REPORT_TOKEN"]) {
		return "", nil, ErrInstall
	}
	for _, name := range []string{"CONTROL", "REPORT"} {
		alias := env["CLAWMANAGER_AGENT_"+name+"_TOKEN"]
		if alias != "" && alias != env["RUNTIME_AGENT_"+name+"_TOKEN"] {
			return "", nil, ErrInstall
		}
	}
	for _, name := range []string{"ENV", "BASH_ENV", "LD_PRELOAD", "LD_LIBRARY_PATH", "SHELLOPTS"} {
		value, exists := env[name]
		baseline, known := image.defaults[name]
		if exists && (!known || value != baseline) {
			return "", nil, ErrInstall
		}
	}
	// A literal PATH may only restate the byte-authenticated base's PATH. A
	// generic PATH search, function, loader or mounted interpreter is not assumed.
	if env["PATH"] != image.defaults["PATH"] {
		return "", nil, ErrInstall
	}
	launch := ""
	if reflect.DeepEqual(c.Command, []string{"/usr/local/bin/clawmanager-agent"}) && len(c.Args) == 0 && len(image.command) == 0 {
		launch = "direct-fixed-shared-agent"
	} else if len(c.Command) == 0 && len(c.Args) == 0 && reflect.DeepEqual(image.entrypoint, []string{"/init"}) && len(image.command) == 0 {
		launch = "fixed-s6-shared-no-configured-mods"
	} else {
		return "", nil, OriginalWriterSourceFailure{Dependency: "runtime_fixed_original_startup_override_unsupported"}
	}
	if launch == "fixed-s6-shared-no-configured-mods" {
		if _, defined := env["DOCKER_MODS"]; defined {
			return "", nil, ErrInstall
		}
		if env["MODMANAGER_MODONLY"] != "" {
			return "", nil, ErrInstall
		}
		for name := range env {
			if strings.HasPrefix(name, "FILE__") || strings.HasPrefix(name, "MODMANAGER_") && name != "MODMANAGER_MODONLY" {
				return "", nil, ErrInstall
			}
		}
		// Only this already-read fixed hook/default resolver profile. Empty defined
		// DOCKER_MODS is NOT the absent case. No fallback helpers are classified.
		if hook := env["S6_STAGE2_HOOK"]; hook != "" && hook != "/docker-mods" {
			return "", nil, ErrInstall
		}
		if keep := env["S6_KEEP_ENV"]; keep != "" && keep != "0" {
			return "", nil, ErrInstall
		}
		for name := range seen {
			if strings.HasPrefix(name, "S6_") && name != "S6_STAGE2_HOOK" && name != "S6_KEEP_ENV" {
				return "", nil, ErrInstall
			}
		}
	}
	controls := []string{"/init", "/command", "/package", "/etc/services.d", "/etc/s6-overlay", "/etc/cont-init.d", "/etc/cont-finish.d", "/custom-cont-init.d", "/custom-services.d", "/run/s6", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/lib", "/usr/lib", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"}
	if launch == "fixed-s6-shared-no-configured-mods" {
		controls = append(controls, "/config", "/root", "/home", "/docker-mods")
		// The fixed hook invokes interpreters through the original image PATH.
		// A mounted earlier directory must not replace that authenticated chain.
		for _, directory := range strings.Split(image.defaults["PATH"], ":") {
			if !originalStoppedCleanRoot(directory) || directory == "/" {
				return "", nil, ErrInstall
			}
			controls = append(controls, directory)
		}
		if home := image.defaults["HOME"]; home != "" {
			controls = append(controls, home)
		}
	}
	for _, m := range c.VolumeMounts {
		if !originalStoppedCleanRoot(m.MountPath) {
			return "", nil, ErrInstall
		}
		for _, p := range controls {
			if originalRuntimePathOverlap(m.MountPath, p) {
				return "", nil, OriginalWriterSourceFailure{Dependency: "runtime_mounted_startup_or_environment_unsupported"}
			}
		}
	}
	if len(c.VolumeDevices) != 0 {
		return "", nil, ErrInstall
	}
	if env["RUNTIME_AGENT_DATA_DIR"] == "" {
		env["RUNTIME_AGENT_DATA_DIR"] = "/var/lib/clawmanager-agent"
	}
	if !originalStoppedCleanRoot(env["RUNTIME_AGENT_DATA_DIR"]) || !originalStoppedCleanRoot(env["RUNTIME_WORKSPACE_ROOT"]) {
		return "", nil, ErrInstall
	}
	return launch, env, nil
}
func originalSelectionRuntimeDataDirectory(images map[string]*originalRuntimeStartupImage, pod *corev1.Pod) (string, error) {
	if pod == nil || len(pod.Spec.Containers) != 1 {
		return "", ErrInstall
	}
	c := &pod.Spec.Containers[0]
	// Keep the preexisting literal-only rule unless this exact fixed image's
	// default script+configuration have been independently byte authenticated.
	if value, e := originalSelectionLiteralDirectory(*c, "RUNTIME_AGENT_DATA_DIR"); e == nil {
		return value, nil
	}
	for _, v := range c.Env {
		if v.Name == "RUNTIME_AGENT_DATA_DIR" && v.ValueFrom != nil {
			return "", ErrInstall
		}
	}
	status := originalContainerStatus(pod.Status.ContainerStatuses, c.Name)
	image := originalRuntimeImageForContainer(images, c, status)
	_, env, e := decodeOriginalRuntimeStartup(image, &pod.Spec, c)
	if e != nil {
		return "", e
	}
	return env["RUNTIME_AGENT_DATA_DIR"], nil
}
func originalRuntimePodEnvName(name string) bool {
	if strings.HasPrefix(name, "RUNTIME_") || strings.HasPrefix(name, "CLAWMANAGER_") {
		return true
	}
	switch name {
	case "POD_NAME", "POD_NAMESPACE", "POD_IP", "POD_UID", "NODE_NAME", "HERMES_TUI_DIR", "PATH", "S6_STAGE2_HOOK", "S6_KEEP_ENV", "DOCKER_MODS", "MODMANAGER_MODONLY":
		return true
	}
	return false
}
func originalRuntimePathOverlap(a, b string) bool {
	return a == b || a == "/" || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// Called only by the REAL original finite backup-consumer source, after its
// actual captured Pod/container match. No public DTO can construct h/g/proof.
func classifyOriginalBackupRuntimePeer(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, pod *corev1.Pod, spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, until time.Time) (originalBackupStartupDisposition, error) {
	if h != nil && h.set != nil && len(h.set.sharedRuntimes) > 0 {
		value, err := classifyOriginalSharedRuntimePeer(ctx, p, h, pod, spec, c, status, until)
		if err != errOriginalBackupConsumerUnclassified {
			return value, err
		}
	}
	zero := originalBackupStartupDisposition{}
	if !originalEmptyHistoryOwner(ctx, p, h, false) || pod == nil || spec == nil || c == nil || status == nil || h.set == nil || !originalPeerContainerMatches(pod, spec, c, status, false) {
		return zero, ErrInstall
	}
	relevant := false
	for _, g := range h.set.gateways {
		relevant = relevant || g != nil && g.row.UID == string(pod.UID)
	}
	if !relevant {
		return zero, errOriginalBackupConsumerUnclassified
	}
	image := originalRuntimeImageForContainer(h.set.runtimeStartups, c, status)
	if image == nil {
		return zero, OriginalWriterSourceFailure{Dependency: "runtime_content_authenticated_startup_image_inputs_required"}
	}
	launch, environment, e := decodeOriginalRuntimeStartup(image, spec, c)
	if e != nil {
		return zero, e
	}
	type nativeJoin struct {
		InstanceID                                             int
		PodUID, ContainerID, Slot, Anchor, Boot, OriginalState string
	}
	joined := []nativeJoin{}
	seen := map[int]bool{}
	for _, g := range h.set.gateways {
		if g == nil || g.row.UID != string(pod.UID) {
			continue
		}
		if g.owner != h.set.owner || g.proof == nil || !g.stopDispatched || g.resumeDispatched || g.recovery != nil || g.source.Type != image.runtime || g.request.Binding.OperationID != h.set.owner.operation || g.request.Binding.InventorySHA256 != h.set.inventorySHA || g.row.Namespace != pod.Namespace || g.row.Pod != pod.Name || g.anchor == "" || g.boot == "" || len(g.raw) == 0 || len(g.completion) != 0 || seen[g.source.ID] || g.selection.AgentDataDir != environment["RUNTIME_AGENT_DATA_DIR"] || g.selection.WorkspaceRoot != environment["RUNTIME_WORKSPACE_ROOT"] {
			return zero, ErrInstall
		}
		seen[g.source.ID] = true
		original := g.request
		original.Action = "stopped"
		original.Anchor = g.anchor
		original.SourcePaths = append([]string{}, g.request.SourcePaths...)
		original.Raw = bytes.Clone(g.raw)
		original.RawAction = g.rawAction
		original.CompletionRaw = nil
		original.OriginalStateSHA256 = g.proof.Response().OriginalStateSHA256
		cap, e := g.proof.RecheckOriginalGatewayAgentPod(ctx, original, g.boot, pod, time.Now().UTC())
		clear(original.Raw)
		if e != nil || cap.IsZero() {
			return zero, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
		if original.Binding.ExpiresAt.Before(until) {
			until = original.Binding.ExpiresAt
		}
		joined = append(joined, nativeJoin{g.source.ID, g.row.UID, status.ContainerID, g.request.Slot, g.anchor, g.boot, original.OriginalStateSHA256})
	}
	if len(joined) == 0 || !time.Now().Before(until) || !originalEmptyHistoryOwner(ctx, p, h, false) {
		return zero, ErrInstall
	}
	sort.Slice(joined, func(i, j int) bool { return joined[i].InstanceID < joined[j].InstanceID })
	// No changing observation timestamps/raw receipts enter stable source identity.
	// Their genuine original proof/cap is checked separately on every use.
	source := originalObjectSHA(struct {
		Version, Image, Runtime, Launch, PodUID, ContainerID string
		Container                                            corev1.Container
		Native                                               []nativeJoin
	}{"original-runtime-fixed-startup-content.v1", image.source, image.runtime, launch, string(pod.UID), status.ContainerID, *c, joined})
	return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: "original-held-" + image.runtime + "-fixed-startup.v1", sourceSHA256: source, until: until}, nil
}
