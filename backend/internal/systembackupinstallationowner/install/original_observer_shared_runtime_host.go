package install

import (
	"bytes"
	"path"
	"strings"
)

// Actual release files are independently pinned inputs, never request-selected
// hashes. The owner and readonly CLI both inspect the running /proc/PID/exe.
// No Agent ELF is executed or installed by this material producer.
type OriginalObserverSharedRuntimeHostConfig struct {
	OwnerDirectory, CgroupMount string
	AgentExecutables            map[string]BootstrapSourceFilePin
}

func sharedObserverHostDirectory(c *OriginalObserverSharedRuntimeHostConfig, nodeUID string) string {
	return path.Join(c.OwnerDirectory, "node-"+hash([]byte(nodeUID))[:24])
}

func validateSharedObserverHostConfig(def OriginalObserverHostDefinition, pki GeneratedOriginalObserverPKI) error {
	shared := map[string]OriginalObserverPKIEndpoint{}
	whole := map[string]OriginalObserverPKIEndpoint{}
	for _, ep := range pki.Endpoints {
		if ep.Kind == "shared" {
			if shared[ep.Node].Node != "" {
				return ErrInstall
			}
			shared[ep.Node] = ep
		}
		if ep.Kind == "whole" {
			if whole[ep.Node].Node != "" {
				return ErrInstall
			}
			whole[ep.Node] = ep
		}
	}
	if def.SharedRuntime == nil {
		if len(shared) != 0 || def.Binaries["shared"] != (BootstrapSourceFilePin{}) {
			return ErrInstall
		}
		return nil
	}
	c := def.SharedRuntime
	if len(shared) == 0 || len(shared) != len(whole) || def.Binaries["shared"] == (BootstrapSourceFilePin{}) || !observerHostPath(c.OwnerDirectory) || !strings.HasPrefix(c.OwnerDirectory, "/var/lib/clawmanager-system-backup/") || c.CgroupMount != "/sys/fs/cgroup" || len(c.AgentExecutables) != 2 {
		return ErrInstall
	}
	for _, runtime := range []string{"openclaw", "hermes"} {
		input, ok := c.AgentExecutables[runtime]
		if !ok {
			return ErrInstall
		}
		raw, err := readObserverHostFile(input, 64<<20)
		valid := err == nil && len(raw) >= 64 && bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) && raw[4] == 2 && raw[5] == 1 && raw[18] == 0x3e && raw[19] == 0
		clear(raw)
		if !valid {
			return ErrInstall
		}
	}
	for node, ep := range shared {
		reader, ok := whole[node]
		if !ok || reader.NodeUID != ep.NodeUID || reader.BootID != ep.BootID || reader.MachineID != ep.MachineID || ep.AnchorKey != reader.AnchorKey || ep.AnchorKey == (BootstrapSourceFilePin{}) {
			return ErrInstall
		}
	}
	return nil
}

func sharedObserverHostArgs(args []string, ep OriginalObserverPKIEndpoint, def OriginalObserverHostDefinition) ([]string, error) {
	if def.SharedRuntime == nil {
		if ep.Kind == "shared" {
			return nil, ErrInstall
		}
		return args, nil
	}
	if ep.Kind != "whole" && ep.Kind != "shared" {
		return args, nil
	}
	c := def.SharedRuntime
	if c.AgentExecutables["openclaw"].SHA256 == "" || c.AgentExecutables["hermes"].SHA256 == "" {
		return nil, ErrInstall
	}
	directory := sharedObserverHostDirectory(c, ep.NodeUID)
	if ep.Kind == "shared" {
		return append(args, "--owner-directory", directory, "--cgroup-mount", c.CgroupMount,
			"--openclaw-agent-elf-sha256", c.AgentExecutables["openclaw"].SHA256,
			"--hermes-agent-elf-sha256", c.AgentExecutables["hermes"].SHA256), nil
	}
	return append(args, "--shared-owner-directory", directory, "--shared-cgroup-mount", c.CgroupMount,
		"--shared-openclaw-agent-elf-sha256", c.AgentExecutables["openclaw"].SHA256,
		"--shared-hermes-agent-elf-sha256", c.AgentExecutables["hermes"].SHA256), nil
}
