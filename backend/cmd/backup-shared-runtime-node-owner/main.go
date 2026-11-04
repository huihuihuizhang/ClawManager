package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"clawreef/internal/systembackup/quiesce"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if run(ctx, os.Args[1:]) != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "shared runtime native owner unavailable; original recovery obligations retained")
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("backup-shared-runtime-node-owner", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	node := f.String("node", "", "original node name")
	uid := f.String("node-uid", "", "original Kubernetes Node UID")
	machine := f.String("machine-id", "", "original Node status.nodeInfo.machineID")
	boot := f.String("boot-id", "", "original Node status.nodeInfo.bootID")
	root := f.String("host-root", "/", "native host root")
	proc := f.String("host-proc", "/proc", "complete native host procfs")
	listen := f.String("listen", "127.0.0.1:8447", "restricted deployment listen address")
	binary := f.String("crictl", "/usr/local/bin/crictl", "deployment-pinned read-only CRI inspector")
	endpoint := f.String("runtime-endpoint", "unix:///run/containerd/containerd.sock", "local deployment CRI endpoint")
	ca := f.String("client-ca", "", "original controller CA")
	cert := f.String("tls-cert", "", "native owner TLS certificate")
	key := f.String("tls-key", "", "native owner TLS private key")
	controller := f.String("controller-uri", "", "exact controller SPIFFE URI")
	anchorKey := f.String("anchor-key", "", "root-only node-local 32-byte original key")
	store := f.String("owner-directory", "", "persistent root-private native recovery directory")
	cgroup := f.String("cgroup-mount", "/sys/fs/cgroup", "native host cgroup v2 mount")
	openclawELF := f.String("openclaw-agent-elf-sha256", "", "release-approved running shared Agent executable")
	hermesELF := f.String("hermes-agent-elf-sha256", "", "release-approved running shared Agent executable")
	if f.Parse(args) != nil || f.NArg() != 0 || runtime.GOOS != "linux" || *anchorKey == "" || *store == "" || *ca == "" || *cert == "" || *key == "" || *controller == "" || *openclawELF == "" || *hermesELF == "" {
		return quiesce.ErrNodeObservation
	}
	secret, err := quiesce.ReadNodeObservationKey(*anchorKey)
	if err != nil {
		return err
	}
	observer, err := quiesce.NewNodeObserver(*node, *uid, *machine, *boot, *root, *proc, quiesce.CRICommand{Binary: *binary, Endpoint: *endpoint}, secret)
	for i := range secret {
		secret[i] = 0
	}
	if err != nil {
		return err
	}
	h, err := quiesce.NewSharedRuntimeNodeHandler(observer, quiesce.SharedRuntimeNodeOwnerConfig{CgroupMount: *cgroup, Directory: *store, ControllerURI: *controller, Releases: map[string]quiesce.SharedRuntimeAgentRelease{
		"openclaw": {ExecutableSHA256: *openclawELF, DataDir: "/var/lib/openclaw-agent"},
		"hermes":   {ExecutableSHA256: *hermesELF, DataDir: "/var/lib/clawmanager-agent"},
	}})
	if err != nil {
		return err
	}
	defer h.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return quiesce.ErrNodeObservation
	}
	defer listener.Close()
	return quiesce.ServeSharedRuntimeNodeLifecycle(ctx, listener, *ca, *cert, *key, h)
}
