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
		fmt.Fprintln(os.Stderr, "stopped Pro node observer unavailable")
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("backup-stopped-pro-node-observer", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	node := f.String("node", "", "original node name")
	uid := f.String("node-uid", "", "original Node UID")
	machine := f.String("machine-id", "", "original Node machineID")
	boot := f.String("boot-id", "", "original Node bootID")
	root := f.String("host-root", "/", "native host root")
	proc := f.String("host-proc", "/proc", "complete native host procfs")
	listen := f.String("listen", "127.0.0.1:8446", "restricted listen address")
	binary := f.String("crictl", "/usr/local/bin/crictl", "deployment-pinned native inspector")
	endpoint := f.String("runtime-endpoint", "unix:///run/containerd/containerd.sock", "deployment-pinned CRI socket")
	ca := f.String("client-ca", "", "original controller CA")
	cert := f.String("tls-cert", "", "node certificate")
	key := f.String("tls-key", "", "node private key")
	controller := f.String("controller-uri", "", "exact controller SPIFFE URI")
	anchorKey := f.String("anchor-key", "", "root-only node observation key")
	if f.Parse(args) != nil || f.NArg() != 0 || runtime.GOOS != "linux" || *ca == "" || *cert == "" || *key == "" || *anchorKey == "" || *controller == "" {
		return quiesce.ErrNodeObservation
	}
	secret, e := quiesce.ReadNodeObservationKey(*anchorKey)
	if e != nil {
		return e
	}
	observer, e := quiesce.NewNodeObserver(*node, *uid, *machine, *boot, *root, *proc, quiesce.CRICommand{Binary: *binary, Endpoint: *endpoint}, secret)
	for i := range secret {
		secret[i] = 0
	}
	if e != nil {
		return e
	}
	l, e := net.Listen("tcp", *listen)
	if e != nil {
		return quiesce.ErrNodeObservation
	}
	defer l.Close()
	return quiesce.ServeStoppedProNodeObservations(ctx, l, *ca, *cert, *key, &quiesce.StoppedProNodeObservationHandler{Observer: observer, ControllerURI: *controller})
}
