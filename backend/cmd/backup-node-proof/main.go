package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/quiesce"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx, os.Args[1:]); e != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "node proof service unavailable")
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("backup-node-proof", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	node := flags.String("node", "", "exact Kubernetes node name")
	listen := flags.String("listen", ":8443", "TLS listen address")
	binary := flags.String("crictl", "/usr/local/bin/crictl", "pinned read-only inspection binary")
	endpoint := flags.String("runtime-endpoint", "unix:///run/containerd/containerd.sock", "local CRI Unix socket")
	ca := flags.String("client-ca", "", "controller client CA file")
	cert := flags.String("tls-cert", "", "node certificate file")
	key := flags.String("tls-key", "", "node key file")
	controller := flags.String("controller-uri", "", "exact allowed controller SPIFFE URI")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *node == "" || !filepath.IsAbs(*binary) || *ca == "" || *cert == "" || *key == "" {
		return flow.ErrNotReady
	}
	uri, e := url.Parse(*controller)
	if e != nil || uri.Scheme != "spiffe" || uri.Host == "" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || runtime.GOOS != "linux" {
		return flow.ErrNotReady
	}
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		return flow.ErrNotReady
	}
	defer listener.Close()
	return quiesce.ServeProof(ctx, listener, *ca, *cert, *key, quiesce.ProofHandler{Prover: quiesce.CRIProver{Node: *node, Inspector: quiesce.CRICommand{Binary: *binary, Endpoint: *endpoint}}, ControllerURIs: map[string]bool{*controller: true}})
}
