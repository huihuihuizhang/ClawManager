// backup-worker consumes a credential-free invocation and a task-scoped mTLS
// control grant. It never reads production kubeconfig or database configuration.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"clawreef/internal/systembackup/worker"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx, os.Args[1:], os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, "backup worker failed; inspect controller evidence")
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) error {
	f := flag.NewFlagSet("backup-worker", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	requestPath := f.String("request", "-", "credential-free invocation JSON, or stdin")
	endpoint := f.String("control-url", "", "task-scoped mTLS control endpoint")
	ca := f.String("control-ca", "", "controller CA PEM")
	cert := f.String("client-cert", "", "task identity certificate PEM")
	key := f.String("client-key", "", "task identity private key PEM")
	if f.Parse(args) != nil || f.NArg() != 0 || *endpoint == "" || *ca == "" || *cert == "" || *key == "" {
		return worker.ErrRequest
	}
	if runtime.GOOS != "linux" {
		return worker.ErrNotReady
	} // fixtures call the library on Windows
	reader := stdin
	if *requestPath != "-" {
		file, e := os.Open(*requestPath)
		if e != nil {
			return worker.ErrRequest
		}
		defer file.Close()
		reader = file
	}
	i, e := worker.ReadInvocation(reader)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithDeadline(ctx, i.Request.Deadline)
	defer cancel()
	control, e := worker.NewControlClient(*endpoint, *ca, *cert, *key)
	if e != nil {
		return e
	}
	defer control.Close()
	store, e := os.OpenRoot(i.StagingPath)
	if e != nil {
		return worker.ErrRequest
	}
	defer store.Close()
	if e = awaitControl(ctx, func() error { return control.Ready(ctx, i) }); e != nil {
		return e
	}
	var lease worker.Lease
	for {
		lease, e = control.Acquire(ctx, i)
		if e == nil {
			break
		}
		if e != worker.ErrNotReady {
			return e
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	defer lease.Clear()
	// The short-lived key grant cannot be extended by a later heartbeat.
	ctx, keyCancel := context.WithDeadline(ctx, lease.ExpiresAt)
	defer keyCancel()
	check := func(ctx context.Context, point string, _ worker.Request) error { return control.Check(ctx, i, point) }
	var result worker.Result
	if i.Request.Database != nil {
		db, err := worker.OpenDatabase(i.Request.Database, lease.Database)
		if err != nil {
			return err
		}
		defer db.Close()
		var evidence *os.Root
		if i.EvidencePath != "" {
			evidence, err = os.OpenRoot(i.EvidencePath)
			if err != nil {
				return worker.ErrRequest
			}
			defer evidence.Close()
		}
		result, e = worker.RunDatabase(ctx, i.Request, worker.DatabaseEnvironment{Database: db, Staging: store, Evidence: evidence, Key: lease.DEK, Check: check})
	} else {
		workspace, err := os.OpenRoot(i.WorkspacePath)
		if err != nil {
			return worker.ErrRequest
		}
		defer workspace.Close()
		result, e = worker.Run(ctx, i.Request, worker.Environment{Workspace: workspace, Staging: store, Key: lease.DEK, PreserveOwner: true, Check: check})
	}
	if e != nil {
		return e
	}
	if e = awaitControl(ctx, func() error { return control.Complete(ctx, i, result) }); e != nil {
		return e
	}
	return json.NewEncoder(stdout).Encode(result)
}

func awaitControl(ctx context.Context, call func() error) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e := call()
		if e == nil {
			return nil
		}
		if e != worker.ErrNotReady {
			return e
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
