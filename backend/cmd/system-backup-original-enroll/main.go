package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

// The operator selects existing trusted native connection files, not a Plan or
// a claimed identity. No credential, DSN, certificate private key or password is
// accepted through argv or printed by this command.
func run(ctx context.Context, args []string, out io.Writer) int {
	if len(args) > 0 && args[0] == "runtime-issuers" {
		return runRuntimeIssuers(ctx, args[1:], out)
	}
	if len(args) > 0 && args[0] == "sql-accounts" {
		return install.RunOriginalSQLAccounts(ctx, args[1:], out)
	}
	flags := flag.NewFlagSet("system-backup-original-enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	namespace := flags.String("namespace", "", "actual selected installation namespace")
	username := flags.String("local-admin-username", "", "existing active local administrator")
	serverName := flags.String("database-tls-server-name", "", "actual selected MySQL certificate SAN")
	kubeFile := flags.String("kubeconfig-file", "", "existing trusted private operator kubeconfig")
	installerDSN := flags.String("installer-dsn-file", "", "existing private installer DSN")
	businessDSN := flags.String("business-dsn-file", "", "existing private business DSN")
	caFile := flags.String("database-ca-file", "", "existing private pinned MySQL CA file")
	passwordFile := flags.String("local-admin-password-file", "", "existing private exact password bytes")
	directory := flags.String("output-directory", "", "new operation-private output directory")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *namespace == "" || *username == "" || *serverName == "" || *directory == "" {
		return 2
	}
	pin := func(file string, limit int64) (install.BootstrapSourceFilePin, error) {
		raw, err := install.ReadPrivateFile(file, limit)
		if err != nil {
			return install.BootstrapSourceFilePin{}, err
		}
		defer clear(raw)
		sum := sha256.Sum256(raw)
		return install.BootstrapSourceFilePin{File: file, SHA256: hex.EncodeToString(sum[:])}, nil
	}
	kube, err := pin(*kubeFile, 262144)
	if err != nil {
		return 1
	}
	installer, err := pin(*installerDSN, 16384)
	if err != nil {
		return 1
	}
	business, err := pin(*businessDSN, 16384)
	if err != nil {
		return 1
	}
	ca, err := pin(*caFile, 65536)
	if err != nil {
		return 1
	}
	password, err := install.ReadPrivateFile(*passwordFile, 1024)
	if err != nil {
		return 1
	}
	defer clear(password)
	if !filepath.IsAbs(*directory) || filepath.Clean(*directory) != *directory {
		return 2
	}
	parent := filepath.Dir(*directory)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return 1
	}
	if os.Mkdir(*directory, 0700) != nil {
		return 1
	}
	// Any later error retains created key/Plan and an unknown original enrollment
	// for exact inspection. It never removes material or issues another identity.
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	produced, err := install.BootstrapOriginalEnrollment(active, password, install.OriginalEnrollmentInputs{Namespace: *namespace, LocalAdminUsername: *username, DatabaseTLSServerName: *serverName, Kubeconfig: kube, InstallerDSN: installer, BusinessDSN: business, DatabaseCA: ca, OutputDirectory: *directory})
	if errors.Is(err, install.ErrCommitUnknown) {
		return 3
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(produced) != nil {
		return 3
	}
	return 0
}
func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout))
}
