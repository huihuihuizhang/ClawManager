package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

func runFreshInstallationIdentity(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("initialize-installation", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "query", "query or apply")
	operation := f.String("operation", "", "retained 32-character random operation ID")
	namespace := f.String("namespace", "", "selected fresh namespace")
	namespaceUID := f.String("namespace-uid", "", "independently observed namespace UID")
	app := f.String("app-deployment", "", "actual ready business App Deployment")
	appUID := f.String("app-deployment-uid", "", "independently observed business App Deployment UID")
	server := f.String("expected-server-uuid", "", "independently observed MySQL server UUID")
	database := f.String("expected-database", "", "selected new database")
	admin := f.String("local-admin-username", "", "existing active App local administrator")
	serverName := f.String("database-tls-server-name", "", "selected MySQL TLS SAN")
	kubeFile := f.String("kubeconfig-file", "", "selected private static kubeconfig")
	kubeSHA := f.String("kubeconfig-sha256", "", "independently selected kubeconfig bytes")
	installerFile := f.String("installer-dsn-file", "", "private installer DSN")
	businessFile := f.String("business-dsn-file", "", "private App business DSN")
	useAppSecret := f.Bool("use-app-database-secret", false, "authenticate using the selected App database Secret")
	caFile := f.String("database-ca-file", "", "private selected MySQL CA")
	passwordFile := f.String("local-admin-password-file", "", "private App local admin password")
	if ctx == nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 || (*mode != "query" && *mode != "apply") {
		return 2
	}
	if *useAppSecret == (*businessFile != "") {
		return 2
	}
	for _, value := range []*string{operation, namespace, namespaceUID, app, appUID, server, database, admin, serverName, kubeFile, kubeSHA, installerFile, caFile, passwordFile} {
		if *value == "" {
			return 2
		}
	}
	pin := func(file string, max int64) (install.BootstrapSourceFilePin, error) {
		raw, err := install.ReadPrivateFile(file, max)
		if err != nil {
			return install.BootstrapSourceFilePin{}, err
		}
		defer clear(raw)
		sum := sha256.Sum256(raw)
		return install.BootstrapSourceFilePin{File: file, SHA256: hex.EncodeToString(sum[:])}, nil
	}
	installer, err := pin(*installerFile, 16384)
	if err != nil {
		return 1
	}
	var business install.BootstrapSourceFilePin
	if !*useAppSecret {
		business, err = pin(*businessFile, 16384)
		if err != nil {
			return 1
		}
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
	active, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	receipt, err := install.InitializeFreshInstallationIdentity(active, password, install.FreshInstallationIdentityInputs{
		OriginalEnrollmentInputs: install.OriginalEnrollmentInputs{Namespace: *namespace, LocalAdminUsername: *admin, DatabaseTLSServerName: *serverName,
			Kubeconfig: install.BootstrapSourceFilePin{File: *kubeFile, SHA256: *kubeSHA}, InstallerDSN: installer, BusinessDSN: business, DatabaseCA: ca},
		Operation: *operation, NamespaceUID: *namespaceUID, AppDeployment: *app, AppDeploymentUID: *appUID, ExpectedServerUUID: *server, ExpectedDatabase: *database, Apply: *mode == "apply", UseAppDatabaseSecret: *useAppSecret,
	})
	if errors.Is(err, install.ErrCommitUnknown) {
		return 3
	}
	if err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
