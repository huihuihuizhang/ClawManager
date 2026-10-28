// Command system-backup-controller-grants prints reviewable MySQL grants for
// the current D-only controller. It never connects to a database.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"clawreef/internal/systembackupcontroller"
	execution "clawreef/internal/systembackupexecution"
)

func main() {
	schema := flag.String("schema", "", "target MySQL schema")
	user := flag.String("user", "", "pre-created dedicated controller database user")
	host := flag.String("host", "", "MySQL account host")
	allowAnyHost := flag.Bool("allow-any-host", false, "explicitly acknowledge host %")
	publicCapture := flag.Bool("public-capture", false, "render the public-v1 workspace capture metadata role")
	kubeConfig := flag.String("kubernetes-config", "", "render Kubernetes RBAC for this pinned public deployment JSON")
	kubeDigest := flag.String("kubernetes-config-sha256", "", "exact public deployment JSON SHA256")
	controllerSA := flag.String("controller-service-account", "", "pre-created dedicated capture controller ServiceAccount")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *kubeConfig != "" {
		if *publicCapture || *schema != "" || *user != "" || *host != "" || *allowAnyHost {
			fmt.Fprintln(os.Stderr, "Kubernetes and SQL grant modes are exclusive")
			os.Exit(2)
		}
		cfg, err := execution.LoadDeploymentConfig(*kubeConfig, *kubeDigest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pinned public deployment unavailable")
			os.Exit(2)
		}
		objects, err := execution.CaptureKubernetesGrants(cfg, *controllerSA)
		if err != nil {
			fmt.Fprintln(os.Stderr, "public Kubernetes access inventory invalid")
			os.Exit(2)
		}
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": objects}) != nil {
			os.Exit(1)
		}
		return
	}
	if *kubeDigest != "" || *controllerSA != "" {
		fmt.Fprintln(os.Stderr, "Kubernetes configuration required")
		os.Exit(2)
	}
	statements, err := systembackupcontroller.ControllerGrantSQL(*schema, *user, *host, *allowAnyHost)
	if *publicCapture {
		statements, err = systembackupcontroller.PublicCaptureGrantSQL(*schema, *user, *host, *allowAnyHost)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println("-- Review before applying. Create the user and Secret separately; no password is included.")
	for _, statement := range statements {
		fmt.Println(statement)
	}
}
