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
	runtimeControl := flag.Bool("runtime-control", false, "render the opt-in public runtime control and authenticated relay role")
	formalVerifier := flag.Bool("formal-verifier", false, "extend the selected capture role for the independent controller unwrap reader")
	providerPermits := flag.Bool("formal-provider-permits", false, "add original Generate permit planned/unknown reference writes; requires formal-verifier")
	publication := flag.Bool("publication", false, "add original v2 publication journal writes and frozen-signature chunks; requires formal-verifier")
	controlEvidence := flag.Bool("control-evidence", false, "add exact read-only control snapshot projections; requires formal-verifier; no worker SQL access")
	kubeConfig := flag.String("kubernetes-config", "", "render Kubernetes RBAC for this pinned public deployment JSON")
	kubeDigest := flag.String("kubernetes-config-sha256", "", "exact public deployment JSON SHA256")
	verifierMaterialsSHA := flag.String("verifier-materials-sha256", "", "independently deployed formal verifier materials SHA256 for exact read-only actor/owner RBAC")
	controllerSA := flag.String("controller-service-account", "", "pre-created dedicated capture controller ServiceAccount")
	publisherMaterialsSHA := flag.String("publisher-verifier-materials-sha256", "", "independent publisher verifier materials SHA256 for exact named GET roles")
	flag.Parse()
	if *runtimeControl && *publicCapture {
		fmt.Fprintln(os.Stderr, "SQL grant modes are exclusive")
		os.Exit(2)
	}
	if *formalVerifier && !*runtimeControl && !*publicCapture {
		fmt.Fprintln(os.Stderr, "formal verifier requires an explicit capture role")
		os.Exit(2)
	}
	if *providerPermits && !*formalVerifier {
		fmt.Fprintln(os.Stderr, "formal provider permits require the explicit formal verifier role")
		os.Exit(2)
	}
	if *publication && !*formalVerifier {
		fmt.Fprintln(os.Stderr, "publication requires the explicit formal verifier role")
		os.Exit(2)
	}
	if *controlEvidence && !*formalVerifier {
		fmt.Fprintln(os.Stderr, "control evidence requires the explicit formal verifier role")
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *kubeConfig != "" {
		if *controlEvidence || *publication || *providerPermits || *formalVerifier || *publicCapture || *runtimeControl || *schema != "" || *user != "" || *host != "" || *allowAnyHost {
			fmt.Fprintln(os.Stderr, "Kubernetes and SQL grant modes are exclusive")
			os.Exit(2)
		}
		cfg, err := execution.LoadDeploymentConfig(*kubeConfig, *kubeDigest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pinned public deployment unavailable")
			os.Exit(2)
		}
		var verifierInputs []execution.FormalVerifierInput
		if *verifierMaterialsSHA != "" {
			if cfg.FormalVerifier == nil {
				fmt.Fprintln(os.Stderr, "formal verifier reference required")
				os.Exit(2)
			}
			verifierInputs = append(verifierInputs, execution.FormalVerifierInput{File: cfg.FormalVerifier.Path, SHA256: *verifierMaterialsSHA})
		}
		inputs := execution.DeploymentStartupInputs{FormalVerifier: verifierInputs}
		if *publisherMaterialsSHA != "" {
			if cfg.PublisherVerifier == nil {
				fmt.Fprintln(os.Stderr, "publisher verifier reference required")
				os.Exit(2)
			}
			inputs.PublisherVerifier = append(inputs.PublisherVerifier, execution.PublisherVerifierInput{File: cfg.PublisherVerifier.Path, SHA256: *publisherMaterialsSHA})
		}
		objects, err := execution.CaptureKubernetesGrantsWithInputs(cfg, *controllerSA, inputs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "public Kubernetes access inventory invalid")
			os.Exit(2)
		}
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": objects}) != nil {
			os.Exit(1)
		}
		return
	}
	if *kubeDigest != "" || *controllerSA != "" || *verifierMaterialsSHA != "" || *publisherMaterialsSHA != "" {
		fmt.Fprintln(os.Stderr, "Kubernetes configuration required")
		os.Exit(2)
	}
	statements, err := systembackupcontroller.ControllerGrantSQL(*schema, *user, *host, *allowAnyHost)
	if *publicCapture {
		statements, err = systembackupcontroller.PublicCaptureGrantSQL(*schema, *user, *host, *allowAnyHost)
	}
	if *runtimeControl {
		statements, err = systembackupcontroller.RuntimeControlGrantSQL(*schema, *user, *host, *allowAnyHost)
	}
	if *formalVerifier {
		statements, err = systembackupcontroller.FormalCaptureGrantSQL(*schema, *user, *host, *allowAnyHost, *runtimeControl)
	}
	if *providerPermits {
		statements, err = systembackupcontroller.FormalProviderPermitGrantSQL(*schema, *user, *host, *allowAnyHost, *runtimeControl)
	}
	if *publication {
		statements, err = systembackupcontroller.PublicationGrantSQL(*schema, *user, *host, *allowAnyHost, *runtimeControl, *providerPermits)
	}
	if *controlEvidence {
		statements, err = systembackupcontroller.ControlEvidenceGrantSQL(*schema, *user, *host, *allowAnyHost, *runtimeControl, *providerPermits, *publication)
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
