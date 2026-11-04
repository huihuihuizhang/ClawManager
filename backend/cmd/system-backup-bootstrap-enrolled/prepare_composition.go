package main

// Composition is a location/data projection of existing ORIGINAL producer
// output. This command issues no grant, signs no record and installs no config.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"

	execution "clawreef/internal/systembackupexecution"
	"clawreef/internal/systembackupinstallationowner/install"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func assemblySHA(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func readCompositionProducer(pin install.BootstrapSourceFilePin, target any) ([]byte, error) {
	if !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File {
		return nil, install.ErrInstall
	}
	canonical, e := filepath.EvalSymlinks(pin.File)
	if e != nil || canonical != pin.File {
		return nil, install.ErrInstall
	}
	raw, e := install.ReadPrivateFile(pin.File, 262144)
	if e != nil || assemblySHA(raw) != pin.SHA256 {
		return nil, install.ErrInstall
	}
	if target != nil {
		// Native CLI stdout has a final newline. Authenticate its ORIGINAL pin,
		// reject duplicate JSON keys, and decode data without rewriting receipt.
		if _, e = jsoncanonicalizer.Transform(raw); e != nil {
			return nil, install.ErrInstall
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, install.ErrInstall
		}
	}
	return raw, nil
}

func compositionWriteNew(file string, raw []byte) error {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file || len(raw) == 0 || len(raw) > 262144 {
		return install.ErrInstall
	}
	parent := filepath.Dir(file)
	canonical, e := filepath.EvalSymlinks(parent)
	info, statErr := os.Stat(parent)
	if e != nil || canonical != parent || statErr != nil || !info.IsDir() || runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return install.ErrInstall
	}
	f, e := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, writeErr := f.Write(raw)
	flush, closeErr := f.Sync(), f.Close()
	if writeErr != nil || flush != nil || closeErr != nil || n != len(raw) {
		return install.ErrInstall
	}
	if runtime.GOOS != "windows" {
		dir, e := os.Open(parent)
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	}
	return nil
}

type compositionFunctionalReceipt struct {
	Version            string
	Classification     install.FunctionalClassificationFiles
	PublicationPolicy  install.BootstrapSourceFilePin
	SourceDefinition   install.BootstrapSourceFilePin
	ComponentsTemplate install.BootstrapSourceFilePin
}

func runPrepareComposition(ctx context.Context, args []string, out io.Writer) int {
	f := flag.NewFlagSet("prepare-composition", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	inputs := map[string]*install.BootstrapSourceFilePin{}
	for _, name := range []string{"config", "bootstrap-grant", "consumption", "facts-receipt", "functional-receipt", "minio-input", "nonce-binding", "artifact-ca-binding", "evidence-ca-binding", "catalog-location", "kek-config", "evidence", "installer-dsn", "signing-consumer", "signing-consumer-pin"} {
		p := &install.BootstrapSourceFilePin{}
		inputs[name] = p
		f.StringVar(&p.File, name+"-file", "", "existing actual original producer output")
		f.StringVar(&p.SHA256, name+"-sha256", "", "exact retained bytes; no grant from hash")
	}
	dirs := map[string]*string{}
	for _, name := range []string{"mapping-directory", "source-registry-directory", "status-relay-directory", "six-reference-directory", "kek-window-directory", "registry-directory", "nonce-directory", "output-directory"} {
		dirs[name] = f.String(name, "", "existing original controlled directory")
	}
	if ctx == nil || ctx.Err() != nil || out == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, p := range inputs {
		if p.File == "" || len(p.SHA256) != 64 {
			return 2
		}
	}
	for _, p := range dirs {
		if !filepath.IsAbs(*p) || filepath.Clean(*p) != *p {
			return 2
		}
	}
	retained := []install.BootstrapSourceFilePin{}
	read := func(name string, target any) ([]byte, error) {
		pin := *inputs[name]
		raw, e := readCompositionProducer(pin, target)
		if e == nil {
			retained = append(retained, pin)
		}
		return raw, e
	}
	record := func(directory, stem string, target any) (install.BootstrapSourceFilePin, string, error) {
		file, signature := filepath.Join(directory, stem+".record.json"), filepath.Join(directory, stem+".signature")
		expected, e := install.ReadPrivateFile(filepath.Join(directory, stem+".sha256"), 64)
		if e != nil || len(expected) != 64 {
			return install.BootstrapSourceFilePin{}, "", install.ErrInstall
		}
		pin := install.BootstrapSourceFilePin{File: file, SHA256: string(expected)}
		if _, e = readCompositionProducer(pin, target); e != nil {
			return pin, "", e
		}
		sig, e := install.ReadPrivateFile(signature, 64)
		if e != nil || len(sig) != 64 {
			return pin, "", install.ErrInstall
		}
		retained = append(retained, pin, install.BootstrapSourceFilePin{File: signature, SHA256: assemblySHA(sig)})
		return pin, signature, nil
	}
	var original install.BootstrapOriginalMapping
	originalPin, originalSig, e := record(*dirs["mapping-directory"], "bootstrap-original", &original)
	if e != nil {
		return 1
	}
	var native install.BootstrapNativeHostMapping
	nativePin, nativeSig, e := record(*dirs["mapping-directory"], "bootstrap-native-hosts", &native)
	if e != nil || native.OriginalMappingSHA256 != originalPin.SHA256 || native.Target != original.Target || native.SelectionSHA256 != original.SelectionSHA256 {
		return 1
	}
	var request pd.BootstrapConsumptionRequest
	if _, e = read("consumption", &request); e != nil {
		return 1
	}
	selection, e := pd.BootstrapConsumptionHash(request)
	if e != nil || string(selection) != original.SelectionSHA256 {
		return 1
	}
	configRaw, e := read("config", nil)
	if e != nil {
		return 1
	}
	config, e := sec.DecodeBootstrapConfig(configRaw)
	var mode struct {
		Enabled bool `json:"enabled"`
	}
	if e != nil || json.Unmarshal(configRaw, &mode) != nil || mode.Enabled || config.SHA256() != string(request.ConfigHash) {
		return 1
	}
	if _, e = read("bootstrap-grant", nil); e != nil {
		return 1
	}
	grant, _, _, e := sec.ReadBootstrapGrantFile(inputs["bootstrap-grant"].File, inputs["bootstrap-grant"].SHA256)
	if e != nil || grant.InstallationID != original.Target.InstallationID || grant.ServerUUID != original.Target.ServerUUID || grant.Database != original.Target.Database || grant.ConfigSHA256 != config.SHA256() {
		return 1
	}
	var classified compositionFunctionalReceipt
	var facts execution.BootstrapSourceRegistryFactsReceipt
	d := enrolledComposition{Version: enrolledCompositionVersion, Terminal: install.BootstrapTerminalFiles{MappingFile: originalPin.File, MappingSHA256: originalPin.SHA256, SignatureFile: originalSig, EvidenceFile: inputs["evidence"].File, RegistryDirectory: *dirs["registry-directory"]}, NativeHost: install.BootstrapNativeHostFiles{RecordFile: nativePin.File, RecordSHA256: nativePin.SHA256, SignatureFile: nativeSig}, Selections: request.Candidates}
	if _, e = read("functional-receipt", &classified); e != nil || classified.Version != "original-functional-publication-materials.v1" {
		return 1
	}
	d.Classification = classified.Classification
	if _, e = read("facts-receipt", &facts); e != nil || facts.Version != "original-source-registry-facts-receipt.v1" || facts.NativeRegistries == nil {
		return 1
	}
	d.SourceNativeRegistries = *facts.NativeRegistries
	if _, e = read("minio-input", &d.MinIO); e != nil {
		return 1
	}
	if _, e = read("nonce-binding", &d.Nonce); e != nil {
		return 1
	}
	if _, e = read("artifact-ca-binding", &d.ArtifactCA); e != nil {
		return 1
	}
	if _, e = read("evidence-ca-binding", &d.EvidenceCA); e != nil {
		return 1
	}
	if d.Nonce.InstallationID != grant.InstallationID || d.Nonce.ServerUUID != grant.ServerUUID || d.Nonce.Database != grant.Database || d.Nonce.ConfigSHA256 != config.SHA256() || d.ArtifactCA.InstallationID != grant.InstallationID || d.EvidenceCA.InstallationID != grant.InstallationID || d.ArtifactCA.ServerUUID != grant.ServerUUID || d.EvidenceCA.ServerUUID != grant.ServerUUID || d.ArtifactCA.Database != grant.Database || d.EvidenceCA.Database != grant.Database || d.ArtifactCA.Purpose != "artifact_ca" || d.EvidenceCA.Purpose != "evidence_ca" || d.ArtifactCA.ConfigSHA256 != config.SHA256() || d.EvidenceCA.ConfigSHA256 != config.SHA256() {
		return 1
	}
	sourcePin, sourceSig, e := record(*dirs["source-registry-directory"], "bootstrap-source-registries-v2", nil)
	if e != nil {
		return 1
	}
	d.SourceRegistries = install.BootstrapSourceRegistryFiles{RecordFile: sourcePin.File, RecordSHA256: sourcePin.SHA256, SignatureFile: sourceSig}
	statusPin, statusSig, e := record(*dirs["status-relay-directory"], "status-relay-reference", nil)
	if e != nil {
		return 1
	}
	d.StatusRelay = install.StatusRelayReferenceFiles{RecordFile: statusPin.File, RecordSHA256: statusPin.SHA256, SignatureFile: statusSig}
	sixPin, sixSig, e := record(*dirs["six-reference-directory"], "six-provider-references", nil)
	if e != nil {
		return 1
	}
	d.SixReferences = install.SixReferenceFiles{RecordFile: sixPin.File, RecordSHA256: sixPin.SHA256, SignatureFile: sixSig}
	windowPin, windowSig, e := record(*dirs["kek-window-directory"], "bootstrap-kek-window", nil)
	if e != nil {
		return 1
	}
	d.KEKWindow = install.BootstrapKEKWindowFiles{RecordFile: windowPin.File, RecordSHA256: windowPin.SHA256, SignatureFile: windowSig}
	for _, name := range []string{"catalog-location", "kek-config", "evidence", "installer-dsn", "signing-consumer", "signing-consumer-pin"} {
		if _, e = read(name, nil); e != nil {
			return 1
		}
	}
	if inputs["evidence"].SHA256 != original.EvidenceSourceSHA256 {
		return 1
	}
	d.CatalogLocation = *inputs["catalog-location"]
	d.KEKFile, d.KEKSHA256 = inputs["kek-config"].File, inputs["kek-config"].SHA256
	d.SigningConsumerFile, d.SigningConsumerSHA256, d.SigningConsumerPinFile = inputs["signing-consumer"].File, inputs["signing-consumer"].SHA256, inputs["signing-consumer-pin"].File
	consumerPin, _ := readCompositionProducer(*inputs["signing-consumer-pin"], nil)
	if string(consumerPin) != d.SigningConsumerSHA256 {
		return 1
	}
	deployment := sec.BootstrapDeploymentConfig{SchemaVersion: "system-backup-bootstrap-deployment.v1", InstallationID: grant.InstallationID, ExpectedServerUUID: grant.ServerUUID, ExpectedDatabase: grant.Database, ConfigFile: inputs["config"].File, ConfigSHA256: config.SHA256(), GrantFile: inputs["bootstrap-grant"].File, GrantSHA256: inputs["bootstrap-grant"].SHA256, RegistryDirectory: *dirs["registry-directory"], NonceDirectory: *dirs["nonce-directory"], CapacityReportFile: original.CapacityReportFile, DSNFile: inputs["installer-dsn"].File}
	compositionRaw, e := json.Marshal(d)
	if e != nil {
		return 1
	}
	deploymentRaw, e := json.Marshal(deployment)
	if e != nil {
		return 1
	}
	for _, p := range retained {
		if _, e = readCompositionProducer(p, nil); e != nil || ctx.Err() != nil {
			return 1
		}
	}
	output := *dirs["output-directory"]
	intent, _ := json.Marshal(map[string]any{"Version": "original-composition-data-assembly-intent.v1", "Inputs": retained})
	if compositionWriteNew(filepath.Join(output, "composition.prepare-intent.json"), intent) != nil || compositionWriteNew(filepath.Join(output, "enrolled-composition.json"), compositionRaw) != nil || compositionWriteNew(filepath.Join(output, "bootstrap-deployment.json"), deploymentRaw) != nil {
		return 3 // exact partial files retained, never repair/overwrite or apply
	}
	compositionPin := install.BootstrapSourceFilePin{File: filepath.Join(output, "enrolled-composition.json"), SHA256: assemblySHA(compositionRaw)}
	if _, e = loadEnrolledComposition(compositionPin.File, compositionPin.SHA256); e != nil {
		return 3
	}
	if json.NewEncoder(out).Encode(map[string]any{"Version": "original-composition-data-assembly-result.v1", "state": "composition_data_assembled_original_admission_not_run", "Composition": compositionPin, "Deployment": install.BootstrapSourceFilePin{File: filepath.Join(output, "bootstrap-deployment.json"), SHA256: assemblySHA(deploymentRaw)}, "native_owners_verified": false, "configuration_mutated": false}) != nil {
		return 3
	}
	return 0
}
