package install

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ReleaseBinary is an optional independently verified official offline crictl
// input. Binary is always the actual selected host destination, never guessed.
type OriginalObserverHostCRI struct {
	Node, NodeUID, Binary, BinarySHA256, Endpoint string
	ReleaseBinary                                 BootstrapSourceFilePin
}

const observerHostCRIBinarySHA256 = "d9f541aa6a3a1fce15392d4366da5f97b47683aa55a825909ad8c0a624c7f4f3"
const observerHostCRIBundleName = "crictl-v1.31.1"

type OriginalObserverHostDefinition struct {
	Version                            string
	PKIDefinition, PKIReceipt          BootstrapSourceFilePin
	Binaries                           map[string]BootstrapSourceFilePin
	BinaryDirectory, MaterialDirectory string
	CRI                                []OriginalObserverHostCRI
	SharedRuntime                      *OriginalObserverSharedRuntimeHostConfig `json:",omitempty"`
}
type OriginalObserverHostMaterialsReceipt struct {
	Version, Status, PlanSHA256, DefinitionSHA256, PKIReceiptSHA256 string
	NodeBundles                                                     map[string]BootstrapSourceFilePin
	AuthorityHead                                                   HeadCAS
}

var originalObserverBinary = map[string]string{"whole": "backup-node-observer", "gateway": "backup-gateway-node-observer", "stopped-pro": "backup-stopped-pro-node-observer", "shared": "backup-shared-runtime-node-owner"}

func observerHostPath(v string) bool {
	return path.IsAbs(v) && path.Clean(v) == v && v != "/" && !strings.ContainsAny(v, "\x00\r\n\\")
}
func observerUnitArg(v string) string  { return strconv.Quote(strings.ReplaceAll(v, "%", "%%")) }
func observerShellArg(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }

// The release ELF is public input, separately pinned by the actual operator.
// Source and output are read completely, including stable-file EOF checks.
func readObserverHostFile(pin BootstrapSourceFilePin, max int64) ([]byte, error) {
	if !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File || !digestPattern.MatchString(pin.SHA256) {
		return nil, ErrInstall
	}
	before, e := os.Lstat(pin.File)
	if e != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > max {
		return nil, ErrInstall
	}
	f, e := os.Open(pin.File)
	if e != nil {
		return nil, ErrInstall
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, ErrInstall
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	after, e2 := f.Stat()
	if e != nil || e2 != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || int64(len(raw)) > max || hash(raw) != pin.SHA256 {
		clear(raw)
		return nil, ErrInstall
	}
	return raw, nil
}

func observerHostUnit(pki GeneratedOriginalObserverPKI, ep OriginalObserverPKIEndpoint, def OriginalObserverHostDefinition, cri OriginalObserverHostCRI) ([]byte, error) {
	u, e := url.Parse(ep.Endpoint.URL)
	if e != nil || net.ParseIP(u.Hostname()) == nil {
		return nil, ErrInstall
	}
	material := path.Join(def.MaterialDirectory, "node-"+hash([]byte(ep.NodeUID))[:24])
	anchorKind := ep.Kind
	if ep.Kind == "shared" {
		anchorKind = "whole"
	}
	args := []string{path.Join(def.BinaryDirectory, originalObserverBinary[ep.Kind]), "--node", ep.Node, "--node-uid", ep.NodeUID, "--machine-id", ep.MachineID, "--boot-id", ep.BootID, "--host-root", "/", "--host-proc", "/proc", "--listen", u.Host, "--crictl", cri.Binary, "--runtime-endpoint", cri.Endpoint, "--client-ca", path.Join(material, "observer-ca.pem"), "--tls-cert", path.Join(material, ep.Kind+"-server.pem"), "--tls-key", path.Join(material, ep.Kind+"-server-key.pem"), "--anchor-key", path.Join(material, anchorKind+"-anchor.key"), "--controller-uri", pki.ClientURI}
	args, e = sharedObserverHostArgs(args, ep, def)
	if e != nil {
		return nil, e
	}
	quoted := make([]string, len(args))
	for n, arg := range args {
		quoted[n] = observerUnitArg(arg)
	}
	// Preserve the real host's PID/network/mount/user namespaces. Sandboxing
	// which supplies a synthetic /proc or root would invalidate native proof.
	unit := "[Unit]\nDescription=Clawreef " + ep.Kind + " native observer on " + ep.Node + "\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\nUMask=0077\nExecStart=" + strings.Join(quoted, " ") + "\nRestart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nPrivateTmp=false\nPrivateNetwork=false\nPrivateDevices=false\nPrivateUsers=false\nPrivateMounts=false\n\n[Install]\nWantedBy=multi-user.target\n"
	return []byte(unit), nil
}

func observerHostInstallScript(ep OriginalObserverPKIEndpoint, def OriginalObserverHostDefinition, cri OriginalObserverHostCRI, kinds []string) []byte {
	material := path.Join(def.MaterialDirectory, "node-"+hash([]byte(ep.NodeUID))[:24])
	var script strings.Builder
	script.WriteString("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n[[ ${EUID} -eq 0 && $(uname -s) == Linux && $(uname -m) == x86_64 ]] || exit 21\ncd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\"\nfor tool in install sha256sum stat systemctl flock sync; do command -v \"$tool\" >/dev/null || exit 22; done\nsha256sum --strict -c payload.sha256 >/dev/null\n")
	script.WriteString("[[ $(cat /etc/machine-id) == " + observerShellArg(ep.MachineID) + " && $(cat /proc/sys/kernel/random/boot_id) == " + observerShellArg(ep.BootID) + " ]] || exit 23\n")
	u, _ := url.Parse(cri.Endpoint)
	script.WriteString("[[ -S " + observerShellArg(u.Path) + " && ! -L " + observerShellArg(u.Path) + " ]] || exit 24\n")
	script.WriteString("safe_parent() { local item=$1 mode; while [[ $item != / ]]; do if [[ -e $item || -L $item ]]; then [[ -d $item && ! -L $item && $(stat -c %u -- \"$item\") == 0 ]] || exit 26; mode=$(stat -c %a -- \"$item\"); (( (8#$mode & 0022) == 0 )) || exit 26; fi; item=$(dirname -- \"$item\"); done; }\n")
	for _, directory := range []string{material, def.BinaryDirectory, path.Dir(cri.Binary), path.Dir(u.Path), "/etc/systemd/system"} {
		script.WriteString("safe_parent " + observerShellArg(directory) + "\n")
	}
	if def.SharedRuntime != nil {
		store := sharedObserverHostDirectory(def.SharedRuntime, ep.NodeUID)
		script.WriteString("safe_parent " + observerShellArg(store) + "\n")
		script.WriteString("[[ -d /sys/fs/cgroup && ! -L /sys/fs/cgroup && $(stat -f -c %T -- /sys/fs/cgroup) == cgroup2fs ]] || exit 29\n")
	}
	// The preflight uses the bundled official executable only if its selected
	// create-only destination is absent. Both paths are pinned before execution.
	script.WriteString("check_crictl() { local binary=$1; [[ -f $binary && ! -L $binary && $(stat -c %u -- \"$binary\") == 0 ]] || exit 24; local mode; mode=$(stat -c %a -- \"$binary\"); (( (8#$mode & 0022) == 0 )) || exit 24; [[ $(sha256sum -- \"$binary\" | cut -d ' ' -f 1) == " + observerShellArg(cri.BinarySHA256) + " ]] || exit 25; }\n")
	if cri.ReleaseBinary.File != "" {
		script.WriteString("cri_probe=" + observerShellArg(cri.Binary) + "\nif [[ ! -e $cri_probe && ! -L $cri_probe ]]; then cri_probe=./" + observerHostCRIBundleName + "; fi\ncheck_crictl \"$cri_probe\"\n[[ $(\"$cri_probe\" --version) == 'crictl version v1.31.1' ]] || exit 25\n")
	} else {
		script.WriteString("cri_probe=" + observerShellArg(cri.Binary) + "\ncheck_crictl \"$cri_probe\"\n")
	}
	script.WriteString("\"$cri_probe\" --runtime-endpoint " + observerShellArg(cri.Endpoint) + " --timeout 5s version >/dev/null\n")
	script.WriteString("[[ ${1:-} == --apply ]] || { echo 'local preflight only; no installation or source proof'; exit 0; }\n")
	script.WriteString("if [[ ! -d " + observerShellArg(material) + " ]]; then install -d -o 0 -g 0 -m 0700 -- " + observerShellArg(material) + "; fi\nexec 9>" + observerShellArg(path.Join(material, ".install.lock")) + "\nflock -n 9 || exit 27\n")
	script.WriteString("if [[ ! -d " + observerShellArg(def.BinaryDirectory) + " ]]; then install -d -o 0 -g 0 -m 0755 -- " + observerShellArg(def.BinaryDirectory) + "; fi\n")
	script.WriteString("copy_exact() { local source=$1 target=$2 mode=$3; if [[ -e $target || -L $target ]]; then [[ -f $target && ! -L $target && $(stat -c %u -- \"$target\") == 0 && $(stat -c %a -- \"$target\") == $mode && $(sha256sum -- \"$source\" | cut -d ' ' -f 1) == $(sha256sum -- \"$target\" | cut -d ' ' -f 1) ]] || exit 28; else install -o 0 -g 0 -m \"$mode\" -- \"$source\" \"$target\"; fi; }\n")
	if cri.ReleaseBinary.File != "" {
		script.WriteString("if [[ ! -d " + observerShellArg(path.Dir(cri.Binary)) + " ]]; then install -d -o 0 -g 0 -m 0755 -- " + observerShellArg(path.Dir(cri.Binary)) + "; fi\ncopy_exact " + observerHostCRIBundleName + " " + observerShellArg(cri.Binary) + " 755\ncheck_crictl " + observerShellArg(cri.Binary) + "\n")
	}
	if def.SharedRuntime != nil {
		store := observerShellArg(sharedObserverHostDirectory(def.SharedRuntime, ep.NodeUID))
		script.WriteString("if [[ ! -e " + store + " && ! -L " + store + " ]]; then install -d -o 0 -g 0 -m 0700 -- " + store + "; fi\n")
		script.WriteString("[[ -d " + store + " && ! -L " + store + " && $(stat -c %u:%g:%a -- " + store + ") == 0:0:700 ]] || exit 29\n")
		script.WriteString("sync -f -- " + store + "\n")
	}
	script.WriteString("copy_exact observer-ca.pem " + observerShellArg(path.Join(material, "observer-ca.pem")) + " 600\n")
	units := []string{}
	for _, kind := range kinds {
		names := []string{kind + "-server.pem", kind + "-server-key.pem"}
		if kind != "shared" {
			names = append(names, kind+"-anchor.key")
		}
		for _, name := range names {
			script.WriteString("copy_exact " + observerShellArg(name) + " " + observerShellArg(path.Join(material, name)) + " 600\n")
		}
		binary := originalObserverBinary[kind]
		unit := "clawreef-" + binary + ".service"
		units = append(units, observerShellArg(unit))
		script.WriteString("copy_exact " + observerShellArg(binary) + " " + observerShellArg(path.Join(def.BinaryDirectory, binary)) + " 755\n")
		script.WriteString("copy_exact " + observerShellArg(unit) + " " + observerShellArg(path.Join("/etc/systemd/system", unit)) + " 644\n")
	}
	script.WriteString("systemctl daemon-reload\nsystemctl enable --now " + strings.Join(units, " ") + "\nsystemctl is-active --quiet " + strings.Join(units, " ") + "\necho 'host observer services active; TLS connectivity and native source proof still require independent validation'\n")
	return []byte(script.String())
}

// ProduceOriginalObserverHostMaterials consumes A's actual PKI contract and
// repeats real original authentication/Kube identities before and after every
// output. Per-node private bundles contain ONLY that node's server/anchor keys,
// public CA, exact selected release ELFs and reviewed systemd/install scripts.
// The controller client key is never distributed to observer hosts.
func (i *Installer) ProduceOriginalObserverHostMaterials(ctx context.Context, password []byte, pin EnrollmentPin, file, digest, directory string) (OriginalObserverHostMaterialsReceipt, error) {
	var zero OriginalObserverHostMaterialsReceipt
	if i == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: file, SHA256: digest}, 262144)
	var def OriginalObserverHostDefinition
	if e != nil || decodeExact(raw, &def) != nil || def.Version != "original-observer-host-deployment.v1" || !observerHostPath(def.BinaryDirectory) || !observerHostPath(def.MaterialDirectory) || len(def.Binaries) < 1 || len(def.Binaries) > 4 {
		return zero, ErrInstall
	}
	definitionRaw, e := readBootstrapSourcePin(def.PKIDefinition, 262144)
	var definition OriginalObserverPKIDefinition
	if e != nil || decodeExact(definitionRaw, &definition) != nil {
		return zero, ErrInstall
	}
	pkiRaw, e := readBootstrapSourcePin(def.PKIReceipt, 262144)
	var pki GeneratedOriginalObserverPKI
	if e != nil || decodeExact(pkiRaw, &pki) != nil || pki.Version != "original-observer-pki-materials.v1" || pki.Status != "materialized_uninstalled_not_task_authority" || pki.PlanSHA256 != i.planHash || pki.DefinitionSHA256 != def.PKIDefinition.SHA256 || pki.Namespace != i.plan.Target.Namespace || pki.NamespaceUID != i.plan.Target.NamespaceUID || !reflect.DeepEqual(pki.Enrollment, pin) {
		return zero, ErrInstall
	}
	if validateSharedObserverHostConfig(def, pki) != nil {
		return zero, ErrInstall
	}
	s, e := i.authenticate(ctx, password)
	if e != nil {
		return zero, e
	}
	before, now, e := s.observerPKIOwner(ctx, pin)
	if e != nil || before.cas != pki.AuthorityHead || now.Before(pki.NotBefore) || !now.Before(pki.NotAfter) || pki.ClientURI != observerPKIURI(definition.TrustDomain, i.plan.Target.InstallationID, i.plan.Target.NamespaceUID, "controller-service-account", definition.ServiceAccountUID) {
		return zero, ErrInstall
	}
	check := func() error {
		inputs := []BootstrapSourceFilePin{{File: file, SHA256: digest}, def.PKIDefinition, def.PKIReceipt, pki.CA, pki.ClientCertificate, pki.ClientKey}
		for _, ep := range pki.Endpoints {
			inputs = append(inputs, ep.Certificate, ep.PrivateKey, ep.AnchorKey)
		}
		for _, input := range inputs {
			actual, e := readBootstrapSourcePin(input, 262144)
			clear(actual)
			if e != nil {
				return ErrInstall
			}
		}
		if validateSharedObserverHostConfig(def, pki) != nil {
			return ErrInstall
		}
		for _, input := range def.Binaries {
			actual, e := readObserverHostFile(input, 64<<20)
			clear(actual)
			if e != nil {
				return ErrInstall
			}
		}
		for _, cri := range def.CRI {
			if cri.ReleaseBinary.File == "" {
				continue
			}
			actual, e := readObserverHostFile(cri.ReleaseBinary, 64<<20)
			clear(actual)
			if e != nil {
				return ErrInstall
			}
		}
		actual, e := s.readObserverPKIState(ctx, definition)
		if e != nil || actual.ServiceAccountUID != pki.ServiceAccountUID {
			return ErrInstall
		}
		want := append([]OriginalObserverPKIEndpoint(nil), pki.Endpoints...)
		for n := range want {
			want[n].Certificate = BootstrapSourceFilePin{}
			want[n].PrivateKey = BootstrapSourceFilePin{}
			want[n].AnchorKey = BootstrapSourceFilePin{}
		}
		if !reflect.DeepEqual(actual.Endpoints, want) {
			return ErrInstall
		}
		current, clock, e := s.observerPKIOwner(ctx, pin)
		if e != nil || current.cas != before.cas || clock.Before(now) || !clock.Before(pki.NotAfter) {
			return ErrInstall
		}
		now = clock
		return nil
	}
	if check() != nil {
		return zero, ErrInstall
	}
	ca, e := readBootstrapSourcePin(pki.CA, 262144)
	if e != nil {
		return zero, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return zero, ErrInstall
	}
	clientCert, e := readBootstrapSourcePin(pki.ClientCertificate, 262144)
	if e != nil {
		return zero, e
	}
	clientKey, e := readBootstrapSourcePin(pki.ClientKey, 262144)
	if e != nil {
		return zero, e
	}
	clientPair, e := tls.X509KeyPair(clientCert, clientKey)
	clear(clientKey)
	if e != nil {
		return zero, ErrInstall
	}
	clientLeaf, e := x509.ParseCertificate(clientPair.Certificate[0])
	if e != nil || len(clientLeaf.URIs) != 1 || clientLeaf.URIs[0].String() != pki.ClientURI {
		return zero, ErrInstall
	}
	if _, e := clientLeaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); e != nil {
		return zero, ErrInstall
	}
	binaries := map[string][]byte{}
	for kind, input := range def.Binaries {
		if originalObserverBinary[kind] == "" {
			return zero, ErrInstall
		}
		binary, e := readObserverHostFile(input, 64<<20)
		if e != nil || len(binary) < 64 || !bytes.Equal(binary[:4], []byte{0x7f, 'E', 'L', 'F'}) || binary[4] != 2 || binary[5] != 1 || binary[18] != 0x3e || binary[19] != 0 {
			return zero, ErrInstall
		}
		binaries[kind] = binary
	}
	criByNode := map[string]OriginalObserverHostCRI{}
	for _, cri := range def.CRI {
		u, e := url.Parse(cri.Endpoint)
		if cri.Node == "" || cri.NodeUID == "" || criByNode[cri.Node].Node != "" || !observerHostPath(cri.Binary) || !digestPattern.MatchString(cri.BinarySHA256) || e != nil || u.Scheme != "unix" || u.Host != "" || !observerHostPath(u.Path) || u.RawQuery != "" || u.Fragment != "" {
			return zero, ErrInstall
		}
		if cri.ReleaseBinary != (BootstrapSourceFilePin{}) {
			if cri.ReleaseBinary.SHA256 != observerHostCRIBinarySHA256 || cri.BinarySHA256 != cri.ReleaseBinary.SHA256 {
				return zero, ErrInstall
			}
			binary, e := readObserverHostFile(cri.ReleaseBinary, 64<<20)
			if e != nil || len(binary) < 64 || !bytes.Equal(binary[:4], []byte{0x7f, 'E', 'L', 'F'}) || binary[4] != 2 || binary[5] != 1 || binary[18] != 0x3e || binary[19] != 0 {
				return zero, ErrInstall
			}
		}
		criByNode[cri.Node] = cri
	}
	grouped := map[string][]OriginalObserverPKIEndpoint{}
	for _, ep := range pki.Endpoints {
		grouped[ep.Node] = append(grouped[ep.Node], ep)
	}
	if len(grouped) == 0 || len(grouped) > 16 || len(grouped) != len(criByNode) || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	receipt := OriginalObserverHostMaterialsReceipt{Version: "original-observer-host-materials.v1", Status: "materialized_uninstalled_no_native_source_proof", PlanSHA256: i.planHash, DefinitionSHA256: digest, PKIReceiptSHA256: def.PKIReceipt.SHA256, NodeBundles: map[string]BootstrapSourceFilePin{}, AuthorityHead: before.cas}
	for node, endpoints := range grouped {
		cri := criByNode[node]
		if cri.NodeUID != endpoints[0].NodeUID {
			return zero, ErrInstall
		}
		actualNode, e := i.kube.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
		if e != nil || actualNode.Status.NodeInfo.OperatingSystem != "linux" || actualNode.Status.NodeInfo.Architecture != "amd64" {
			return zero, ErrInstall
		}
		files := map[string][]byte{"observer-ca.pem": ca}
		if cri.ReleaseBinary.File != "" {
			binary, e := readObserverHostFile(cri.ReleaseBinary, 64<<20)
			if e != nil {
				return zero, ErrInstall
			}
			files[observerHostCRIBundleName] = binary
		}
		kinds := []string{}
		for _, ep := range endpoints {
			if binaries[ep.Kind] == nil {
				return zero, ErrInstall
			}
			kinds = append(kinds, ep.Kind)
			cert, e := readBootstrapSourcePin(ep.Certificate, 262144)
			if e != nil {
				return zero, e
			}
			key, e := readBootstrapSourcePin(ep.PrivateKey, 262144)
			if e != nil {
				return zero, e
			}
			anchor, e := readBootstrapSourcePin(ep.AnchorKey, 32)
			if e != nil || len(anchor) != 32 {
				return zero, ErrInstall
			}
			pair, e := tls.X509KeyPair(cert, key)
			if e != nil {
				return zero, ErrInstall
			}
			leaf, e := x509.ParseCertificate(pair.Certificate[0])
			u, _ := url.Parse(ep.Endpoint.URL)
			if e != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != ep.Endpoint.ServerURI {
				return zero, ErrInstall
			}
			if _, e := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: u.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now}); e != nil {
				return zero, ErrInstall
			}
			unit, e := observerHostUnit(pki, ep, def, cri)
			if e != nil {
				return zero, e
			}
			files[ep.Kind+"-server.pem"], files[ep.Kind+"-server-key.pem"] = cert, key
			if ep.Kind != "shared" {
				files[ep.Kind+"-anchor.key"] = anchor
			} else {
				clear(anchor)
			}
			files[originalObserverBinary[ep.Kind]] = binaries[ep.Kind]
			files["clawreef-"+originalObserverBinary[ep.Kind]+".service"] = unit
		}
		sort.Strings(kinds)
		checks := []string{}
		for name, content := range files {
			checks = append(checks, hash(content)+"  "+name)
		}
		sort.Strings(checks)
		files["payload.sha256"] = []byte(strings.Join(checks, "\n") + "\n")
		files["install.sh"] = observerHostInstallScript(endpoints[0], def, cri, kinds)
		metadata, _ := json.Marshal(struct {
			Version, Node, NodeUID, MachineID, BootID, ClientURI string
			Endpoints                                            []OriginalObserverPKIEndpoint
		}{"original-observer-host-bundle.v1", node, endpoints[0].NodeUID, endpoints[0].MachineID, endpoints[0].BootID, pki.ClientURI, endpoints})
		files["node-receipt.json"] = metadata
		var archive bytes.Buffer
		writer := tar.NewWriter(&archive)
		names := []string{}
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			mode := int64(0600)
			if name == "install.sh" || strings.HasPrefix(name, "backup-") || name == observerHostCRIBundleName {
				mode = 0700
			}
			if writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Uid: 0, Gid: 0, Size: int64(len(files[name])), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0)}) != nil {
				return zero, ErrInstall
			}
			if _, e := writer.Write(files[name]); e != nil {
				return zero, ErrInstall
			}
		}
		if writer.Close() != nil || archive.Len() > 200<<20 || check() != nil {
			return zero, ErrInstall
		}
		name := "observer-node-" + hash([]byte(endpoints[0].NodeUID))[:24] + ".private.tar"
		if writeNewFiles(directory, map[string][]byte{name: archive.Bytes()}) != nil {
			return zero, ErrInstall
		}
		output := BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(archive.Bytes())}
		actual, e := readObserverHostFile(output, 200<<20)
		same := e == nil && bytes.Equal(actual, archive.Bytes())
		clear(actual)
		clear(archive.Bytes())
		for key, content := range files {
			if strings.HasSuffix(key, "-key.pem") || strings.HasSuffix(key, "-anchor.key") {
				clear(content)
			}
		}
		if !same || check() != nil {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
		receipt.NodeBundles[node] = output
	}
	if check() != nil {
		return zero, ErrOriginalObserverPKIUnconfirmed
	}
	return receipt, nil
}
