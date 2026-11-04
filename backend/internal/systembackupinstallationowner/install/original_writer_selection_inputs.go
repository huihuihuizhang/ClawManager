package install

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"clawreef/internal/runtimecustody"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	q "clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/staging"
	corev1 "k8s.io/api/core/v1"
)

func originalSelectionNumber(id int) string { return strconv.Itoa(id) }
func originalSelectionGatewayName(id, generation int) string {
	return fmt.Sprintf("gw-%d-%d", id, generation)
}
func originalSelectionProKeyName(id int) string { return "pro-" + strconv.Itoa(id) + "-recovery.key" }

// Only ordinary generated material data and the AEAD-authenticated ORIGINAL
// runtime HTTP payload use this decoder. Their immutable SHA remains over the
// original bytes. Signed owner/authorization records still use decodeExact.
// Canonicalizing for parsing preserves the closed schema/duplicate rejection
// without requiring Runtime Agent's real json.Marshal HTTP bytes or CLI's
// json.Encoder receipt to have been RFC8785 encoded at their original writer.
func decodeOriginalWriterMaterialData(raw []byte, out any) error {
	canonicalRaw, e := jsoncanonicalizer.Transform(raw)
	if e != nil {
		return ErrInstall
	}
	return decodeExact(canonicalRaw, out)
}

func originalSelectionCurrentPin(file string, limit int64) (BootstrapSourceFilePin, error) {
	raw, e := ReadPrivateFile(file, limit)
	defer clear(raw)
	if e != nil || len(raw) == 0 {
		return BootstrapSourceFilePin{}, ErrInstall
	}
	return BootstrapSourceFilePin{File: file, SHA256: hash(raw)}, nil
}

func originalSelectionLiteralDirectory(container corev1.Container, name string) (string, error) {
	// EnvFrom may define this same name; accepting an absent literal would guess
	// an image default or claim to have read the original process environment.
	value := ""
	found := false
	for _, env := range container.Env {
		if env.Name != name {
			continue
		}
		if found || env.ValueFrom != nil {
			return "", ErrInstall
		}
		found = true
		value = env.Value
	}
	if !found || !originalStoppedCleanRoot(value) || strings.Contains(value, "$(") {
		return "", ErrInstall
	}
	return value, nil
}

func (p *OriginalWriterMaintenance) originalSelectionObservers(ctx context.Context, options OriginalWriterSelectionOptions, s *OriginalWriterSetSelection) error {
	raw, e := readBootstrapSourcePin(options.ObserverDefinition, 262144)
	var definition OriginalObserverPKIDefinition
	if e != nil || decodeExact(raw, &definition) != nil {
		return ErrInstall
	}
	receiptRaw, e := readBootstrapSourcePin(options.ObserverReceipt, 262144)
	var receipt GeneratedOriginalObserverPKI
	if e != nil || decodeOriginalWriterMaterialData(receiptRaw, &receipt) != nil {
		return ErrInstall
	}
	i := p.operator.installer
	if receipt.Version != "original-observer-pki-materials.v1" || receipt.Status != "materialized_uninstalled_not_task_authority" || receipt.PlanSHA256 != i.planHash || receipt.DefinitionSHA256 != options.ObserverDefinition.SHA256 || receipt.Enrollment != p.enrollment || receipt.AuthorityHead != p.initial || receipt.Namespace != i.plan.Target.Namespace || receipt.NamespaceUID != i.plan.Target.NamespaceUID || receipt.ClientURI != observerPKIURI(definition.TrustDomain, i.plan.Target.InstallationID, i.plan.Target.NamespaceUID, "controller-service-account", definition.ServiceAccountUID) || !receipt.NotBefore.Before(receipt.NotAfter) || time.Now().Before(receipt.NotBefore) || !time.Now().Before(receipt.NotAfter) {
		return ErrInstall
	}
	actual, e := p.operator.readObserverPKIState(ctx, definition)
	if e != nil || actual.ServiceAccount != receipt.ServiceAccount || actual.ServiceAccountUID != receipt.ServiceAccountUID || len(actual.Endpoints) != len(receipt.Endpoints) {
		return ErrInstall
	}
	s.ObserverCA, s.ObserverCertificate, s.ObserverKey = receipt.CA, receipt.ClientCertificate, receipt.ClientKey
	for _, pin := range []BootstrapSourceFilePin{s.ObserverCA, s.ObserverCertificate, s.ObserverKey} {
		data, e := readBootstrapSourcePin(pin, 262144)
		clear(data)
		if e != nil {
			return ErrInstall
		}
	}
	s.GatewayEndpoints = map[string]q.ProofEndpoint{}
	s.SharedRuntimeEndpoints = map[string]q.ProofEndpoint{}
	s.WholePodEndpoints = map[string]q.ProofEndpoint{}
	s.StoppedProEndpoints = map[string]q.ProofEndpoint{}
	for n, current := range actual.Endpoints {
		retained := receipt.Endpoints[n]
		// Certificate paths belong to generated material; live API identity is
		// independently read above. A retained receipt is never an installed ACK.
		current.Certificate, current.PrivateKey, current.AnchorKey = retained.Certificate, retained.PrivateKey, retained.AnchorKey
		if !reflect.DeepEqual(current, retained) {
			return ErrInstall
		}
		var target map[string]q.ProofEndpoint
		switch current.Kind {
		case "whole":
			target = s.WholePodEndpoints
		case "shared":
			target = s.SharedRuntimeEndpoints
		case "gateway":
			target = s.GatewayEndpoints
		case "stopped-pro":
			target = s.StoppedProEndpoints
		default:
			return ErrInstall
		}
		if _, duplicate := target[current.Node]; duplicate {
			return ErrInstall
		}
		target[current.Node] = current.Endpoint
	}
	if len(s.WholePodEndpoints) == 0 {
		return ErrInstall
	}
	// Parse the actual mTLS files using the same production client constructor.
	_, e = q.NewNodeObservationClient(s.WholePodEndpoints, s.ObserverCA.File, s.ObserverCertificate.File, s.ObserverKey.File)
	if e != nil {
		return ErrInstall
	}
	return nil
}

// Select only an existing immutable encrypted ORIGINAL request. No request is
// rebuilt from current instance settings. A port retry can have multiple
// retained files: the real allocated port and AEAD binding must select exactly
// one original. Missing/ambiguous custody is an explicit prerequisite.
func originalSelectionGatewayCustody(ctx context.Context, installation string, source domain.SourceInstance, row originalGatewayRow, directory string, keyPin BootstrapSourceFilePin) (OriginalGatewaySelection, error) {
	zero := OriginalGatewaySelection{InstanceID: source.ID}
	if source.Status == "stopped" {
		return zero, nil
	}
	if source.Status != "running" || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	key, e := readBootstrapSourcePin(keyPin, 32)
	defer clear(key)
	if e != nil || len(key) != 32 {
		return zero, ErrInstall
	}
	entries, e := os.ReadDir(directory)
	if e != nil || len(entries) > 10000 {
		return zero, ErrInstall
	}
	prefix := fmt.Sprintf("gateway-%d-%d-", source.ID, source.Generation)
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".enc") {
			return zero, ErrInstall
		}
		plainSHA := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".enc")
		decoded, e := hex.DecodeString(plainSHA)
		if e != nil || len(decoded) != 32 || strings.ToLower(plainSHA) != plainSHA {
			return zero, ErrInstall
		}
		file := filepath.Join(directory, name)
		sealed, e := ReadSourceMaterialFile(file)
		if e != nil {
			return zero, ErrInstall
		}
		var plain bytes.Buffer
		binding := runtimecustody.Binding(installation, runtimecustody.Identity{InstanceID: source.ID, UserID: source.UserID, Generation: source.Generation, WorkspacePath: source.Workspace}, plainSHA)
		if staging.Open(ctx, bytes.NewReader(sealed), &plain, key, binding, 7<<20) != nil || hash(plain.Bytes()) != plainSHA {
			clear(plain.Bytes())
			return zero, ErrInstall
		}
		var request services.RuntimeAgentCreateGatewayRequest
		e = decodeOriginalWriterMaterialData(plain.Bytes(), &request)
		clear(plain.Bytes())
		plan, planErr := scope.PlanRuntime(scope.Runtime{Type: source.Type, Mode: source.Mode, Backend: source.Backend, Variant: source.Variant, OS: source.OS})
		if e != nil || planErr != nil || request.InstanceID != source.ID || request.UserID != source.UserID || request.Generation != source.Generation || request.WorkspacePath != source.Workspace || request.AgentType != plan.Type || request.UpgradeID != "" {
			return zero, ErrInstall
		}
		matches := request.GatewayPort == row.Port && request.PortRange.Start == row.Port && row.Port <= request.PortRange.End && request.PortRange.End <= 65535 && request.PodUID == row.UID && request.UID > 0 && request.GID > 0
		if !matches {
			continue
		}
		if found {
			return zero, ErrInstall
		}
		found = true
		zero.OriginalCipher = BootstrapSourceFilePin{File: file, SHA256: hash(sealed)}
		zero.OriginalKey = keyPin
		zero.OriginalPlainSHA256 = plainSHA
	}
	if !found || ctx.Err() != nil {
		return zero, ErrInstall
	}
	return zero, nil
}
