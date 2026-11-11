package install

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"time"

	sb "clawreef/internal/systembackup"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type RedisNativeMaterialOptions struct {
	Version, Mode, Deployment, Service, OutputDirectory string
	Policy, Helper, Intent                              BootstrapSourceFilePin
}
type RedisNativeMaterialReceipt struct {
	Version, State, Operation                                                                            string
	Intent, WriterSelection, KeeperSelection, Policy, CA, KeeperCredential, ReaderCredential, CustodyKey BootstrapSourceFilePin
	ServerVersion, RunID                                                                                 string
}
type redisNativeIntent struct {
	BeforePodUID, BeforeContainerID, DataClaim, DataClaimUID, DataClaimSpecSHA256, DataPV, DataPVUID, DataPVSpecSHA256 string
	Version, Operation, DeploymentUID, ServiceUID, Container                                                           string
	BeforeDeployment, DesiredDeployment                                                                                apps.DeploymentSpec
	BeforeService, DesiredService                                                                                      core.ServiceSpec
	Before                                                                                                             sb.RedisBootstrapNativeFacts
	Policy                                                                                                             sb.RedisCapturePolicy
	Selection                                                                                                          BootstrapSourceFilePin
	Helper                                                                                                             BootstrapSourceFilePin
}

func redisMaterialPin(directory, name string, raw []byte) BootstrapSourceFilePin {
	return BootstrapSourceFilePin{File: filepath.Join(directory, name), SHA256: hash(raw)}
}

// This is only startup DATA for the separately pinned Redis image. Both the
// actual Pod and its selected Deployment must match; the native helper still
// independently requires INFO process_id=1 and the exact Redis server profile.
func originalRedisEffectiveServerArgs(c *core.Container) ([]string, error) {
	if c == nil {
		return nil, ErrInstall
	}
	if reflect.DeepEqual(c.Command, []string{"redis-server"}) {
		return c.Args, nil
	}
	if len(c.Command) == 0 && len(c.Args) > 0 && c.Args[0] == "redis-server" {
		return c.Args[1:], nil
	}
	return nil, ErrInstall
}
func redisMaterialTLS(server string) ([]byte, []byte, []byte, error) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, ErrInstall
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		return nil, nil, nil, ErrInstall
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "original-redis-source-installation"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return nil, nil, nil, ErrInstall
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, ErrInstall
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: server}, DNSNames: []string{server}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		return nil, nil, nil, ErrInstall
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, nil, ErrInstall
	}
	defer clear(private)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
}

func (i *Installer) redisNativePod(ctx context.Context, name, uid string) (*apps.Deployment, *core.Pod, error) {
	d, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).Get(ctx, name, metav1.GetOptions{})
	if e != nil || string(d.UID) != uid || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Status.ReadyReplicas != 1 || d.Status.ObservedGeneration < d.Generation || len(d.Spec.Template.Spec.Containers) != 1 || len(d.Spec.Template.Spec.InitContainers) != 0 || d.Spec.Template.Spec.HostNetwork || d.Spec.Template.Spec.HostPID {
		return nil, nil, ErrInstall
	}
	selector, e := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if e != nil {
		return nil, nil, ErrInstall
	}
	pods, e := i.kube.CoreV1().Pods(d.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if e != nil || len(pods.Items) != 1 {
		return nil, nil, ErrInstall
	}
	p := &pods.Items[0]
	if p.DeletionTimestamp != nil || p.Status.Phase != core.PodRunning || net.ParseIP(p.Status.PodIP) == nil || len(p.Spec.Containers) != 1 || len(p.Spec.InitContainers) != 0 || len(p.Spec.EphemeralContainers) != 0 || len(p.Status.ContainerStatuses) != 1 {
		return nil, nil, ErrInstall
	}
	parent := metav1.GetControllerOf(p)
	if parent == nil || parent.Kind != "ReplicaSet" {
		return nil, nil, ErrInstall
	}
	rs, e := i.kube.AppsV1().ReplicaSets(d.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil || rs.UID != parent.UID {
		return nil, nil, ErrInstall
	}
	parent = metav1.GetControllerOf(rs)
	if parent == nil || parent.Kind != "Deployment" || parent.UID != d.UID {
		return nil, nil, ErrInstall
	}
	actualContainer, desiredContainer := p.Spec.Containers[0], d.Spec.Template.Spec.Containers[0]
	// Pod admission may add the ordinary SA mount. Pin the actual native
	// executable/image/args here; the actual data PVC/PV/spec is checked separately.
	if actualContainer.Name != desiredContainer.Name || actualContainer.Image != desiredContainer.Image || !reflect.DeepEqual(actualContainer.Command, desiredContainer.Command) || !reflect.DeepEqual(actualContainer.Args, desiredContainer.Args) {
		return nil, nil, ErrInstall
	}
	status := p.Status.ContainerStatuses[0]
	_, startupErr := originalRedisEffectiveServerArgs(&desiredContainer)
	if !status.Ready || status.State.Running == nil || status.ImageID != originalPeerRedisImage || status.ContainerID == "" || startupErr != nil || !originalPeerNativeEntry(&p.Spec, &p.Spec.Containers[0], "redis-server") {
		return nil, nil, ErrInstall
	}
	return d, p, nil
}

// Each mode is a NEW real original administrator/enrollment action. Prepare
// writes durable intent before native changes; apply sends at most once;
// query only reads. Recovery advances object RVs and cancels the old native
// connection before restoring original specs. No mode asserts a backup hold.
func (i *Installer) ProduceOriginalRedisNativeMaterials(ctx context.Context, password []byte, enrollment EnrollmentPin, writerPin, kubePin BootstrapSourceFilePin, opt RedisNativeMaterialOptions) (_ RedisNativeMaterialReceipt, resultErr error) {
	var zero RedisNativeMaterialReceipt
	phase := "input_validation"
	defer func() {
		if resultErr != nil {
			resultErr = OriginalRedisMaterialFailure{phase: phase, cause: resultErr}
		}
	}()
	if runtime.GOOS != "linux" || i == nil || ctx == nil || ctx.Err() != nil || opt.Version != "original-redis-native-material-options.v1" || privateDirectory(opt.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	phase = "owner_authentication"
	operator, e := i.authenticate(ctx, password)
	if e != nil || operator.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	phase = "kubernetes_transport"
	cfg, e := i.originalRedisRESTConfig(ctx, kubePin)
	if e != nil {
		return zero, ErrInstall
	}
	phase = "writer_selection"
	raw, e := readBootstrapSourcePin(writerPin, 262144)
	var selection OriginalWriterSetSelection
	if e != nil || decodeExact(raw, &selection) != nil || selection.Version != OriginalWriterSetSelectionVersion {
		return zero, ErrInstall
	}
	roster := map[string]string{}
	role := map[string]string{}
	for _, d := range selection.Deployments {
		if roster[d.Name] != "" {
			return zero, ErrInstall
		}
		roster[d.Name] = d.UID
		role[d.Name] = d.Role
	}
	guard := func() error {
		if operator.authority(ctx, enrollment) != nil {
			return ErrInstall
		}
		data, e := readBootstrapSourcePin(writerPin, 262144)
		clear(data)
		if e != nil {
			return ErrInstall
		}
		current, e := i.kube.AppsV1().Deployments(i.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
		if e != nil || len(current.Items) != len(roster) {
			return ErrInstall
		}
		for _, d := range current.Items {
			if roster[d.Name] != string(d.UID) || d.DeletionTimestamp != nil {
				return ErrInstall
			}
		}
		return nil
	}
	phase = "platform_roster"
	if guard() != nil {
		return zero, ErrInstall
	}
	phase = "retained_native_intent"
	intentFile := filepath.Join(opt.OutputDirectory, "redis-native-intent.private.json")
	var intent redisNativeIntent
	if opt.Mode != "prepare" {
		if opt.Intent.File != intentFile {
			return zero, ErrInstall
		}
		body, e := readBootstrapSourcePin(opt.Intent, 262144)
		if e != nil || decodeExact(body, &intent) != nil || intent.Version != "original-redis-native-intent.v1" || intent.Selection != writerPin {
			return zero, ErrInstall
		}
		opt.Deployment = ""
		for name, uid := range roster {
			if uid == intent.DeploymentUID {
				if opt.Deployment != "" {
					return zero, ErrInstall
				}
				opt.Deployment = name
			}
		}
		opt.Service = ""
		services, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).List(ctx, metav1.ListOptions{})
		if e != nil {
			return zero, ErrInstall
		}
		for _, s := range services.Items {
			if string(s.UID) == intent.ServiceUID {
				opt.Service = s.Name
			}
		}
		if opt.Deployment == "" || opt.Service == "" {
			return zero, ErrInstall
		}
	}
	if role[opt.Deployment] != "writer" {
		return zero, ErrInstall
	}
	phase = "original_redis_pod"
	d, p, e := i.redisNativePod(ctx, opt.Deployment, roster[opt.Deployment])
	if e != nil {
		return zero, ErrInstall
	}
	phase = "original_redis_service"
	service, e := i.kube.CoreV1().Services(d.Namespace).Get(ctx, opt.Service, metav1.GetOptions{})
	if e != nil || service.DeletionTimestamp != nil || service.Spec.Type != core.ServiceTypeClusterIP || service.UID == "" || !labels.SelectorFromSet(service.Spec.Selector).Matches(labels.Set(p.Labels)) {
		return zero, ErrInstall
	}
	if opt.Mode == "prepare" {
		phase = "original_plain_redis_launch"
		args, startupErr := originalRedisEffectiveServerArgs(&d.Spec.Template.Spec.Containers[0])
		if len(selection.RedisReadKeepers) != 0 || startupErr != nil || !reflect.DeepEqual(args, []string{"--appendonly", "yes"}) {
			return zero, ErrInstall
		}
		nonce := make([]byte, 16)
		if _, e = rand.Read(nonce); e != nil {
			return zero, ErrInstall
		}
		operation := hex.EncodeToString(nonce)
		phase = "original_redis_native_inspection"
		before, e := i.originalRedisHelper(ctx, cfg, p.Name, p.Spec.Containers[0].Name, opt.Helper, sb.RedisBootstrapNativeRequest{Mode: "inspect", Operation: operation})
		if e != nil || before.ACLFile != "" || before.TLSport != "0" {
			return zero, ErrInstall
		}
		phase = "persistent_data_volume"
		persistent := false
		var dataClaim *core.PersistentVolumeClaim
		var dataPV *core.PersistentVolume
		for _, m := range p.Spec.Containers[0].VolumeMounts {
			if m.ReadOnly || m.SubPath != "" || m.SubPathExpr != "" || m.MountPath != before.DataDirectory {
				continue
			}
			for _, v := range p.Spec.Volumes {
				if v.Name == m.Name && v.PersistentVolumeClaim != nil && !v.PersistentVolumeClaim.ReadOnly {
					claim, e := i.kube.CoreV1().PersistentVolumeClaims(d.Namespace).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
					if e != nil || claim.Status.Phase != core.ClaimBound || claim.Spec.VolumeName == "" {
						return zero, ErrInstall
					}
					pv, e := i.kube.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
					if e != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID {
						return zero, ErrInstall
					}
					if persistent {
						return zero, ErrInstall
					}
					persistent = true
					dataClaim = claim
					dataPV = pv
				}
			}
		}
		if !persistent {
			return zero, ErrInstall
		}
		phase = "capture_policy"
		policyRaw, e := readBootstrapSourcePin(opt.Policy, 65536)
		var policy sb.RedisCapturePolicy
		if e != nil || decodeExact(policyRaw, &policy) != nil {
			return zero, ErrInstall
		}
		policy.ServerID = before.RunID
		if policy.Validate() != nil {
			return zero, ErrInstall
		}
		phase = "source_tls_and_credentials"
		server := service.Name + "." + d.Namespace + ".svc"
		ca, cert, key, e := redisMaterialTLS(server)
		if e != nil {
			return zero, ErrInstall
		}
		defer clear(key)
		password := func() ([]byte, error) {
			raw := make([]byte, 32)
			if _, e := rand.Read(raw); e != nil {
				return nil, e
			}
			defer clear(raw)
			return []byte(base64.RawURLEncoding.EncodeToString(raw)), nil
		}
		keeperPassword, e := password()
		if e != nil {
			return zero, ErrInstall
		}
		defer clear(keeperPassword)
		readerPassword, e := password()
		if e != nil {
			return zero, ErrInstall
		}
		defer clear(readerPassword)
		keeper, reader := "sbk_keeper_"+operation[:16], "sbk_reader_"+operation[:16]
		keeperRaw, _ := canonical(originalRedisCredential{Username: keeper, Password: keeperPassword})
		defer clear(keeperRaw)
		readerRaw, _ := canonical(originalRedisCredential{Username: reader, Password: readerPassword})
		defer clear(readerRaw)
		custody := make([]byte, 32)
		if _, e = rand.Read(custody); e != nil {
			return zero, ErrInstall
		}
		defer clear(custody)
		desired := d.Spec.DeepCopy()
		directory := filepath.Join(before.DataDirectory, ".system-backup-redis-"+operation)
		desired.Template.Spec.Containers[0].Args = append(desired.Template.Spec.Containers[0].Args, "--aclfile", filepath.Join(directory, "users.acl"), "--tls-port", "6380", "--tls-cert-file", filepath.Join(directory, "server.pem"), "--tls-key-file", filepath.Join(directory, "server-key.pem"), "--tls-ca-cert-file", filepath.Join(directory, "ca.pem"), "--tls-auth-clients", "no")
		desiredService := service.Spec.DeepCopy()
		for _, port := range desiredService.Ports {
			if port.Port == 6380 || port.Name == "backup-tls" {
				return zero, ErrInstall
			}
		}
		port := core.ServicePort{Name: "backup-tls", Port: 6380, Protocol: core.ProtocolTCP}
		port.TargetPort.IntVal = 6380
		desiredService.Ports = append(desiredService.Ports, port)
		intent = redisNativeIntent{Version: "original-redis-native-intent.v1", Operation: operation, DeploymentUID: string(d.UID), ServiceUID: string(service.UID), Container: p.Spec.Containers[0].Name, BeforeDeployment: d.Spec, DesiredDeployment: *desired, BeforeService: service.Spec, DesiredService: *desiredService, Before: before, Policy: policy, Selection: writerPin, Helper: opt.Helper}
		intent.BeforePodUID = string(p.UID)
		intent.BeforeContainerID = p.Status.ContainerStatuses[0].ContainerID
		intent.DataClaim = dataClaim.Name
		intent.DataClaimUID = string(dataClaim.UID)
		intent.DataClaimSpecSHA256 = originalObjectSHA(dataClaim.Spec)
		intent.DataPV = dataPV.Name
		intent.DataPVUID = string(dataPV.UID)
		intent.DataPVSpecSHA256 = originalObjectSHA(dataPV.Spec)
		intentRaw, e := canonical(intent)
		if e != nil {
			return zero, ErrInstall
		}
		phase = "private_material_outputs"
		if guard() != nil || writeNewFiles(opt.OutputDirectory, map[string][]byte{"redis-native-intent.private.json": intentRaw, "redis-ca.pem": ca, "redis-server.pem": cert, "redis-server-key.pem": key, "redis-keeper.private.json": keeperRaw, "redis-reader.private.json": readerRaw, "redis-custody.key": custody}) != nil {
			return zero, ErrInstall
		}
		if guard() != nil {
			return zero, ErrInstall
		}
		phase = "original_redis_native_prepare"
		result, e := i.originalRedisHelper(ctx, cfg, p.Name, intent.Container, intent.Helper, sb.RedisBootstrapNativeRequest{Mode: "prepare", Operation: operation, ExpectedRunID: before.RunID, DataDirectory: before.DataDirectory, Keeper: keeper, Reader: reader, KeeperPassword: keeperPassword, ReaderPassword: readerPassword, CA: ca, Certificate: cert, Key: key, Prefixes: policy.Policy.Prefixes})
		if e != nil || result.RunID != before.RunID || guard() != nil {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
		return RedisNativeMaterialReceipt{Version: "original-redis-native-materials.v1", State: "native_prepared_loopback_isolated_requires_apply", Operation: operation, Intent: redisMaterialPin(opt.OutputDirectory, "redis-native-intent.private.json", intentRaw), ServerVersion: before.ServerVersion, RunID: before.RunID}, nil
	}
	phase = "native_transition_readback"
	if string(service.UID) != intent.ServiceUID {
		return zero, ErrInstall
	}
	receipt := RedisNativeMaterialReceipt{Version: "original-redis-native-materials.v1", Operation: intent.Operation, Intent: opt.Intent}
	patch := func(recover bool) error {
		if guard() != nil {
			return ErrInstall
		}
		if !reflect.DeepEqual(d.Spec, intent.BeforeDeployment) && !reflect.DeepEqual(d.Spec, intent.DesiredDeployment) {
			return ErrInstall
		}
		if !reflect.DeepEqual(service.Spec, intent.BeforeService) && !reflect.DeepEqual(service.Spec, intent.DesiredService) {
			return ErrInstall
		}
		target, targetService := intent.DesiredDeployment, intent.DesiredService
		if recover {
			target, targetService = intent.BeforeDeployment, intent.BeforeService
		}
		marker := "apply.sent"
		if recover {
			nonce := make([]byte, 16)
			if _, e = rand.Read(nonce); e != nil {
				return ErrInstall
			}
			marker = "recover." + hex.EncodeToString(nonce) + ".sent"
		}
		if writeNewFiles(opt.OutputDirectory, map[string][]byte{marker: []byte(intent.Operation)}) != nil {
			return ErrInstall
		}
		servicePatch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": intent.ServiceUID}, {"op": "test", "path": "/metadata/resourceVersion", "value": service.ResourceVersion}, {"op": "replace", "path": "/spec", "value": targetService}})
		if recover {
			annotations := map[string]string{}
			for k, v := range service.Annotations {
				annotations[k] = v
			}
			annotations["backup.clawreef.io/redis-install-cancelled"] = marker
			var ops []map[string]any
			json.Unmarshal(servicePatch, &ops)
			ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": annotations})
			servicePatch, _ = json.Marshal(ops)
		}
		if _, e = i.kube.CoreV1().Services(d.Namespace).Patch(ctx, service.Name, types.JSONPatchType, servicePatch, metav1.PatchOptions{}); e != nil {
			return ErrOriginalObserverPKIUnconfirmed
		}
		deploymentPatch, _ := json.Marshal([]map[string]any{{"op": "test", "path": "/metadata/uid", "value": intent.DeploymentUID}, {"op": "test", "path": "/metadata/resourceVersion", "value": d.ResourceVersion}, {"op": "replace", "path": "/spec", "value": target}})
		if recover {
			annotations := map[string]string{}
			for k, v := range d.Annotations {
				annotations[k] = v
			}
			annotations["backup.clawreef.io/redis-install-cancelled"] = marker
			var ops []map[string]any
			json.Unmarshal(deploymentPatch, &ops)
			ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": annotations})
			deploymentPatch, _ = json.Marshal(ops)
		}
		if _, e = i.kube.AppsV1().Deployments(d.Namespace).Patch(ctx, d.Name, types.JSONPatchType, deploymentPatch, metav1.PatchOptions{}); e != nil {
			return ErrOriginalObserverPKIUnconfirmed
		}
		return guard()
	}
	switch opt.Mode {
	case "apply":
		if !reflect.DeepEqual(d.Spec, intent.BeforeDeployment) || !reflect.DeepEqual(service.Spec, intent.BeforeService) {
			return zero, ErrInstall
		}
		if e = patch(false); e != nil {
			return zero, e
		}
		receipt.State = "rollout_sent_requires_query_and_finalize"
		return receipt, nil
	case "query":
		receipt.State = "original_specs"
		if reflect.DeepEqual(d.Spec, intent.DesiredDeployment) && reflect.DeepEqual(service.Spec, intent.DesiredService) {
			receipt.State = "desired_specs_ready_requires_native_finalize"
		} else if !reflect.DeepEqual(d.Spec, intent.BeforeDeployment) || !reflect.DeepEqual(service.Spec, intent.BeforeService) {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
		return receipt, nil
	case "recover":
		if _, e = i.originalRedisHelper(ctx, cfg, p.Name, intent.Container, intent.Helper, sb.RedisBootstrapNativeRequest{Mode: "cancel", Operation: intent.Operation, ExpectedRunID: intent.Before.RunID, DataDirectory: intent.Before.DataDirectory}); e != nil {
			return zero, e
		}
		if e = patch(true); e != nil {
			return zero, e
		}
		receipt.State = "original_spec_restore_sent_requires_recover_finalize"
		return receipt, nil
	case "recover-finalize":
		if !reflect.DeepEqual(d.Spec, intent.BeforeDeployment) || !reflect.DeepEqual(service.Spec, intent.BeforeService) {
			return zero, ErrInstall
		}
		if _, e = i.originalRedisHelper(ctx, cfg, p.Name, intent.Container, intent.Helper, sb.RedisBootstrapNativeRequest{Mode: "rollback", Operation: intent.Operation, ExpectedRunID: intent.Before.RunID, DataDirectory: intent.Before.DataDirectory}); e != nil {
			return zero, e
		}
		receipt.State = "original_native_redis_restored_no_backup_claim"
		return receipt, nil
	case "finalize", "query-finalize":
		if intent.BeforePodUID == "" || intent.BeforeContainerID == "" || string(p.UID) == intent.BeforePodUID || p.Status.ContainerStatuses[0].ContainerID == intent.BeforeContainerID {
			return zero, ErrInstall
		}
		claim, e := i.kube.CoreV1().PersistentVolumeClaims(d.Namespace).Get(ctx, intent.DataClaim, metav1.GetOptions{})
		if e != nil || string(claim.UID) != intent.DataClaimUID || claim.Spec.VolumeName != intent.DataPV || originalObjectSHA(claim.Spec) != intent.DataClaimSpecSHA256 {
			return zero, ErrInstall
		}
		pv, e := i.kube.CoreV1().PersistentVolumes().Get(ctx, intent.DataPV, metav1.GetOptions{})
		if e != nil || string(pv.UID) != intent.DataPVUID || originalObjectSHA(pv.Spec) != intent.DataPVSpecSHA256 || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID {
			return zero, ErrInstall
		}
		mounted := false
		for _, volume := range p.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName == claim.Name {
				for _, mount := range p.Spec.Containers[0].VolumeMounts {
					mounted = mounted || mount.Name == volume.Name && mount.MountPath == intent.Before.DataDirectory && !mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
				}
			}
		}
		if !mounted {
			return zero, ErrInstall
		}
		if !reflect.DeepEqual(d.Spec, intent.DesiredDeployment) || !reflect.DeepEqual(service.Spec, intent.DesiredService) {
			return zero, ErrInstall
		}
		ca, e := ReadPrivateFile(filepath.Join(opt.OutputDirectory, "redis-ca.pem"), 65536)
		if e != nil {
			return zero, ErrInstall
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return zero, ErrInstall
		}
		var keeper, reader originalRedisCredential
		keeperRaw, e := ReadPrivateFile(filepath.Join(opt.OutputDirectory, "redis-keeper.private.json"), 65536)
		if e != nil || decodeExact(keeperRaw, &keeper) != nil {
			return zero, ErrInstall
		}
		defer clear(keeperRaw)
		defer clear(keeper.Password)
		readerRaw, e := ReadPrivateFile(filepath.Join(opt.OutputDirectory, "redis-reader.private.json"), 65536)
		if e != nil || decodeExact(readerRaw, &reader) != nil {
			return zero, ErrInstall
		}
		defer clear(readerRaw)
		defer clear(reader.Password)
		server := service.Name + "." + d.Namespace + ".svc"
		var runID string
		for _, credential := range []originalRedisCredential{keeper, reader} {
			db := 0
			if credential.Username == reader.Username {
				db = intent.Policy.Policy.DB
			}
			client, e := sb.ConnectRedis(ctx, sb.RedisOptions{Address: net.JoinHostPort(p.Status.PodIP, strconv.Itoa(6380)), Username: credential.Username, Password: string(credential.Password), Database: db, TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: server}, MaxReplyBytes: 4 << 20})
			if e != nil {
				return zero, ErrInstall
			}
			id, _, e := client.Identity(ctx)
			client.Close()
			if e != nil || runID != "" && runID != id {
				return zero, ErrInstall
			}
			runID = id
		}
		finishMode := "finish"
		if _, e := os.Lstat(filepath.Join(opt.OutputDirectory, "finalize.sent")); e == nil {
			sent, readErr := ReadPrivateFile(filepath.Join(opt.OutputDirectory, "finalize.sent"), 32)
			if readErr != nil || string(sent) != intent.Operation {
				return zero, ErrInstall
			}
			finishMode = "verify-finished"
		} else if opt.Mode == "query-finalize" || !os.IsNotExist(e) {
			return zero, ErrInstall
		} else if writeNewFiles(opt.OutputDirectory, map[string][]byte{"finalize.sent": []byte(intent.Operation)}) != nil {
			return zero, ErrInstall
		}
		// query-finalize is a new authenticated READ of the same original send.
		// It cannot create finalize.sent, call finish, apply, cancel or rollback.
		if opt.Mode == "query-finalize" && finishMode != "verify-finished" {
			return zero, ErrInstall
		}
		result, e := i.originalRedisHelper(ctx, cfg, p.Name, intent.Container, intent.Helper, sb.RedisBootstrapNativeRequest{Mode: finishMode, Operation: intent.Operation, ExpectedRunID: intent.Before.RunID, DataDirectory: intent.Before.DataDirectory})
		if e != nil || result.RunID != runID || result.RunID == intent.Before.RunID || guard() != nil {
			return zero, ErrOriginalObserverPKIUnconfirmed
		}
		custodyFile := filepath.Join(opt.OutputDirectory, "redis-custody.key")
		custody, e := ReadPrivateFile(custodyFile, 32)
		if e != nil || len(custody) != 32 {
			return zero, ErrInstall
		}
		defer clear(custody)
		custodyDirectory := filepath.Join(opt.OutputDirectory, "redis-native-custody")
		if e := os.Mkdir(custodyDirectory, 0700); e != nil && !os.IsExist(e) {
			return zero, ErrInstall
		}
		if privateDirectory(custodyDirectory) != nil {
			return zero, ErrInstall
		}
		policy := intent.Policy
		policy.ServerID = runID
		policyRaw, e := canonical(policy)
		if e != nil {
			return zero, ErrInstall
		}
		selected := OriginalRedisReadKeeperSelection{Deployment: d.Name, DeploymentUID: string(d.UID), ServerName: server, Port: 6380, CA: redisMaterialPin(opt.OutputDirectory, "redis-ca.pem", ca), KeeperCredential: redisMaterialPin(opt.OutputDirectory, "redis-keeper.private.json", keeperRaw), ReaderCredential: redisMaterialPin(opt.OutputDirectory, "redis-reader.private.json", readerRaw), CustodyKey: redisMaterialPin(opt.OutputDirectory, "redis-custody.key", custody), Native: sb.RedisReadGateInput{Namespace: d.Namespace, NamespaceUID: i.plan.Target.NamespaceUID, Pod: p.Name, PodUID: string(p.UID), Container: intent.Container, ImageID: p.Status.ContainerStatuses[0].ImageID, ACLFile: filepath.Join(intent.Before.DataDirectory, ".system-backup-redis-"+intent.Operation, "users.acl"), ServerVersion: result.ServerVersion, KeeperAccount: keeper.Username, ReaderAccount: reader.Username, Policy: policy, CustodyDirectory: custodyDirectory}}
		selection.RedisReadKeepers = []OriginalRedisReadKeeperSelection{selected}
		selectedRaw, e := canonical(selected)
		if e != nil {
			return zero, ErrInstall
		}
		selectionRaw, e := canonical(selection)
		if e != nil {
			return zero, ErrInstall
		}
		for name, body := range map[string][]byte{"redis-read-keeper-selection.json": selectedRaw, "redis-native-writer-selection.json": selectionRaw, "redis-capture-policy.json": policyRaw} {
			file := filepath.Join(opt.OutputDirectory, name)
			if _, e := os.Lstat(file); e == nil {
				current, e := ReadPrivateFile(file, 262144)
				if e != nil || hash(current) != hash(body) {
					return zero, ErrInstall
				}
			} else if !os.IsNotExist(e) || writeNewFiles(opt.OutputDirectory, map[string][]byte{name: body}) != nil {
				return zero, ErrInstall
			}
		}
		receipt.State = "native_tls_and_accounts_read_back_not_a_hold"
		receipt.WriterSelection = redisMaterialPin(opt.OutputDirectory, "redis-native-writer-selection.json", selectionRaw)
		receipt.KeeperSelection = redisMaterialPin(opt.OutputDirectory, "redis-read-keeper-selection.json", selectedRaw)
		receipt.Policy = redisMaterialPin(opt.OutputDirectory, "redis-capture-policy.json", policyRaw)
		receipt.CA = selected.CA
		receipt.KeeperCredential = selected.KeeperCredential
		receipt.ReaderCredential = selected.ReaderCredential
		receipt.CustodyKey = selected.CustodyKey
		receipt.RunID = runID
		receipt.ServerVersion = result.ServerVersion
		return receipt, nil
	default:
		return zero, ErrInstall
	}
}
