package systembackupsourcetlsbootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	apps "k8s.io/api/apps/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type ObjectPin struct{ Name, UID, ResourceVersion, SpecSHA256 string }
type BootstrapPlan struct {
	Operation                                                                                                                          string
	DatabaseAddress                                                                                                                    string
	Version, Namespace, NamespaceUID, ClusterUID, Operator, OperatorUID, AdminUsername, Database, Container, ContainerID, HelperSHA256 string
	Deployment, Pod                                                                                                                    ObjectPin
	Services                                                                                                                           []ObjectPin
	DNSNames, IPAddresses                                                                                                              []string
	Native                                                                                                                             MySQLNativeTLS
}
type ClientOptions struct{ KubeconfigFile, KubeconfigSHA256, Namespace, AdminUsername, PasswordFile, HelperFile, HelperSHA256, OutputDirectory string }
type BootstrapReceipt struct {
	DSNFile, DSNSHA256, SourceTLSFile, SourceTLSSHA256, SQLAccount string
	OperatorSQLTLSVerified                                         bool
	Version, State, Operation, ServerUUID                          string
	PlanFile, PlanSHA256, CAFile, CASHA256                         string
	Result                                                         MySQLHelperResult
}
type Client struct {
	config                                          *rest.Config
	kube                                            kubernetes.Interface
	options                                         ClientOptions
	password, helper                                []byte
	operator, operatorUID, namespaceUID, clusterUID string
}

func sourceInput(file, pin string, max int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return nil, ErrBootstrap
	}
	info, e := os.Lstat(file)
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max || private && runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrBootstrap
	}
	raw, e := os.ReadFile(file)
	after, e2 := os.Lstat(file)
	if e != nil || e2 != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || pin != "" && digest(raw) != pin {
		clear(raw)
		return nil, ErrBootstrap
	}
	return raw, nil
}
func NewClient(ctx context.Context, options ClientOptions) (*Client, error) {
	if ctx == nil || ctx.Err() != nil || options.Namespace == "" {
		return nil, ErrBootstrap
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrBootstrap
	}
	kubeRaw, e := sourceInput(options.KubeconfigFile, options.KubeconfigSHA256, 262144, true)
	if e != nil {
		return nil, e
	}
	config, e := clientcmd.RESTConfigFromKubeConfig(kubeRaw)
	clear(kubeRaw)
	if e != nil || config.Insecure || !strings.HasPrefix(config.Host, "https://") || len(config.CAData) == 0 && config.CAFile == "" {
		return nil, ErrBootstrap
	}
	kube, e := kubernetes.NewForConfig(config)
	if e != nil {
		return nil, ErrBootstrap
	}
	password, e := sourceInput(options.PasswordFile, "", 1024, true)
	if e != nil {
		return nil, e
	}
	helper, e := sourceInput(options.HelperFile, options.HelperSHA256, 64<<20, false)
	if e != nil {
		clear(password)
		return nil, e
	}
	if len(helper) < 64 || !bytes.Equal(helper[:4], []byte{0x7f, 'E', 'L', 'F'}) || helper[4] != 2 || helper[5] != 1 || helper[18] != 0x3e || helper[19] != 0 {
		clear(password)
		return nil, ErrBootstrap
	}
	c := &Client{config: config, kube: kube, options: options, password: password, helper: helper}
	if c.identity(ctx, true) != nil {
		c.Close()
		return nil, ErrBootstrap
	}
	return c, nil
}
func (c *Client) Close() {
	if c != nil {
		clear(c.password)
		clear(c.helper)
	}
}
func (c *Client) identity(ctx context.Context, initial bool) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrBootstrap
	}
	user, e := c.kube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authentication.SelfSubjectReview{}, metav1.CreateOptions{})
	if e != nil || user.Status.UserInfo.Username == "" {
		return ErrBootstrap
	}
	ns, e := c.kube.CoreV1().Namespaces().Get(ctx, c.options.Namespace, metav1.GetOptions{})
	if e != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return ErrBootstrap
	}
	cluster, e := c.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if e != nil || cluster.UID == "" {
		return ErrBootstrap
	}
	if initial {
		c.operator, c.operatorUID, c.namespaceUID, c.clusterUID = user.Status.UserInfo.Username, user.Status.UserInfo.UID, string(ns.UID), string(cluster.UID)
	} else if c.operator != user.Status.UserInfo.Username || c.operatorUID != user.Status.UserInfo.UID || c.namespaceUID != string(ns.UID) || c.clusterUID != string(cluster.UID) {
		return ErrBootstrap
	}
	kube, e := sourceInput(c.options.KubeconfigFile, c.options.KubeconfigSHA256, 262144, true)
	clear(kube)
	if e != nil {
		return e
	}
	return nil
}
func (c *Client) access(ctx context.Context, verb, group, resource, subresource, name string) error {
	r, e := c.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorization.SelfSubjectAccessReview{Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Namespace: c.options.Namespace, Verb: verb, Group: group, Resource: resource, Subresource: subresource, Name: name}}}, metav1.CreateOptions{})
	if e != nil || !r.Status.Allowed || r.Status.Denied || r.Status.EvaluationError != "" {
		return ErrBootstrap
	}
	return nil
}
func objectSHA(value any) string { raw, _ := json.Marshal(value); return digest(raw) }
func (c *Client) discover(ctx context.Context) (BootstrapPlan, *core.Pod, error) {
	var zero BootstrapPlan
	if c.identity(ctx, false) != nil || c.access(ctx, "list", "apps", "deployments", "", "") != nil || c.access(ctx, "list", "", "pods", "", "") != nil || c.access(ctx, "list", "", "services", "", "") != nil {
		return zero, nil, ErrBootstrap
	}
	deployments, e := c.kube.AppsV1().Deployments(c.options.Namespace).List(ctx, metav1.ListOptions{})
	if e != nil {
		return zero, nil, ErrBootstrap
	}
	var selected *apps.Deployment
	container, database := "", ""
	for n := range deployments.Items {
		deployment := &deployments.Items[n]
		for _, candidate := range deployment.Spec.Template.Spec.Containers {
			for _, env := range candidate.Env {
				if env.Name == "MYSQL_DATABASE" && env.Value != "" {
					if selected != nil {
						return zero, nil, ErrBootstrap
					}
					selected = deployment
					container, database = candidate.Name, env.Value
				}
			}
		}
	}
	if selected == nil || selected.UID == "" || selected.DeletionTimestamp != nil || selected.Spec.Replicas == nil || *selected.Spec.Replicas != 1 || !bootstrapDatabase.MatchString(database) {
		return zero, nil, ErrBootstrap
	}
	selector, e := metav1.LabelSelectorAsSelector(selected.Spec.Selector)
	if e != nil || selector.Empty() {
		return zero, nil, ErrBootstrap
	}
	pods, e := c.kube.CoreV1().Pods(c.options.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if e != nil || len(pods.Items) != 1 {
		return zero, nil, ErrBootstrap
	}
	pod := &pods.Items[0]
	if pod.UID == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != core.PodRunning {
		return zero, nil, ErrBootstrap
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" {
		return zero, nil, ErrBootstrap
	}
	rs, e := c.kube.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if e != nil || rs.UID != owner.UID {
		return zero, nil, ErrBootstrap
	}
	owner = metav1.GetControllerOf(rs)
	if owner == nil || owner.Kind != "Deployment" || owner.UID != selected.UID {
		return zero, nil, ErrBootstrap
	}
	cid := ""
	for _, state := range pod.Status.ContainerStatuses {
		if state.Name == container && state.Ready && state.State.Running != nil {
			cid = state.ContainerID
		}
	}
	if cid == "" {
		return zero, nil, ErrBootstrap
	}
	plan := BootstrapPlan{Version: "original-source-tls-bootstrap-plan.v1", Namespace: c.options.Namespace, NamespaceUID: c.namespaceUID, ClusterUID: c.clusterUID, Operator: c.operator, OperatorUID: c.operatorUID, AdminUsername: c.options.AdminUsername, Database: database, Container: container, ContainerID: cid, HelperSHA256: c.options.HelperSHA256, Deployment: ObjectPin{selected.Name, string(selected.UID), selected.ResourceVersion, objectSHA(selected.Spec)}, Pod: ObjectPin{pod.Name, string(pod.UID), pod.ResourceVersion, objectSHA(pod.Spec)}}
	services, e := c.kube.CoreV1().Services(pod.Namespace).List(ctx, metav1.ListOptions{})
	if e != nil {
		return zero, nil, ErrBootstrap
	}
	names, addresses := map[string]bool{}, map[string]bool{}
	serviceAddresses := map[string]string{}
	for _, service := range services.Items {
		if len(service.Spec.Selector) == 0 || service.DeletionTimestamp != nil {
			continue
		}
		matches := true
		for key, value := range service.Spec.Selector {
			matches = matches && pod.Labels[key] == value
		}
		if !matches {
			continue
		}
		mysqlPort := false
		for _, port := range service.Spec.Ports {
			mysqlPort = mysqlPort || port.Port == 3306
		}
		if !mysqlPort {
			continue
		}
		peers, e := c.kube.CoreV1().Pods(pod.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.SelectorFromSet(service.Spec.Selector).String()})
		if e != nil || len(peers.Items) != 1 || peers.Items[0].UID != pod.UID {
			return zero, nil, ErrBootstrap
		}
		plan.Services = append(plan.Services, ObjectPin{service.Name, string(service.UID), service.ResourceVersion, objectSHA(service.Spec)})
		if net.ParseIP(service.Spec.ClusterIP) != nil {
			serviceAddresses[service.Name] = net.JoinHostPort(service.Spec.ClusterIP, "3306")
		} else {
			serviceAddresses[service.Name] = net.JoinHostPort(pod.Status.PodIP, "3306")
		}
		for _, suffix := range []string{"", "." + pod.Namespace, "." + pod.Namespace + ".svc"} {
			names[service.Name+suffix] = true
		}
		for _, ip := range service.Spec.ClusterIPs {
			if net.ParseIP(ip) != nil {
				addresses[ip] = true
			}
		}
	}
	if len(plan.Services) == 0 {
		return zero, nil, ErrBootstrap
	}
	if net.ParseIP(pod.Status.PodIP) != nil {
		addresses[pod.Status.PodIP] = true
	}
	for name := range names {
		plan.DNSNames = append(plan.DNSNames, name)
	}
	for address := range addresses {
		plan.IPAddresses = append(plan.IPAddresses, address)
	}
	sort.Strings(plan.DNSNames)
	sort.Strings(plan.IPAddresses)
	sort.Slice(plan.Services, func(i, j int) bool { return plan.Services[i].Name < plan.Services[j].Name })
	plan.DatabaseAddress = serviceAddresses[plan.Services[0].Name]
	return plan, pod, nil
}

type boundedOutput struct {
	bytes.Buffer
	max int
}

func (b *boundedOutput) Write(raw []byte) (int, error) {
	if len(raw) > b.max-b.Len() {
		return 0, ErrBootstrap
	}
	return b.Buffer.Write(raw)
}
func (c *Client) exec(ctx context.Context, pod, container string, command []string, input io.Reader, max int) ([]byte, error) {
	if c.identity(ctx, false) != nil || c.access(ctx, "create", "", "pods", "exec", pod) != nil {
		return nil, ErrBootstrap
	}
	req := c.kube.CoreV1().RESTClient().Post().Resource("pods").Namespace(c.options.Namespace).Name(pod).SubResource("exec").VersionedParams(&core.PodExecOptions{Container: container, Command: command, Stdin: true, Stdout: true, Stderr: true, TTY: false}, scheme.ParameterCodec)
	executor, e := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if e != nil {
		return nil, ErrBootstrap
	}
	output := &boundedOutput{max: max}
	if executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: input, Stdout: output, Stderr: io.Discard}) != nil {
		return nil, ErrBootstrap
	}
	return output.Bytes(), nil
}
func (c *Client) helperCall(ctx context.Context, plan BootstrapPlan, request MySQLHelperRequest) (MySQLHelperResult, error) {
	var zero MySQLHelperResult
	current, _, e := c.discover(ctx)
	if e != nil || current.Pod.UID != plan.Pod.UID || current.Pod.SpecSHA256 != plan.Pod.SpecSHA256 || current.ContainerID != plan.ContainerID || current.Deployment.UID != plan.Deployment.UID {
		return zero, ErrBootstrap
	}
	nonce := make([]byte, 16)
	if _, e := rand.Read(nonce); e != nil {
		return zero, ErrBootstrap
	}
	suffix := hex.EncodeToString(nonce)
	directory := "/tmp/.clawreef-source-tls-helper-" + suffix
	binary := directory + "/bootstrap"
	// Only fixed, random hexadecimal coordinates enter this shell. No password,
	// SQL, source path, namespace, service name or certificate is interpolated.
	upload := "set -eu; umask 077; mkdir -m 0700 " + directory + "; cat > " + binary + "; chmod 0700 " + binary
	if _, e := c.exec(ctx, plan.Pod.Name, plan.Container, []string{"sh", "-c", upload}, bytes.NewReader(c.helper), 1024); e != nil {
		return zero, e
	}
	request.AdminPassword = c.password
	request.Deadline = time.Now().Add(90 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(request.Deadline) {
		request.Deadline = deadline
	}
	raw, e := json.Marshal(request)
	if e != nil {
		return zero, ErrBootstrap
	}
	defer clear(raw)
	result, e := c.exec(ctx, plan.Pod.Name, plan.Container, []string{binary, "mysql-helper"}, bytes.NewReader(raw), 262144)
	if e != nil {
		return zero, e
	}
	defer clear(result)
	decoder := json.NewDecoder(bytes.NewReader(result))
	decoder.DisallowUnknownFields()
	var out MySQLHelperResult
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.Version != "original-source-mysql-tls-result.v1" || out.Operation != request.Operation || out.Mode != request.Mode || out.Native.Database != plan.Database || out.Native.AdminUsername == "" || (c.options.AdminUsername != "" && out.Native.AdminUsername != c.options.AdminUsername) {
		return zero, ErrBootstrap
	}
	last, _, e := c.discover(ctx)
	if e != nil || last.Pod.UID != plan.Pod.UID || last.Pod.SpecSHA256 != plan.Pod.SpecSHA256 || last.ContainerID != plan.ContainerID || last.Deployment.UID != plan.Deployment.UID || last.Deployment.SpecSHA256 != plan.Deployment.SpecSHA256 || !reflect.DeepEqual(last.Services, plan.Services) {
		return zero, ErrBootstrap
	}
	return out, nil
}
func writeOutput(directory, name string, raw []byte) (string, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Base(name) != name {
		return "", ErrBootstrap
	}
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return "", ErrBootstrap
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return "", ErrBootstrap
	}
	defer root.Close()
	f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", ErrBootstrap
	}
	if n, e := f.Write(raw); e != nil || n != len(raw) {
		f.Close()
		return "", ErrBootstrap
	}
	if f.Sync() != nil {
		f.Close()
		return "", ErrBootstrap
	}
	if f.Close() != nil {
		return "", ErrBootstrap
	}
	actual, e := sourceInput(filepath.Join(directory, name), digest(raw), int64(len(raw))+1, true)
	clear(actual)
	if e != nil {
		return "", ErrBootstrap
	}
	return filepath.Join(directory, name), nil
}
func (c *Client) Inspect(ctx context.Context) (BootstrapReceipt, error) {
	var zero BootstrapReceipt
	plan, _, e := c.discover(ctx)
	if e != nil {
		return zero, e
	}
	operation := make([]byte, 16)
	if _, e := rand.Read(operation); e != nil {
		return zero, ErrBootstrap
	}
	op := hex.EncodeToString(operation)
	plan.Operation = op
	result, e := c.helperCall(ctx, plan, MySQLHelperRequest{Version: "original-source-mysql-tls-request.v1", Mode: "inspect", Operation: op, Database: plan.Database, AdminUsername: plan.AdminUsername, DNSNames: plan.DNSNames, IPAddresses: plan.IPAddresses})
	if e != nil {
		return zero, e
	}
	plan.Native = result.Native
	// Native bcrypt discovery must produce exactly one existing local admin.
	plan.AdminUsername = result.Native.AdminUsername
	c.options.AdminUsername = result.Native.AdminUsername
	raw, e := json.Marshal(plan)
	if e != nil {
		return zero, ErrBootstrap
	}
	file, e := writeOutput(c.options.OutputDirectory, "mysql-bootstrap-plan.json", raw)
	if e != nil {
		return zero, e
	}
	caFile, e := writeOutput(c.options.OutputDirectory, "mysql-source-ca.pem", plan.Native.CA)
	if e != nil {
		return zero, e
	}
	return BootstrapReceipt{Version: "original-source-tls-bootstrap-receipt.v1", State: "actual_kube_and_local_admin_inspected_no_tls_change", Operation: op, ServerUUID: plan.Native.ServerUUID, PlanFile: file, PlanSHA256: digest(raw), CAFile: caFile, CASHA256: digest(plan.Native.CA), Result: result}, nil
}
func (c *Client) Apply(ctx context.Context, planFile, planSHA, operation string, rollback bool) (BootstrapReceipt, error) {
	var zero BootstrapReceipt
	raw, e := sourceInput(planFile, planSHA, 262144, true)
	var plan BootstrapPlan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if e != nil || decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF || plan.Version != "original-source-tls-bootstrap-plan.v1" || plan.Namespace != c.options.Namespace || plan.NamespaceUID != c.namespaceUID || plan.ClusterUID != c.clusterUID || plan.Operator != c.operator || plan.OperatorUID != c.operatorUID || plan.AdminUsername != c.options.AdminUsername || plan.HelperSHA256 != c.options.HelperSHA256 || (!bootstrapOperation.MatchString(operation) || operation != plan.Operation) {
		return zero, ErrBootstrap
	}
	current, _, e := c.discover(ctx)
	if e != nil || current.Pod.UID != plan.Pod.UID || current.ContainerID != plan.ContainerID || current.Deployment.UID != plan.Deployment.UID || current.Deployment.SpecSHA256 != plan.Deployment.SpecSHA256 || !reflect.DeepEqual(current.Services, plan.Services) {
		return zero, ErrBootstrap
	}
	if !rollback {
		if current.Deployment.ResourceVersion != plan.Deployment.ResourceVersion || current.Pod.ResourceVersion != plan.Pod.ResourceVersion {
			return zero, ErrBootstrap
		}
		for _, target := range []struct {
			resource, group string
			pin             ObjectPin
		}{{"deployments", "apps", plan.Deployment}, {"pods", "", plan.Pod}} {
			if c.access(ctx, "patch", target.group, target.resource, "", target.pin.Name) != nil {
				return zero, ErrBootstrap
			}
			// Metadata-only claim: no template/data/PVC change or Pod rollout.
			var annotations map[string]string
			if target.resource == "deployments" {
				object, e := c.kube.AppsV1().Deployments(c.options.Namespace).Get(ctx, target.pin.Name, metav1.GetOptions{})
				if e != nil || string(object.UID) != target.pin.UID || object.ResourceVersion != target.pin.ResourceVersion {
					return zero, ErrBootstrap
				}
				annotations = object.Annotations
			} else {
				object, e := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, target.pin.Name, metav1.GetOptions{})
				if e != nil || string(object.UID) != target.pin.UID || object.ResourceVersion != target.pin.ResourceVersion {
					return zero, ErrBootstrap
				}
				annotations = object.Annotations
			}
			if old := annotations["backup.clawreef.io/source-tls-bootstrap"]; old != "" && old != operation {
				return zero, ErrBootstrap
			}
			ops := []map[string]any{{"op": "test", "path": "/metadata/uid", "value": target.pin.UID}, {"op": "test", "path": "/metadata/resourceVersion", "value": target.pin.ResourceVersion}}
			if annotations == nil {
				ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations", "value": map[string]string{"backup.clawreef.io/source-tls-bootstrap": operation}})
			} else {
				ops = append(ops, map[string]any{"op": "add", "path": "/metadata/annotations/backup.clawreef.io~1source-tls-bootstrap", "value": operation})
			}
			patch, _ := json.Marshal(ops)
			if target.resource == "deployments" {
				_, e = c.kube.AppsV1().Deployments(c.options.Namespace).Patch(ctx, target.pin.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
			} else {
				_, e = c.kube.CoreV1().Pods(c.options.Namespace).Patch(ctx, target.pin.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
			}
			if e != nil {
				return zero, ErrBootstrap
			}
		}
	}
	mode := "apply"
	if rollback {
		mode = "rollback"
	}
	result, e := c.helperCall(ctx, plan, MySQLHelperRequest{Version: "original-source-mysql-tls-request.v1", Mode: mode, Database: plan.Database, AdminUsername: plan.AdminUsername, Operation: operation, ExpectedServerUUID: plan.Native.ServerUUID, DNSNames: plan.DNSNames, IPAddresses: plan.IPAddresses})
	if e != nil {
		return zero, e
	}
	if result.Native.ServerUUID != plan.Native.ServerUUID || !bytes.Equal(result.Native.CA, plan.Native.CA) || !rollback && (!result.TLSVerified || result.TLSVersion < 0x0304) {
		return zero, ErrBootstrap
	}
	encoded, _ := json.Marshal(result)
	file, e := writeOutput(c.options.OutputDirectory, "mysql-tls-"+mode+"-"+operation+".json", encoded)
	if e != nil {
		return zero, e
	}
	receipt := BootstrapReceipt{Version: "original-source-tls-bootstrap-receipt.v1", State: result.State, Operation: operation, ServerUUID: plan.Native.ServerUUID, PlanFile: file, PlanSHA256: digest(encoded), CAFile: filepath.Join(c.options.OutputDirectory, "mysql-source-ca.pem"), CASHA256: digest(plan.Native.CA), Result: result}
	if !rollback {
		if e := c.emitConnectionInputs(ctx, plan, &receipt); e != nil {
			return receipt, e
		}
	}
	return receipt, nil
}
