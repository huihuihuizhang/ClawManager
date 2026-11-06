package install

import (
	"context"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// This is current placement data. The stable workload UIDs bind the operation;
// the Pod, endpoint and spec pins are compared around each authenticated use.
type freshAppDatabase struct {
	AppUID, AppSpec, AppPods, ServiceUID, ServiceSpec, EndpointUID, EndpointSpec string
	DBUID, DBSpec, DBPodUID, DBPodSpec, DBContainer, DBPod, DBHostname           string
	Address, Database, User                                                      string
	PasswordSecret, PasswordKey                                                  string
}

type freshAppDBEnv struct {
	Host, Port, Database, User, CAFile, CASHA, TLSName string
	PasswordSecret, PasswordKey                        string
}

func readFreshAppDBEnv(spec corev1.PodSpec, useSecret bool) (freshAppDBEnv, error) {
	var out freshAppDBEnv
	if len(spec.Containers) != 1 || len(spec.Containers[0].EnvFrom) != 0 || len(spec.Containers[0].Command) != 0 || len(spec.Containers[0].Args) != 0 ||
		spec.HostNetwork || len(spec.HostAliases) != 0 || spec.DNSPolicy != "" && spec.DNSPolicy != corev1.DNSClusterFirst ||
		spec.DNSConfig != nil && (len(spec.DNSConfig.Nameservers) != 0 || len(spec.DNSConfig.Searches) != 0) {
		return out, ErrInstall
	}
	selected := map[string]*string{"DB_HOST": &out.Host, "DB_PORT": &out.Port, "DB_NAME": &out.Database,
		"DB_USER": &out.User, "DB_TLS_CA_FILE": &out.CAFile, "DB_TLS_CA_SHA256": &out.CASHA, "DB_TLS_SERVER_NAME": &out.TLSName}
	for _, env := range spec.Containers[0].Env {
		if useSecret && env.Name == "DB_PASSWORD" {
			source := env.ValueFrom
			if out.PasswordSecret != "" || env.Value != "" || source == nil || source.SecretKeyRef == nil || source.FieldRef != nil || source.ResourceFieldRef != nil || source.ConfigMapKeyRef != nil {
				return freshAppDBEnv{}, ErrInstall
			}
			ref := source.SecretKeyRef
			if len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || len(validation.IsConfigMapKey(ref.Key)) != 0 || ref.Optional != nil && *ref.Optional {
				return freshAppDBEnv{}, ErrInstall
			}
			out.PasswordSecret, out.PasswordKey = ref.Name, ref.Key
		}
		if target := selected[env.Name]; target != nil {
			if *target != "" || env.ValueFrom != nil || env.Value == "" || strings.TrimSpace(env.Value) != env.Value || strings.Contains(env.Value, "$(") {
				return freshAppDBEnv{}, ErrInstall
			}
			*target = env.Value
		}
	}
	for _, value := range selected {
		if *value == "" {
			return freshAppDBEnv{}, ErrInstall
		}
	}
	if !path.IsAbs(out.CAFile) || path.Clean(out.CAFile) != out.CAFile || useSecret && out.PasswordSecret == "" {
		return freshAppDBEnv{}, ErrInstall
	}
	return out, nil
}

func freshAppServiceName(host, namespace string) string {
	name, _, _ := strings.Cut(host, ".")
	if len(validation.IsDNS1035Label(name)) != 0 {
		return ""
	}
	for _, candidate := range []string{name, name + "." + namespace, name + "." + namespace + ".svc", name + "." + namespace + ".svc.cluster.local"} {
		if host == candidate {
			return name
		}
	}
	return ""
}

func freshReadyDeployment(dep *appsv1.Deployment) bool {
	return dep.UID != "" && dep.DeletionTimestamp == nil && dep.Spec.Replicas != nil && *dep.Spec.Replicas > 0 && *dep.Spec.Replicas <= 16 &&
		dep.Status.ObservedGeneration >= dep.Generation && dep.Status.ReadyReplicas == *dep.Spec.Replicas && dep.Status.UpdatedReplicas == *dep.Spec.Replicas && dep.Status.AvailableReplicas == *dep.Spec.Replicas
}

func freshPodDeployment(ctx context.Context, client kubernetes.Interface, pod *corev1.Pod) (*appsv1.Deployment, error) {
	if pod.UID == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return nil, ErrInstall
	}
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" || owner.UID == "" {
		return nil, ErrInstall
	}
	rs, err := client.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil || rs.UID != owner.UID || rs.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	owner = metav1.GetControllerOf(rs)
	if owner == nil || owner.Kind != "Deployment" || owner.APIVersion != "apps/v1" || owner.UID == "" {
		return nil, ErrInstall
	}
	dep, err := client.AppsV1().Deployments(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil || dep.UID != owner.UID || !freshReadyDeployment(dep) {
		return nil, ErrInstall
	}
	return dep, nil
}

func freshReadyContainer(pod *corev1.Pod) string {
	if len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 {
		return ""
	}
	status := pod.Status.ContainerStatuses[0]
	if status.Name != pod.Spec.Containers[0].Name || !status.Ready || status.State.Running == nil || status.ImageID == "" {
		return ""
	}
	return status.ContainerID
}

func observeFreshAppDatabase(ctx context.Context, client kubernetes.Interface, input FreshInstallationIdentityInputs) (freshAppDatabase, error) {
	var zero freshAppDatabase
	app, err := client.AppsV1().Deployments(input.Namespace).Get(ctx, input.AppDeployment, metav1.GetOptions{})
	if err != nil || string(app.UID) != input.AppDeploymentUID || !freshReadyDeployment(app) || app.Spec.Selector == nil || len(app.Spec.Selector.MatchLabels) == 0 || len(app.Spec.Selector.MatchExpressions) != 0 {
		return zero, ErrInstall
	}
	env, err := readFreshAppDBEnv(app.Spec.Template.Spec, input.UseAppDatabaseSecret)
	if err != nil || env.Database != input.ExpectedDatabase || env.CASHA != input.DatabaseCA.SHA256 || env.TLSName != input.DatabaseTLSServerName {
		return zero, ErrInstall
	}
	appPods, err := client.CoreV1().Pods(input.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set(app.Spec.Selector.MatchLabels).String(), Limit: 17})
	if err != nil || appPods.Continue != "" || len(appPods.Items) != int(*app.Spec.Replicas) {
		return zero, ErrInstall
	}
	var appPins []string
	for n := range appPods.Items {
		pod := &appPods.Items[n]
		dep, err := freshPodDeployment(ctx, client, pod)
		podEnv, envErr := readFreshAppDBEnv(pod.Spec, input.UseAppDatabaseSecret)
		container := freshReadyContainer(pod)
		if err != nil || dep.UID != app.UID || envErr != nil || podEnv != env || container == "" {
			return zero, ErrInstall
		}
		appPins = append(appPins, originalObjectSHA([]string{string(pod.UID), container, originalObjectSHA(pod.Spec)}))
	}
	sort.Strings(appPins)
	serviceName := freshAppServiceName(env.Host, input.Namespace)
	port, err := strconv.Atoi(env.Port)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != env.Port || serviceName == "" {
		return zero, ErrInstall
	}
	service, err := client.CoreV1().Services(input.Namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil || service.UID == "" || service.DeletionTimestamp != nil || service.Spec.Type != corev1.ServiceTypeClusterIP || net.ParseIP(service.Spec.ClusterIP) == nil || len(service.Spec.Selector) == 0 || len(service.Spec.Ports) != 1 {
		return zero, ErrInstall
	}
	servicePort := service.Spec.Ports[0]
	if servicePort.Port != int32(port) || servicePort.Protocol != corev1.ProtocolTCP || servicePort.TargetPort.IntVal != int32(port) {
		return zero, ErrInstall
	}
	slices, err := client.DiscoveryV1().EndpointSlices(input.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set{"kubernetes.io/service-name": service.Name}.String(), Limit: 2})
	if err != nil || slices.Continue != "" || len(slices.Items) != 1 {
		return zero, ErrInstall
	}
	slice := slices.Items[0]
	if slice.UID == "" || slice.DeletionTimestamp != nil || len(slice.OwnerReferences) != 1 || len(slice.Endpoints) != 1 || len(slice.Ports) != 1 {
		return zero, ErrInstall
	}
	owner := slice.OwnerReferences[0]
	if owner.APIVersion != "v1" || owner.Kind != "Service" || owner.Name != service.Name || owner.UID != service.UID {
		return zero, ErrInstall
	}
	endpoint, endpointPort := slice.Endpoints[0], slice.Ports[0]
	if endpointPort.Port == nil || *endpointPort.Port != int32(port) || endpointPort.Protocol == nil || *endpointPort.Protocol != corev1.ProtocolTCP || endpointPort.Name == nil || *endpointPort.Name != servicePort.Name ||
		endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating || endpoint.Conditions.Serving != nil && !*endpoint.Conditions.Serving || len(endpoint.Addresses) != 1 ||
		endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != input.Namespace || endpoint.TargetRef.UID == "" {
		return zero, ErrInstall
	}
	db, err := client.CoreV1().Pods(input.Namespace).Get(ctx, endpoint.TargetRef.Name, metav1.GetOptions{})
	if err != nil || db.UID != endpoint.TargetRef.UID || db.Status.PodIP != endpoint.Addresses[0] || net.ParseIP(db.Status.PodIP) == nil || !labels.Set(service.Spec.Selector).AsSelector().Matches(labels.Set(db.Labels)) {
		return zero, ErrInstall
	}
	peers, err := client.CoreV1().Pods(input.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.Set(service.Spec.Selector).String(), Limit: 2})
	if err != nil || peers.Continue != "" || len(peers.Items) != 1 || peers.Items[0].UID != db.UID {
		return zero, ErrInstall
	}
	deployment, err := freshPodDeployment(ctx, client, db)
	container := freshReadyContainer(db)
	if err != nil || *deployment.Spec.Replicas != 1 || deployment.UID == app.UID || container == "" || !freshMySQLDatabaseEnv(db.Spec, env.Database, env.User) {
		return zero, ErrInstall
	}
	return freshAppDatabase{AppUID: string(app.UID), AppSpec: originalObjectSHA(app.Spec), AppPods: originalObjectSHA(appPins), ServiceUID: string(service.UID), ServiceSpec: originalObjectSHA(service.Spec),
		EndpointUID: string(slice.UID), EndpointSpec: originalObjectSHA(slice), DBUID: string(deployment.UID), DBSpec: originalObjectSHA(deployment.Spec), DBPodUID: string(db.UID), DBPodSpec: originalObjectSHA(db.Spec), DBContainer: container,
		DBPod: db.Name, DBHostname: db.Spec.Hostname, Address: net.JoinHostPort(service.Spec.ClusterIP, env.Port), Database: env.Database, User: env.User,
		PasswordSecret: env.PasswordSecret, PasswordKey: env.PasswordKey}, nil
}

type freshAppDatabaseSecret struct{ UID, ResourceVersion, Digest string }

func readFreshAppDatabaseSecret(ctx context.Context, client kubernetes.Interface, namespace string, target freshAppDatabase) (freshAppDatabaseSecret, []byte, error) {
	var zero freshAppDatabaseSecret
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, target.PasswordSecret, metav1.GetOptions{})
	if err != nil || secret.Name != target.PasswordSecret || secret.Namespace != namespace || secret.UID == "" || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil {
		return zero, nil, ErrInstall
	}
	defer func() {
		for _, value := range secret.Data {
			clear(value)
		}
	}()
	password := secret.Data[target.PasswordKey]
	if len(password) == 0 || len(password) > 1024 {
		return zero, nil, ErrInstall
	}
	return freshAppDatabaseSecret{string(secret.UID), secret.ResourceVersion, hash(password)}, append([]byte(nil), password...), nil
}

func freshMySQLDatabaseEnv(spec corev1.PodSpec, database, user string) bool {
	if len(spec.Containers) != 1 || len(spec.Containers[0].EnvFrom) != 0 {
		return false
	}
	want := map[string]string{"MYSQL_DATABASE": database, "MYSQL_USER": user}
	seen := map[string]bool{}
	for _, env := range spec.Containers[0].Env {
		if value, ok := want[env.Name]; ok {
			if seen[env.Name] || env.ValueFrom != nil || env.Value != value {
				return false
			}
			seen[env.Name] = true
		}
	}
	return len(seen) == len(want)
}

func checkFreshAppDatabaseDSN(pin BootstrapSourceFilePin, target freshAppDatabase, business bool) error {
	raw, err := readBootstrapSourcePin(pin, 16384)
	if err != nil {
		return ErrInstall
	}
	defer clear(raw)
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || cfg.Net != "tcp" || cfg.Addr != target.Address || cfg.DBName != target.Database || business && cfg.User != target.User {
		return ErrInstall
	}
	return nil
}

func checkFreshDatabaseHostname(ctx context.Context, reader sqlRead, target freshAppDatabase) error {
	var hostname string
	if reader.QueryRowContext(ctx, "SELECT @@hostname").Scan(&hostname) != nil || hostname == "" || hostname != target.DBPod && hostname != target.DBHostname {
		return ErrInstall
	}
	return nil
}
