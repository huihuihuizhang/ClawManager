package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"

	sb "clawreef/internal/systembackup"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type redisBootstrapOutput struct {
	bytes.Buffer
	maximum int
}

func (o *redisBootstrapOutput) Write(p []byte) (int, error) {
	if len(p) > o.maximum-o.Len() {
		return 0, ErrInstall
	}
	return o.Buffer.Write(p)
}

func (i *Installer) originalRedisRESTConfig(ctx context.Context, pin BootstrapSourceFilePin) (*rest.Config, error) {
	raw, e := readBootstrapSourcePin(pin, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	defer clear(raw)
	cfg, e := clientcmd.RESTConfigFromKubeConfig(raw)
	if e != nil || cfg.Host != i.plan.KubernetesAPI || cfg.Insecure || cfg.Proxy != nil || cfg.ExecProvider != nil || cfg.AuthProvider != nil || cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) != 0 || len(cfg.Impersonate.Extra) != 0 {
		return nil, ErrInstall
	}
	cfg.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	if cfg.CAFile != "" {
		if len(cfg.CAData) != 0 {
			return nil, ErrInstall
		}
		cfg.CAData, e = ReadPrivateFile(cfg.CAFile, 65536)
		if e != nil {
			return nil, ErrInstall
		}
		cfg.CAFile = ""
	}
	if len(cfg.CAData) == 0 || hash(cfg.CAData) != i.plan.KubernetesCASHA256 {
		return nil, ErrInstall
	}
	// Native client-go still performs strict CA/SAN validation, using the SAME
	// pinned original static credential and independently authenticated subject.
	if cfg.BearerTokenFile != "" {
		if cfg.BearerToken != "" {
			return nil, ErrInstall
		}
		token, e := ReadPrivateFile(cfg.BearerTokenFile, 16384)
		if e != nil {
			return nil, ErrInstall
		}
		cfg.BearerToken = strings.TrimSpace(string(token))
		clear(token)
		cfg.BearerTokenFile = ""
	}
	if cfg.CertFile != "" {
		if len(cfg.CertData) != 0 {
			return nil, ErrInstall
		}
		cfg.CertData, e = ReadPrivateFile(cfg.CertFile, 65536)
		if e != nil {
			return nil, ErrInstall
		}
		cfg.CertFile = ""
	}
	if cfg.KeyFile != "" {
		if len(cfg.KeyData) != 0 {
			return nil, ErrInstall
		}
		cfg.KeyData, e = ReadPrivateFile(cfg.KeyFile, 65536)
		if e != nil {
			return nil, ErrInstall
		}
		cfg.KeyFile = ""
	}
	if (cfg.BearerToken == "") == (len(cfg.CertData) == 0 && len(cfg.KeyData) == 0) {
		return nil, ErrInstall
	}
	actual, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		return nil, ErrInstall
	}
	subject, e := actual.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if e != nil || subject.Status.UserInfo.Username != i.plan.OwnerUsername || subject.Status.UserInfo.UID != i.plan.OwnerUID {
		return nil, ErrInstall
	}
	groups := append([]string{}, subject.Status.UserInfo.Groups...)
	expected := append([]string{}, i.plan.OwnerGroups...)
	sort.Strings(groups)
	sort.Strings(expected)
	if !reflect.DeepEqual(groups, expected) || len(subject.Status.UserInfo.Extra) != 0 {
		return nil, ErrInstall
	}
	return cfg, nil
}

func (i *Installer) originalRedisExec(ctx context.Context, cfg *rest.Config, pod, container string, command []string, input io.Reader, maximum int) ([]byte, error) {
	req := i.kube.CoreV1().RESTClient().Post().Resource("pods").Namespace(i.plan.Target.Namespace).Name(pod).SubResource("exec").VersionedParams(&corev1.PodExecOptions{Container: container, Command: command, Stdin: true, Stdout: true, Stderr: true, TTY: false}, scheme.ParameterCodec)
	executor, e := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if e != nil {
		return nil, ErrInstall
	}
	output := &redisBootstrapOutput{maximum: maximum}
	if executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: input, Stdout: output, Stderr: io.Discard}) != nil {
		return nil, ErrOriginalObserverPKIUnconfirmed
	}
	return output.Bytes(), nil
}

func (i *Installer) originalRedisHelper(ctx context.Context, cfg *rest.Config, pod, container string, helper BootstrapSourceFilePin, in sb.RedisBootstrapNativeRequest) (sb.RedisBootstrapNativeFacts, error) {
	var zero sb.RedisBootstrapNativeFacts
	nonce, e := hex.DecodeString(in.Operation)
	if e != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != in.Operation {
		return zero, ErrInstall
	}
	body, e := readObserverHostFile(helper, 128<<20)
	if e != nil || len(body) < 64 || !bytes.Equal(body[:4], []byte{127, 'E', 'L', 'F'}) || body[4] != 2 || body[5] != 1 || body[18] != 62 || body[19] != 0 {
		return zero, ErrInstall
	}
	defer clear(body)
	invocation := make([]byte, 16)
	if _, e = rand.Read(invocation); e != nil {
		return zero, ErrInstall
	}
	in.HelperInvocation = hex.EncodeToString(invocation)
	directory := "/tmp/sbk-redis-bootstrap-" + in.Operation + "-" + in.HelperInvocation
	upload := "set -eu; umask 077; mkdir -m 0700 " + directory + "; cat > " + directory + "/helper; chmod 0700 " + directory + "/helper"
	if _, e = i.originalRedisExec(ctx, cfg, pod, container, []string{"sh", "-c", upload}, bytes.NewReader(body), 1024); e != nil {
		return zero, e
	}
	in.Version = "original-redis-native-install-request.v1"
	in.HelperSHA256 = helper.SHA256
	raw, e := json.Marshal(in)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(raw)
	response, e := i.originalRedisExec(ctx, cfg, pod, container, []string{directory + "/helper", "redis-native-helper"}, bytes.NewReader(raw), 262144)
	if e != nil {
		return zero, e
	}
	defer clear(response)
	dec := json.NewDecoder(bytes.NewReader(response))
	dec.DisallowUnknownFields()
	if dec.Decode(&zero) != nil || dec.Decode(new(any)) != io.EOF || zero.Version != "original-redis-native-install-facts.v1" {
		return sb.RedisBootstrapNativeFacts{}, ErrInstall
	}
	return zero, nil
}

// A helper's uploaded ELF is self-removed only when it actually ran. A lost
// upload/run response stays unconfirmed; no foreign /tmp path is ever deleted.
