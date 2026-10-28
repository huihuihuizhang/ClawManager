package kube

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	networkv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const WorkerLabel = "backup.clawmanager.io/worker"

func workerLabels(i Identity) map[string]string {
	hash := sha256.Sum256([]byte(i.Namespace + "/" + i.Name + "/" + i.Owner))
	return map[string]string{OwnerLabel: i.Owner, WorkerLabel: hex.EncodeToString(hash[:16])}
}

type WorkerEndpoint struct {
	Address string
	Port    int32
}

func endpointRule(e WorkerEndpoint, protocol corev1.Protocol) (networkv1.NetworkPolicyEgressRule, error) {
	ip, err := netip.ParseAddr(e.Address)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || e.Port < 1 || e.Port > 65535 {
		return networkv1.NetworkPolicyEgressRule{}, ErrResource
	}
	ip = ip.Unmap()
	port := intstr.FromInt32(e.Port)
	return networkv1.NetworkPolicyEgressRule{To: []networkv1.NetworkPolicyPeer{{IPBlock: &networkv1.IPBlock{CIDR: ip.String() + "/" + strconv.Itoa(ip.BitLen())}}}, Ports: []networkv1.NetworkPolicyPort{{Protocol: &protocol, Port: &port}}}, nil
}

// WorkerEgressPolicy selects exactly this worker, denies ingress, and permits
// only approved controller/database IP+port and optional DNS endpoints. No
// hostname resolution or cluster-wide subnet guessing occurs here. Controller
// must verify the CNI/NAT behavior and absence of other additive allow policies.
func WorkerEgressPolicy(i Identity, control WorkerEndpoint, database *WorkerEndpoint, dns []string) (*networkv1.NetworkPolicy, error) {
	if !i.valid() || len(dns) > 4 {
		return nil, ErrResource
	}
	rule, err := endpointRule(control, corev1.ProtocolTCP)
	if err != nil {
		return nil, err
	}
	rules := []networkv1.NetworkPolicyEgressRule{rule}
	if database != nil {
		rule, err = endpointRule(*database, corev1.ProtocolTCP)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	seen := map[string]bool{}
	for _, ip := range dns {
		if seen[ip] {
			return nil, ErrResource
		}
		seen[ip] = true
		for _, protocol := range []corev1.Protocol{corev1.ProtocolUDP, corev1.ProtocolTCP} {
			rule, err = endpointRule(WorkerEndpoint{Address: ip, Port: 53}, protocol)
			if err != nil {
				return nil, err
			}
			rules = append(rules, rule)
		}
	}
	return &networkv1.NetworkPolicy{ObjectMeta: i.meta(), Spec: networkv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: workerLabels(i)}, PolicyTypes: []networkv1.PolicyType{networkv1.PolicyTypeIngress, networkv1.PolicyTypeEgress}, Egress: rules}}, nil
}
