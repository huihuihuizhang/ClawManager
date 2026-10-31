package systembackupexecution

import (
	"context"

	c "clawreef/internal/systembackupcontroller"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"
)

type controllerObservedActor struct{ PodName, PodUID, ServiceAccountName string }

// New formal verifier role/probe composition never guesses owner names from
// source writers or grants wildcard GET to compensate for missing mappings.
func RequiredDeploymentCaptureAccess(cfg DeploymentConfig, controllerSA string, verifier *FormalVerifierDeploymentConfig) ([]CaptureAccess, error) {
	out, err := RequiredCaptureAccess(cfg, controllerSA)
	if err != nil {
		return nil, err
	}
	if cfg.FormalVerifier == nil {
		if verifier != nil {
			return nil, c.ErrExecutionAuthority
		}
		return out, nil
	}
	if verifier == nil || verifier.KubernetesReads == nil || verifier.validate(cfg) != nil || verifier.Workload.Namespace != cfg.Namespace || verifier.Workload.ServiceAccountName != controllerSA {
		return nil, c.ErrExecutionAuthority
	}
	reads, err := verifier.KubernetesReads.RequiredReads(verifier.Workload)
	if err != nil {
		return nil, c.ErrExecutionAuthority
	}
	for _, read := range reads {
		out = append(out, CaptureAccess{Namespace: read.Namespace, Rule: rbacv1.PolicyRule{APIGroups: []string{read.Group}, Resources: []string{read.Resource}, Verbs: []string{"get"}, ResourceNames: []string{read.Name}}})
	}
	return out, nil
}

func CheckDeploymentCaptureKubernetesAccess(ctx context.Context, k kubernetes.Interface, cfg DeploymentConfig, controllerSA string, verifier *FormalVerifierDeploymentConfig) error {
	access, err := RequiredDeploymentCaptureAccess(cfg, controllerSA, verifier)
	if err != nil {
		return err
	}
	return checkCaptureKubernetesAccess(ctx, k, access)
}

func loadVerifierKubernetesGrantInputs(cfg DeploymentConfig, inputs []FormalVerifierInput) (*FormalVerifierDeploymentConfig, error) {
	service := &DeploymentService{Config: cfg}
	if err := service.loadFormalVerifier(inputs); err != nil {
		return nil, err
	}
	return service.formalVerifier, nil
}
