package systembackupexecution

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/validation"
)

const executionPlanSchema = "system-backup-execution-plan.v1"

type ExecutionPlan struct {
	Schema         string       `json:"schema"`
	InstallationID string       `json:"installation_id"`
	TaskID         string       `json:"task_id"`
	ConfigSHA256   string       `json:"config_sha256"`
	ProfileSHA256  string       `json:"profile_sha256"`
	Jobs           []PlannedJob `json:"jobs"`
}

type PlannedJob struct {
	Phase        string      `json:"phase"`
	UnitKey      string      `json:"unit_key"`
	NamespaceUID string      `json:"namespace_uid"`
	Job          batchv1.Job `json:"job"`
}

func (p ExecutionPlan) Validate() error {
	if p.Schema != executionPlanSchema || p.InstallationID == "" || p.TaskID == "" || len(p.ConfigSHA256) != 64 || len(p.ProfileSHA256) != 64 || len(p.Jobs) < 1 || len(p.Jobs) > 16 {
		return ErrPlan
	}
	seen := map[string]bool{}
	for _, j := range p.Jobs {
		if j.Phase != "capture" && j.Phase != "secret_capture" && j.Phase != "publish" {
			return ErrPlan
		}
		if !planToken.MatchString(j.UnitKey) || j.NamespaceUID == "" || len(validation.IsDNS1123Label(j.Job.Name)) > 0 || j.Job.Name == "" || len(validation.IsDNS1123Label(j.Job.Namespace)) > 0 || j.Job.Namespace == "" || j.Job.UID != "" || j.Job.ResourceVersion != "" || len(j.Job.OwnerReferences) != 0 || j.Job.GenerateName != "" {
			return ErrPlan
		}
		key := j.Job.Namespace + "/" + j.Job.Name
		if seen[key] {
			return ErrPlan
		}
		seen[key] = true
		unit := j.Phase + "/" + j.UnitKey
		if seen[unit] {
			return ErrPlan
		}
		seen[unit] = true
		pod := j.Job.Spec.Template.Spec
		if len(pod.Containers) != 1 || len(pod.InitContainers) != 0 || pod.HostNetwork || pod.HostPID || pod.HostIPC || pod.ServiceAccountName == "" || pod.RestartPolicy != "Never" || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken || j.Job.Spec.BackoffLimit == nil || *j.Job.Spec.BackoffLimit != 0 || j.Job.Spec.TTLSecondsAfterFinished != nil || j.Job.Spec.ActiveDeadlineSeconds == nil || *j.Job.Spec.ActiveDeadlineSeconds < 1 {
			return ErrPlan
		}
		if pod.Containers[0].SecurityContext == nil || pod.Containers[0].SecurityContext.Privileged != nil && *pod.Containers[0].SecurityContext.Privileged {
			return ErrPlan
		}
		// Admission pins executable content; no mutable tag is replayed after a
		// controller restart. Namespace/SA/volume authorization is deployment-owned.
		image := pod.Containers[0].Image
		at := strings.LastIndex(image, "@sha256:")
		if at < 1 || len(image[at+8:]) != 64 {
			return ErrPlan
		}
		if _, err := hex.DecodeString(image[at+8:]); err != nil {
			return ErrPlan
		}
		for _, v := range pod.Volumes {
			if v.HostPath != nil {
				return ErrPlan
			}
		}
	}
	return nil
}

func plannedSpecHash(j PlannedJob) string { raw, _ := json.Marshal(j); return planHash(raw) }

func boundJob(plan ExecutionPlan, j PlannedJob) *batchv1.Job {
	want := j.Job.DeepCopy()
	if want.Labels == nil {
		want.Labels = map[string]string{}
	}
	if want.Annotations == nil {
		want.Annotations = map[string]string{}
	}
	if want.Spec.Template.Labels == nil {
		want.Spec.Template.Labels = map[string]string{}
	}
	want.Labels["backup.clawmanager.io/v2-task"] = plan.TaskID
	want.Spec.Template.Labels["backup.clawmanager.io/v2-task"] = plan.TaskID
	want.Annotations["backup.clawmanager.io/v2-spec-sha256"] = plannedSpecHash(j)
	return want
}

func sameJob(want, got *batchv1.Job) bool {
	if got == nil || got.UID == "" || got.Name != want.Name || got.Namespace != want.Namespace || got.Annotations["backup.clawmanager.io/v2-spec-sha256"] != want.Annotations["backup.clawmanager.io/v2-spec-sha256"] || got.Labels["backup.clawmanager.io/v2-task"] != want.Labels["backup.clawmanager.io/v2-task"] {
		return false
	}
	// Kubernetes defaults may add fields; configured fields must still match.
	// Additional containers or init containers are never treated as defaults.
	if len(got.Spec.Template.Spec.Containers) != 1 || len(got.Spec.Template.Spec.InitContainers) != 0 {
		return false
	}
	w, g := want.Spec.Template.Spec, got.Spec.Template.Spec
	if g.HostNetwork || g.HostPID || g.HostIPC || g.ServiceAccountName != w.ServiceAccountName || len(g.Volumes) != len(w.Volumes) || len(g.HostAliases) != 0 || len(g.EphemeralContainers) != 0 || g.AutomountServiceAccountToken == nil || *g.AutomountServiceAccountToken {
		return false
	}
	if g.NodeName != w.NodeName || !equality.Semantic.DeepEqual(w.NodeSelector, g.NodeSelector) || !equality.Semantic.DeepEqual(w.SecurityContext, g.SecurityContext) || !equality.Semantic.DeepEqual(w.RuntimeClassName, g.RuntimeClassName) {
		return false
	}
	if !equality.Semantic.DeepEqual(w.Containers[0].Command, g.Containers[0].Command) || !equality.Semantic.DeepEqual(w.Containers[0].Args, g.Containers[0].Args) || !equality.Semantic.DeepEqual(w.Containers[0].Env, g.Containers[0].Env) || !equality.Semantic.DeepEqual(w.Containers[0].EnvFrom, g.Containers[0].EnvFrom) || !equality.Semantic.DeepEqual(w.Containers[0].VolumeMounts, g.Containers[0].VolumeMounts) || !equality.Semantic.DeepEqual(w.Containers[0].SecurityContext, g.Containers[0].SecurityContext) {
		return false
	}
	return equality.Semantic.DeepDerivative(want.Spec, got.Spec)
}
