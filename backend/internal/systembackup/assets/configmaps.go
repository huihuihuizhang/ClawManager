package assets

import (
	"context"
	"encoding/json"

	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type DocumentRules struct {
	Format string
	Fields []domain.JSONRule
}
type ConfigMapRef struct {
	Namespace, Name, UID, ResourceVersion string
	Rules                                 map[string]DocumentRules
}
type ConfigMap struct {
	Reference ConfigMapRef
	Data      map[string][]byte
}

func (i Inventory) hasConfigMap(ns, name, key string) bool {
	for _, r := range i.ConfigMaps {
		if r.Namespace == ns && r.Name == name {
			if key == "" {
				return true
			}
			_, ok := r.Rules[key]
			return ok
		}
	}
	return false
}

// CheckPod covers Secret and ConfigMap references in all application containers,
// including projected volumes and envFrom. Infrastructure pull credentials and
// projected service-account tokens are not business assets and are not copied.
func (i Inventory) CheckPod(p *corev1.Pod) error {
	if p == nil {
		return nil
	}
	ns := p.Namespace
	for _, v := range p.Spec.Volumes {
		if v.Secret != nil && !i.HasSecret(ns, v.Secret.SecretName, "") {
			return ErrAssets
		}
		if v.ConfigMap != nil && !i.hasConfigMap(ns, v.ConfigMap.Name, "") {
			return ErrAssets
		}
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.Secret != nil && !i.HasSecret(ns, s.Secret.Name, "") {
					return ErrAssets
				}
				if s.ConfigMap != nil && !i.hasConfigMap(ns, s.ConfigMap.Name, "") {
					return ErrAssets
				}
			}
		}
	}
	containers := append(append([]corev1.Container{}, p.Spec.Containers...), p.Spec.InitContainers...)
	for _, c := range containers {
		for _, e := range c.Env {
			if e.ValueFrom == nil {
				continue
			}
			v := e.ValueFrom
			if v.SecretKeyRef != nil && !i.HasSecret(ns, v.SecretKeyRef.Name, v.SecretKeyRef.Key) {
				return ErrAssets
			}
			if v.ConfigMapKeyRef != nil && !i.hasConfigMap(ns, v.ConfigMapKeyRef.Name, v.ConfigMapKeyRef.Key) {
				return ErrAssets
			}
		}
		for _, e := range c.EnvFrom {
			if e.SecretRef != nil && !i.HasSecret(ns, e.SecretRef.Name, "") {
				return ErrAssets
			}
			if e.ConfigMapRef != nil && !i.hasConfigMap(ns, e.ConfigMapRef.Name, "") {
				return ErrAssets
			}
		}
	}
	return nil
}
func captureMaps(ctx context.Context, client kubernetes.Interface, refs []ConfigMapRef) ([]ConfigMap, error) {
	var out []ConfigMap
	var total int64
	for _, ref := range refs {
		c, e := client.CoreV1().ConfigMaps(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if e != nil || c.DeletionTimestamp != nil || string(c.UID) != ref.UID || c.ResourceVersion != ref.ResourceVersion || len(c.Data)+len(c.BinaryData) != len(ref.Rules) {
			return nil, ErrAssets
		}
		data := map[string][]byte{}
		for k, v := range c.Data {
			data[k] = []byte(v)
		}
		for k, v := range c.BinaryData {
			if _, ok := data[k]; ok {
				return nil, ErrAssets
			}
			data[k] = append([]byte(nil), v...)
		}
		for k, b := range data {
			total += int64(len(b))
			rule, ok := ref.Rules[k]
			if !ok || total > MaxBytes {
				return nil, ErrAssets
			}
			v, e := domain.NormalizeDocument(ctx, rule.Format, b, rule.Fields)
			clear(v.Bytes)
			if e != nil {
				return nil, ErrAssets
			}
		}
		out = append(out, ConfigMap{ref, data})
	}
	return out, nil
}
func validateMaps(refs []ConfigMapRef, values []ConfigMap) error {
	if len(refs) != len(values) {
		return ErrAssets
	}
	for n, v := range values {
		a, _ := json.Marshal(refs[n])
		b, _ := json.Marshal(v.Reference)
		if string(a) != string(b) || len(v.Data) != len(v.Reference.Rules) {
			return ErrAssets
		}
		for k := range v.Reference.Rules {
			if _, ok := v.Data[k]; !ok {
				return ErrAssets
			}
		}
	}
	return nil
}
