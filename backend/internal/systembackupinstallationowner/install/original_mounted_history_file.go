package install

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// A fixed file read from D's actual ORIGINAL mounted-input capture. It is not
// a complete historical universe, a source authority or PreparedCoverage.
type originalMountedHistoryFile struct {
	prep                                                      *PreparedOriginalAdoptionSQLCut
	hold                                                      *OriginalWriterHold
	origin                                                    *originalMountedHistoryFile
	source                                                    *originalMountedHistoryInputs
	ownerKind, ownerName, ownerUID, container, filename       string
	kind, name, uid, resourceVersion, key, objectSHA, fileSHA string
	body                                                      []byte
	until                                                     time.Time
	closed                                                    bool
}

func (*originalMountedHistoryFile) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalMountedHistoryFile) String() string               { return "OriginalMountedHistoryFile" }
func (*originalMountedHistoryFile) GoString() string             { return "OriginalMountedHistoryFile" }
func (f *originalMountedHistoryFile) close() {
	if f != nil {
		if f.origin == f || f.origin == nil {
			clear(f.body)
		}
		f.body = nil
		f.closed = true
	}
}

func cleanOriginalHistoryPath(p string, absolute bool) bool {
	return p != "" && p != "." && p != ".." && path.IsAbs(p) == absolute && path.Clean(p) == p && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\\\x00\r\n")
}

// D's unique original-history factory calls this entry without holding the
// mutexes. Genuine original owner objects are mandatory. This is a fixed file
// read capability, not a complete original universe or PreparedCoverage.
func readOriginalHeldMountedHistoryFile(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, ownerKind, ownerName, ownerUID, container, filename string) (*originalMountedHistoryFile, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	return readOriginalHeldMountedHistoryFileLocked(ctx, p, h, ownerKind, ownerName, ownerUID, container, filename)
}

// C's empty-source authority callback already holds set.mu -> prep.mu. Native
// I/O here must finish before the final SQL source/evidence/KEK lock segment.
func readOriginalHeldMountedHistoryFileLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, ownerKind, ownerName, ownerUID, container, filename string) (*originalMountedHistoryFile, error) {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.set.historyMounted == nil || h.set.historyMounted.installer != p.operator.installer || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	f, err := readOriginalMountedHistoryFile(ctx, h.set.historyMounted, ownerKind, ownerName, ownerUID, container, filename)
	if err != nil {
		return nil, err
	}
	f.prep, f.hold = p, h
	for _, cap := range []time.Time{p.until, h.set.owner.until, p.reservation.ExpiresAt} {
		if cap.IsZero() {
			f.close()
			return nil, ErrInstall
		}
		if cap.Before(f.until) {
			f.until = cap
		}
	}
	if f.recheckBeforeOriginalSQL(ctx) != nil {
		f.close()
		return nil, ErrInstall
	}
	return f, nil
}

// No file bytes, namespace, object location or version may be supplied by a
// public descriptor. The requested container path is resolved against the
// retained ACTUAL owner spec and material objects. Unsupported storage kinds
// (hostPath/PVC/emptyDir/CSI/dynamic subPath) need their genuine native reader.
func readOriginalMountedHistoryFile(ctx context.Context, s *originalMountedHistoryInputs, ownerKind, ownerName, ownerUID, container, filename string) (*originalMountedHistoryFile, error) {
	if s == nil || !s.local(ctx) || ownerUID == "" || container == "" || !cleanOriginalHistoryPath(filename, true) || s.recheckReferences(ctx) != nil {
		return nil, ErrInstall
	}
	ns := s.installer.plan.Target.Namespace
	o := s.objects[ownerKind+"/"+ns+"/"+ownerName]
	if o == nil || o.uid != ownerUID || hash(o.body) != o.digest {
		return nil, ErrInstall
	}
	var spec corev1.PodSpec
	switch ownerKind {
	case "Pod":
		var p corev1.Pod
		if json.Unmarshal(o.body, &p) != nil || string(p.UID) != ownerUID || p.ResourceVersion != o.resourceVersion || p.Namespace != ns || p.Name != ownerName {
			return nil, ErrInstall
		}
		spec = p.Spec
	case "Deployment":
		var d appsv1.Deployment
		if json.Unmarshal(o.body, &d) != nil || string(d.UID) != ownerUID || d.ResourceVersion != o.resourceVersion || d.Namespace != ns || d.Name != ownerName {
			return nil, ErrInstall
		}
		spec = d.Spec.Template.Spec
	default:
		return nil, ErrInstall
	}
	var selected *corev1.Container
	for _, group := range [][]corev1.Container{spec.InitContainers, spec.Containers} {
		for n := range group {
			if group[n].Name == container {
				if selected != nil {
					return nil, ErrInstall
				}
				c := group[n]
				selected = &c
			}
		}
	}
	// Ephemeral containers are not assumed to be original configuration owners.
	if selected == nil {
		return nil, ErrInstall
	}
	var mount *corev1.VolumeMount
	for _, m := range selected.VolumeMounts {
		if !cleanOriginalHistoryPath(m.MountPath, true) {
			return nil, ErrInstall
		}
		if filename == m.MountPath || strings.HasPrefix(filename, m.MountPath+"/") {
			if mount != nil {
				return nil, ErrInstall
			} // overlapping mounts need an explicit native binding
			v := m
			mount = &v
		}
	}
	if mount == nil || mount.SubPathExpr != "" || mount.MountPropagation != nil {
		return nil, ErrInstall
	}
	relative := strings.TrimPrefix(strings.TrimPrefix(filename, mount.MountPath), "/")
	if mount.SubPath != "" {
		if !cleanOriginalHistoryPath(mount.SubPath, false) {
			return nil, ErrInstall
		}
		if relative == "" {
			relative = mount.SubPath
		} else {
			relative = mount.SubPath + "/" + relative
		}
	}
	if !cleanOriginalHistoryPath(relative, false) {
		return nil, ErrInstall
	}
	var volume *corev1.Volume
	for n := range spec.Volumes {
		if spec.Volumes[n].Name == mount.Name {
			if volume != nil {
				return nil, ErrInstall
			}
			v := spec.Volumes[n]
			volume = &v
		}
	}
	if volume == nil {
		return nil, ErrInstall
	}
	sourceBytes, sourceErr := json.Marshal(volume.VolumeSource)
	var declaredSources map[string]json.RawMessage
	if sourceErr != nil || json.Unmarshal(sourceBytes, &declaredSources) != nil || len(declaredSources) != 1 {
		return nil, ErrInstall
	}
	type target struct {
		kind, name, key string
		body            []byte
		object          *originalMountedHistoryObject
	}
	targets := []target{}
	resolve := func(kind, name string, items []corev1.KeyToPath) error {
		object := s.objects[kind+"/"+ns+"/"+name]
		if object == nil || object.uid == "" || object.resourceVersion == "" || hash(object.body) != object.digest {
			return ErrInstall
		}
		data := map[string][]byte{}
		switch kind {
		case "ConfigMap":
			var cm corev1.ConfigMap
			if json.Unmarshal(object.body, &cm) != nil || string(cm.UID) != object.uid || cm.ResourceVersion != object.resourceVersion || cm.Name != name || cm.Namespace != ns {
				return ErrInstall
			}
			for k, v := range cm.Data {
				data[k] = []byte(v)
			}
			for k, v := range cm.BinaryData {
				if _, ok := data[k]; ok {
					return ErrInstall
				}
				data[k] = bytes.Clone(v)
			}
		case "Secret":
			var secret corev1.Secret
			if json.Unmarshal(object.body, &secret) != nil || string(secret.UID) != object.uid || secret.ResourceVersion != object.resourceVersion || secret.Name != name || secret.Namespace != ns || len(secret.StringData) != 0 {
				return ErrInstall
			}
			for k, v := range secret.Data {
				data[k] = bytes.Clone(v)
			}
		default:
			return ErrInstall
		}
		defer func() {
			for _, v := range data {
				clear(v)
			}
		}()
		key := ""
		if len(items) == 0 {
			if _, ok := data[relative]; ok {
				key = relative
			}
		} else {
			for _, item := range items {
				if !cleanOriginalHistoryPath(item.Path, false) || item.Key == "" {
					return ErrInstall
				}
				if item.Path == relative {
					if key != "" {
						return ErrInstall
					}
					key = item.Key
				}
			}
		}
		if key != "" {
			raw, ok := data[key]
			if !ok || len(raw) == 0 || len(raw) > originalMountedHistoryMaxObjectBytes {
				return ErrInstall
			}
			targets = append(targets, target{kind, name, key, bytes.Clone(raw), object})
		}
		return nil
	}
	defer func() {
		for n := range targets {
			clear(targets[n].body)
		}
	}()
	kinds := 0
	if volume.ConfigMap != nil {
		kinds++
		if resolve("ConfigMap", volume.ConfigMap.Name, volume.ConfigMap.Items) != nil {
			return nil, ErrInstall
		}
	}
	if volume.Secret != nil {
		kinds++
		if resolve("Secret", volume.Secret.SecretName, volume.Secret.Items) != nil {
			return nil, ErrInstall
		}
	}
	if volume.Projected != nil {
		kinds++
		for _, p := range volume.Projected.Sources {
			encoded, e := json.Marshal(p)
			var sourceKinds map[string]json.RawMessage
			if e != nil || json.Unmarshal(encoded, &sourceKinds) != nil || len(sourceKinds) != 1 {
				return nil, ErrInstall
			}
			if p.ConfigMap != nil && p.Secret == nil && p.ServiceAccountToken == nil && p.DownwardAPI == nil {
				if resolve("ConfigMap", p.ConfigMap.Name, p.ConfigMap.Items) != nil {
					return nil, ErrInstall
				}
			} else if p.Secret != nil && p.ConfigMap == nil && p.ServiceAccountToken == nil && p.DownwardAPI == nil {
				if resolve("Secret", p.Secret.Name, p.Secret.Items) != nil {
					return nil, ErrInstall
				}
			} else {
				return nil, ErrInstall
			}
		}
	}
	if kinds != 1 || len(targets) != 1 {
		return nil, ErrInstall
	}
	t := targets[0]
	f := &originalMountedHistoryFile{source: s, ownerKind: ownerKind, ownerName: ownerName, ownerUID: ownerUID, container: container, filename: filename, kind: t.kind, name: t.name, uid: t.object.uid, resourceVersion: t.object.resourceVersion, key: t.key, objectSHA: t.object.digest, fileSHA: hash(t.body), body: bytes.Clone(t.body), until: s.until}
	f.origin = f
	if s.recheckReferences(ctx) != nil || !s.local(ctx) {
		f.close()
		return nil, ErrInstall
	}
	return f, nil
}

// Native Kubernetes rechecks are outside final SQL. Bytes stay private and
// carry the original capture cap; restarting a file reader does not renew it.
func (f *originalMountedHistoryFile) recheckBeforeOriginalSQL(ctx context.Context) error {
	if f == nil || f.origin != f || f.closed || f.source == nil || !f.source.local(ctx) || !time.Now().Before(f.until) || f.until.After(f.source.until) || hash(f.body) != f.fileSHA {
		if f != nil {
			f.close()
		}
		return ErrInstall
	}
	if f.hold != nil && (!originalEmptyHistoryOwner(ctx, f.prep, f.hold, false) || f.hold.set.historyMounted != f.source || f.hold.recheckBeforeSQL(ctx) != nil || f.prep.operator.authority(ctx, f.prep.enrollment) != nil) {
		f.close()
		return ErrInstall
	}
	if f.source.recheckReferences(ctx) != nil {
		f.close()
		return ErrInstall
	}
	o := f.source.objects[f.kind+"/"+f.source.installer.plan.Target.Namespace+"/"+f.name]
	if o == nil || o.uid != f.uid || o.resourceVersion != f.resourceVersion || o.digest != f.objectSHA {
		f.close()
		return ErrInstall
	}
	return nil
}
