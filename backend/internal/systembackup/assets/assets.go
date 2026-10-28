// Package assets captures only explicitly registered business Secrets and Skill
// objects. Plaintext lives in bounded memory and must be sent to encrypted staging.
package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var ErrAssets = errors.New("business assets incomplete or changed")

const MaxBytes = 32 << 20

type SecretRef struct {
	Namespace, Name, UID, ResourceVersion, Role string
	Keys                                        []string
}
type ObjectRef struct {
	Key, VersionID, SHA256 string
	Size                   int64
}
type Inventory struct {
	Namespace  string
	Secrets    []SecretRef
	Objects    []ObjectRef
	ConfigMaps []ConfigMapRef
}
type Secret struct {
	Reference SecretRef
	Data      map[string][]byte
}
type Object struct {
	Reference ObjectRef
	Data      []byte
}
type Set struct {
	Version    string
	Inventory  Inventory
	Secrets    []Secret
	Objects    []Object
	ConfigMaps []ConfigMap
}

func (s *Set) Clear() {
	for _, c := range s.ConfigMaps {
		for _, b := range c.Data {
			clear(b)
		}
	}
	for _, v := range s.Secrets {
		for _, b := range v.Data {
			clear(b)
		}
	}
	for _, v := range s.Objects {
		clear(v.Data)
	}
}
func (i Inventory) Validate() error {
	if len(i.ConfigMaps) > 256 {
		return ErrAssets
	}
	maps := map[string]bool{}
	for _, c := range i.ConfigMaps {
		identity := c.Namespace + "/" + c.Name
		if c.Namespace == "" || c.Name == "" || c.UID == "" || c.ResourceVersion == "" || len(c.Rules) == 0 || maps[identity] {
			return ErrAssets
		}
		maps[identity] = true
		for k, r := range c.Rules {
			if k == "" || len(r.Fields) == 0 || !domain.ConfigFormatSupported(r.Format) {
				return ErrAssets
			}
		}
	}
	if i.Namespace == "" || len(i.Secrets) > 256 || len(i.Objects) > 10000 {
		return ErrAssets
	}
	seen := map[string]bool{}
	var total int64
	for _, s := range i.Secrets {
		key := s.Namespace + "/" + s.Name
		if s.Namespace == "" || s.Name == "" || s.UID == "" || s.ResourceVersion == "" || len(s.Keys) == 0 || seen[key] {
			return ErrAssets
		}
		seen[key] = true
		switch s.Role {
		case "model", "channel", "enterprise-auth", "runtime-config":
		default:
			return ErrAssets
		}
		keys := map[string]bool{}
		for _, k := range s.Keys {
			if k == "" || keys[k] {
				return ErrAssets
			}
			keys[k] = true
		}
	}
	seen = map[string]bool{}
	for _, o := range i.Objects {
		hash, e := hex.DecodeString(o.SHA256)
		if o.Key == "" || seen[o.Key] || o.Size < 0 || o.Size > MaxBytes || len(hash) != 32 || e != nil {
			return ErrAssets
		}
		seen[o.Key] = true
		total += o.Size
		if total > MaxBytes {
			return ErrAssets
		}
	}
	return nil
}
func (i Inventory) HasSecret(ns, name, key string) bool {
	for _, s := range i.Secrets {
		if s.Namespace == ns && s.Name == name {
			if key == "" {
				return true
			}
			for _, k := range s.Keys {
				if k == key {
					return true
				}
			}
		}
	}
	return false
}

// CheckReferences is run under the writer gate against the full source snapshot.
// A reference alone does not count as preserved secret/object content.
func (i Inventory) CheckReferences(snapshot domain.Snapshot) error {
	if i.Validate() != nil {
		return ErrAssets
	}
	objects := map[string]ObjectRef{}
	for _, o := range i.Objects {
		objects[o.Key] = o
	}
	for _, table := range snapshot.Tables {
		for _, r := range table.Rows {
			switch table.Name {
			case "llm_models":
				if v := r["api_key_secret_ref"].String(); v != "" {
					ref, e := services.ParseSecretReference(v)
					if e != nil {
						return ErrAssets
					}
					if ref.Namespace == "" {
						ref.Namespace = i.Namespace
					}
					if !i.HasSecret(ref.Namespace, ref.Name, ref.Key) {
						return ErrAssets
					}
				}
			case "openclaw_injection_snapshots":
				if name := r["secret_name"].String(); name != "" && !i.HasSecret(i.Namespace, name, "") {
					return ErrAssets
				}
			case "skill_blobs":
				o, ok := objects[r["object_key"].String()]
				size, e := strconv.ParseInt(r["size_bytes"].String(), 10, 64)
				if !ok || e != nil || size != o.Size || o.SHA256 != strings.TrimPrefix(r["archive_hash"].String(), "sha256:") {
					return ErrAssets
				}
			case "teams":
				for _, pair := range [][2]string{{"redis_url_secret_name", "redis_url_secret_key"}, {"team_token_secret_name", "team_token_secret_key"}} {
					if name := r[pair[0]].String(); name != "" && !i.HasSecret(i.Namespace, name, r[pair[1]].String()) {
						return ErrAssets
					}
				}
			}
		}
	}
	return nil
}
func Capture(ctx context.Context, client kubernetes.Interface, i Inventory, open func(context.Context, ObjectRef) (io.ReadCloser, error)) (Set, error) {
	out := Set{Version: "business-assets.v1", Inventory: i}
	success := false
	defer func() {
		if !success {
			out.Clear()
		}
	}()
	if i.Validate() != nil || client == nil {
		return out, ErrAssets
	}
	var total int64
	maps, e := captureMaps(ctx, client, i.ConfigMaps)
	if e != nil {
		return out, e
	}
	out.ConfigMaps = maps
	for _, c := range maps {
		for _, b := range c.Data {
			total += int64(len(b))
		}
	}
	for _, ref := range i.Secrets {
		s, e := client.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if e != nil {
			return out, ErrAssets
		}
		defer func() {
			for _, b := range s.Data {
				clear(b)
			}
		}()
		if s.Type != corev1.SecretTypeOpaque || string(s.UID) != ref.UID || s.ResourceVersion != ref.ResourceVersion || s.DeletionTimestamp != nil || len(s.Data) != len(ref.Keys) {
			return out, ErrAssets
		}
		v := Secret{Reference: ref, Data: map[string][]byte{}}
		out.Secrets = append(out.Secrets, v)
		for _, k := range ref.Keys {
			b, ok := s.Data[k]
			if !ok {
				return out, ErrAssets
			}
			total += int64(len(b))
			if total > MaxBytes {
				return out, ErrAssets
			}
			v.Data[k] = append([]byte(nil), b...)
		}
	}
	for _, ref := range i.Objects {
		if open == nil || total+ref.Size > MaxBytes {
			return out, ErrAssets
		}
		r, e := open(ctx, ref)
		if e != nil {
			return out, ErrAssets
		}
		b, e := io.ReadAll(io.LimitReader(r, ref.Size+1))
		r.Close()
		h := sha256.Sum256(b)
		if e != nil || int64(len(b)) != ref.Size || hex.EncodeToString(h[:]) != ref.SHA256 {
			clear(b)
			return out, ErrAssets
		}
		total += int64(len(b))
		out.Objects = append(out.Objects, Object{ref, b})
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	success = true
	return out, nil
}
func Decode(r io.Reader) (Set, error) {
	var out Set
	b, e := io.ReadAll(io.LimitReader(r, 48<<20+1))
	if e != nil || len(b) > 48<<20 {
		return out, ErrAssets
	}
	defer clear(b)
	if json.Unmarshal(b, &out) != nil || out.Version != "business-assets.v1" || out.Inventory.Validate() != nil || len(out.Secrets) != len(out.Inventory.Secrets) || len(out.Objects) != len(out.Inventory.Objects) {
		out.Clear()
		return Set{}, ErrAssets
	}
	canonical, _ := json.Marshal(out)
	if !bytes.Equal(bytes.TrimSpace(b), canonical) {
		clear(canonical)
		out.Clear()
		return Set{}, ErrAssets
	}
	clear(canonical)
	if validateMaps(out.Inventory.ConfigMaps, out.ConfigMaps) != nil {
		out.Clear()
		return Set{}, ErrAssets
	}
	for n, v := range out.Secrets {
		a, _ := json.Marshal(v.Reference)
		b, _ := json.Marshal(out.Inventory.Secrets[n])
		if string(a) != string(b) || len(v.Data) != len(v.Reference.Keys) {
			out.Clear()
			return Set{}, ErrAssets
		}
		for _, k := range v.Reference.Keys {
			if _, ok := v.Data[k]; !ok {
				out.Clear()
				return Set{}, ErrAssets
			}
		}
	}
	for n, v := range out.Objects {
		a, _ := json.Marshal(v.Reference)
		b, _ := json.Marshal(out.Inventory.Objects[n])
		h := sha256.Sum256(v.Data)
		if string(a) != string(b) || int64(len(v.Data)) != v.Reference.Size || hex.EncodeToString(h[:]) != v.Reference.SHA256 {
			out.Clear()
			return Set{}, ErrAssets
		}
	}
	return out, nil
}
