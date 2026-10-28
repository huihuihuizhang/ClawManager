package worker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"

	"clawreef/internal/systembackup/assets"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
)

func assetOperation(op string) bool { return op == "restore-assets" || op == "verify-assets" }
func validAssetRequest(r Request) bool {
	return assetOperation(r.Operation) && r.Version == Version && time.Now().Before(r.Deadline) && r.Database == nil && r.RuntimePolicy == nil && len(r.Files) == 0 && r.PolicyVersion != "" && validReceipt(r.Receipt) && r.MaxCompressedBytes == 48<<20 && r.MaxArchiveBytes == 48<<20
}

// Assets are restored into a dedicated isolated PVC, with a portable object-key
// index. No source Secret is activated: secret files contain deterministic,
// task-keyed nonfunctional values. A separate read-only Job verifies every byte.
func RunAssets(ctx context.Context, r Request, env Environment) (Result, error) {
	if r.WorkBuddyIdentity != nil {
		return Result{}, ErrRequest
	}
	if !validAssetRequest(r) || env.Workspace == nil || env.Staging == nil || len(env.Key) != 32 || env.Check == nil || !separateRoots(env.Workspace, env.Staging) {
		return Result{}, ErrRequest
	}
	if env.Check(ctx, "prepare", r) != nil {
		return Result{}, ErrNotReady
	}
	f, e := staging.OpenFile(ctx, env.Staging, r.Receipt)
	if e != nil {
		return Result{}, ErrExecution
	}
	defer f.Close()
	var raw bytes.Buffer
	if e = staging.Open(ctx, f, &raw, env.Key, r.Binding, 48<<20); e != nil {
		clear(raw.Bytes())
		return Result{}, ErrExecution
	}
	defer clear(raw.Bytes())
	set, e := assets.Decode(bytes.NewReader(raw.Bytes()))
	if e != nil {
		return Result{}, ErrExecution
	}
	defer set.Clear()
	files, e := assetFiles(set, env.Key)
	if e != nil {
		return Result{}, e
	}
	defer func() {
		for _, b := range files {
			clear(b)
		}
	}()
	restoring := r.Operation == "restore-assets"
	point := "before-verify"
	if restoring {
		point = "before-restore"
	}
	if env.Check(ctx, point, r) != nil {
		return Result{}, ErrNotReady
	}
	dir, e := env.Workspace.Open(".")
	if e != nil {
		return Result{}, ErrExecution
	}
	entries, e := dir.ReadDir(len(files) + 1)
	dir.Close()
	if e != nil && e != io.EOF {
		return Result{}, ErrExecution
	}
	if restoring && len(entries) != 0 || !restoring && len(entries) != len(files) {
		return Result{}, ErrExecution
	}
	var size int64
	for name, b := range files {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if restoring {
			f, e := env.Workspace.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return Result{}, ErrExecution
			}
			n, we := f.Write(b)
			se := f.Sync()
			ce := f.Close()
			if we != nil || se != nil || ce != nil || n != len(b) {
				return Result{}, ErrExecution
			}
		} else {
			info, e := env.Workspace.Lstat(name)
			if e != nil || !info.Mode().IsRegular() || info.Size() != int64(len(b)) {
				return Result{}, ErrExecution
			}
			f, e := env.Workspace.Open(name)
			if e != nil {
				return Result{}, ErrExecution
			}
			got, e := io.ReadAll(io.LimitReader(f, int64(len(b))+1))
			f.Close()
			same := bytes.Equal(got, b)
			clear(got)
			if e != nil || !same {
				return Result{}, ErrExecution
			}
		}
		size += int64(len(b))
	}
	point = "verified-quarantine"
	if restoring {
		point = "restored-quarantine"
	}
	if env.Check(ctx, point, r) != nil {
		return Result{}, ErrNotReady
	}
	return Result{Receipt: r.Receipt, Files: int64(len(files)), Bytes: size, Quarantined: true, Verified: !restoring}, nil
}
func assetFiles(set assets.Set, key []byte) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, c := range set.ConfigMaps {
		data := map[string][]byte{}
		for name, b := range c.Data {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(c.Reference.Namespace + "/" + c.Reference.Name + ":" + name))
			stubKey := mac.Sum(nil)
			rule := c.Reference.Rules[name]
			normalized, e := domain.NormalizeDocument(domain.WithDrillStubKey(context.Background(), stubKey), rule.Format, b, rule.Fields)
			clear(stubKey)
			if e != nil {
				return nil, ErrExecution
			}
			data[name] = normalized.Bytes
		}
		b, e := json.Marshal(data)
		for _, v := range data {
			clear(v)
		}
		if e != nil {
			return nil, ErrExecution
		}
		sum := sha256.Sum256([]byte(c.Reference.Namespace + "/" + c.Reference.Name))
		files["config-"+hex.EncodeToString(sum[:])+".json"] = b
	}
	index := map[string]string{}
	for _, o := range set.Objects {
		sum := sha256.Sum256([]byte(o.Reference.Key))
		name := "object-" + hex.EncodeToString(sum[:]) + ".blob"
		index[o.Reference.Key] = name
		files[name] = append([]byte(nil), o.Data...)
	}
	for _, s := range set.Secrets {
		id := s.Reference.Namespace + "/" + s.Reference.Name
		data := map[string]string{}
		for _, k := range s.Reference.Keys {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte("clawmanager/drill-secret/v1\x00" + id + "\x00" + k))
			data[k] = "drill-disabled-" + hex.EncodeToString(mac.Sum(nil))
		}
		b, e := json.Marshal(data)
		if e != nil {
			return nil, ErrExecution
		}
		sum := sha256.Sum256([]byte(id))
		files["secret-"+hex.EncodeToString(sum[:])+".json"] = b
	}
	b, e := json.Marshal(index)
	if e != nil {
		return nil, ErrExecution
	}
	files["objects-index.json"] = b
	return files, nil
}
