package systembackup

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"

	"clawreef/internal/systembackup/staging"
)

type redisReadGateOriginal struct {
	Version    string
	Input      RedisReadGateInput
	Users      []redisGateUser
	OwnerValue string
}

func redisGatePrivate(info os.FileInfo) bool {
	if info == nil || runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return false
	}
	if runtime.GOOS != "linux" {
		return true
	}
	stat := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if !stat.IsValid() {
		return false
	}
	uid := stat.FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(os.Geteuid())
}

// Actual encrypted durable original ACL custody, before the first native SET
// NX / ACL request. Neither ACL password hashes nor a bearer credential enters
// inspection JSON, a public journal or stdout. Key bytes come from the real
// owner's existing private key resolver; this code does not issue a new key.
func (g *RedisReadServiceGate) sealOriginal(ctx context.Context, key []byte) error {
	dir := g.in.CustodyDirectory
	if len(key) != 32 || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return ErrRedisReadGate
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !redisGatePrivate(info) {
		return ErrRedisReadGate
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return ErrRedisReadGate
	}
	g.custody = root
	g.custodyDirectoryIdentity = info
	g.custodyKey = bytes.Clone(key)
	g.custodyName = "redis-acl-original-" + g.in.Operation + ".sealed"
	g.custodyBinding = staging.Binding{BackupID: g.in.Operation, Attempt: "original-redis-acl-custody.v1", Path: g.custodyName, CaptureContextHash: g.in.InventorySHA256, EnvelopeID: g.ownerValue}
	err := staging.WithCustodyLock(ctx, root, func() error {
		f, e := root.OpenFile(g.custodyName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return ErrRedisReadGate
		}
		plain, e := json.Marshal(redisReadGateOriginal{"original-redis-acl-custody.v1", g.in, g.original, g.ownerValue})
		if e != nil || len(plain) > 4<<20 {
			f.Close()
			return ErrRedisReadGate
		}
		defer clear(plain)
		e = staging.Seal(ctx, f, g.custodyKey, g.custodyBinding, func(w io.Writer) error { _, err := w.Write(plain); return err })
		syncErr := f.Sync()
		closeErr := f.Close()
		if e != nil || syncErr != nil || closeErr != nil {
			return ErrRedisReadGate
		}
		d, e := root.Open(".")
		if e != nil {
			return ErrRedisReadGate
		}
		syncErr = d.Sync()
		closeErr = d.Close()
		if syncErr != nil || closeErr != nil {
			return ErrRedisReadGate
		}
		return g.readOriginalCustody(ctx)
	})
	if err != nil {
		root.Close()
		g.custody = nil
		clear(g.custodyKey)
		return ErrRedisReadGate
	}
	return nil
}

func (g *RedisReadServiceGate) readOriginalCustody(ctx context.Context) error {
	if g.custody == nil || len(g.custodyKey) != 32 {
		return ErrRedisReadGate
	}
	dir, e := os.Lstat(g.in.CustodyDirectory)
	if e != nil || g.custodyDirectoryIdentity == nil || !os.SameFile(dir, g.custodyDirectoryIdentity) || !dir.IsDir() || !redisGatePrivate(dir) {
		return ErrRedisReadGate
	}
	info, e := g.custody.Lstat(g.custodyName)
	if e != nil || !info.Mode().IsRegular() || !redisGatePrivate(info) || info.Size() <= 0 || info.Size() > 5<<20 {
		return ErrRedisReadGate
	}
	f, e := g.custody.Open(g.custodyName)
	if e != nil {
		return ErrRedisReadGate
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return ErrRedisReadGate
	}
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, f, &plain, g.custodyKey, g.custodyBinding, 4<<20) != nil {
		return ErrRedisReadGate
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return ErrRedisReadGate
	}
	var original redisReadGateOriginal
	d := json.NewDecoder(bytes.NewReader(plain.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&original) != nil || d.Decode(new(any)) != io.EOF || original.Version != "original-redis-acl-custody.v1" || !reflect.DeepEqual(original.Input, g.in) || !reflect.DeepEqual(original.Users, g.original) || original.OwnerValue != g.ownerValue {
		return ErrRedisReadGate
	}
	return nil
}

func (g *RedisReadServiceGate) compatibleCurrent(ctx context.Context) error {
	users, e := g.users(ctx)
	if e != nil {
		return ErrRedisReadGate
	}
	seen := map[string]bool{}
	for _, actual := range users {
		if actual.Name == g.marker {
			continue
		}
		found := false
		for _, original := range g.original {
			if original.Name != actual.Name {
				continue
			}
			found = true
			if reflect.DeepEqual(actual, original) {
				break
			}
			want, ok := g.expected[actual.Name]
			if !ok || g.expectedUser(actual, want) != nil {
				return ErrRedisReadGate
			}
		}
		if !found || seen[actual.Name] {
			return ErrRedisReadGate
		}
		seen[actual.Name] = true
	}
	if len(seen) != len(g.original) {
		return ErrRedisReadGate
	}
	return nil
}
