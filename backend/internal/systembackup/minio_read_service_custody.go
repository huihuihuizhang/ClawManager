package systembackup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/staging"
	"k8s.io/client-go/kubernetes"
)

type minioGateCustody struct {
	root      *os.Root
	directory string
	identity  os.FileInfo
	key       []byte
	binding   staging.Binding
	original  minioGateOriginal
}
type minioGateJournalRecord struct {
	Version, OriginalSHA256, Phase string
	Sequence                       int
	Mutation                       minioGateMutation
}

func minioGateOriginalName(op string) string { return "minio-gate-" + op + ".original.sealed" }
func minioGateStepName(op string, sequence int, phase string) string {
	return fmt.Sprintf("minio-gate-%s.%06d.%s.sealed", op, sequence, phase)
}

func openMinioGateCustody(g *MinIOReadServiceGate, key []byte) (*minioGateCustody, error) {
	dir := g.in.CustodyDirectory
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || !redisGatePrivate(st) || len(key) != 32 {
		return nil, ErrMinIOReadGate
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, ErrMinIOReadGate
	}
	f, e := r.Open(".")
	if e != nil {
		r.Close()
		return nil, e
	}
	opened, e := f.Stat()
	ce := f.Close()
	if e != nil || ce != nil || !os.SameFile(st, opened) {
		r.Close()
		return nil, ErrMinIOReadGate
	}
	c := &minioGateCustody{root: r, directory: dir, identity: st, key: append([]byte(nil), key...)}
	c.binding = staging.Binding{BackupID: g.in.Operation, Attempt: "original-minio-read-gate.v1", CaptureContextHash: g.in.InventorySHA256, EnvelopeID: minioGateHash(g.in)}
	return c, nil
}
func newMinioGateCustody(ctx context.Context, g *MinIOReadServiceGate, key []byte) (*minioGateCustody, error) {
	c, e := openMinioGateCustody(g, key)
	if e != nil {
		return nil, e
	}
	c.original = g.original
	if e = c.write(ctx, minioGateOriginalName(g.in.Operation), g.original); e != nil {
		c.close()
		return nil, e
	}
	if e = c.recheckOriginal(ctx, g); e != nil {
		c.close()
		return nil, e
	}
	return c, nil
}
func (c *minioGateCustody) directoryCurrent() bool {
	st, e := os.Lstat(c.directory)
	return e == nil && c.identity != nil && os.SameFile(st, c.identity) && st.IsDir() && redisGatePrivate(st)
}
func (c *minioGateCustody) write(ctx context.Context, name string, value any) error {
	if c == nil || c.root == nil || !c.directoryCurrent() {
		return ErrMinIOReadGate
	}
	plain, e := json.Marshal(value)
	if e != nil || len(plain) > 4<<20 {
		return ErrMinIOReadGate
	}
	defer clear(plain)
	return staging.WithCustodyLock(ctx, c.root, func() error {
		f, e := c.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return ErrMinIOReadGate
		}
		binding := c.binding
		binding.Path = name
		e = staging.Seal(ctx, f, c.key, binding, func(w io.Writer) error { _, e := w.Write(plain); return e })
		se := f.Sync()
		ce := f.Close()
		if e != nil || se != nil || ce != nil {
			return ErrMinIOReadGate
		}
		d, e := c.root.Open(".")
		if e != nil {
			return ErrMinIOReadGate
		}
		se = d.Sync()
		ce = d.Close()
		if se != nil || ce != nil {
			return ErrMinIOReadGate
		}
		read, e := c.read(ctx, name)
		defer clear(read)
		if e != nil || !bytes.Equal(read, plain) {
			return ErrMinIOReadGate
		}
		return nil
	})
}
func (c *minioGateCustody) read(ctx context.Context, name string) ([]byte, error) {
	if c == nil || c.root == nil || !c.directoryCurrent() {
		return nil, ErrMinIOReadGate
	}
	st, e := c.root.Lstat(name)
	if e != nil || !st.Mode().IsRegular() || !redisGatePrivate(st) || st.Size() < 1 || st.Size() > 5<<20 {
		return nil, ErrMinIOReadGate
	}
	f, e := c.root.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, ErrMinIOReadGate
	}
	var plain minioGateBuffer
	binding := c.binding
	binding.Path = name
	if staging.Open(ctx, f, &plain, c.key, binding, 4<<20) != nil {
		clear(plain.Bytes())
		return nil, ErrMinIOReadGate
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		clear(plain.Bytes())
		return nil, ErrMinIOReadGate
	}
	return plain.Bytes(), nil
}
func (c *minioGateCustody) recheckOriginal(ctx context.Context, g *MinIOReadServiceGate) error {
	if c == nil || !reflect.DeepEqual(c.original, g.original) {
		return ErrMinIOReadGate
	}
	b, e := c.read(ctx, minioGateOriginalName(g.in.Operation))
	if e != nil {
		return e
	}
	defer clear(b)
	var original minioGateOriginal
	if minioGateDecode(b, &original) != nil || !reflect.DeepEqual(original, g.original) {
		return ErrMinIOReadGate
	}
	return nil
}
func (c *minioGateCustody) append(ctx context.Context, sequence int, phase string, m minioGateMutation) error {
	if sequence < 1 || sequence > 1000 || phase != "send_unknown" && phase != "resolved" {
		return ErrMinIOReadGate
	}
	r := minioGateJournalRecord{"minio-read-gate-native-step.v1", minioGateHash(c.original), phase, sequence, m}
	return c.write(ctx, minioGateStepName(c.original.Input.Operation, sequence, phase), r)
}
func (c *minioGateCustody) close() {
	if c == nil {
		return
	}
	if c.root != nil {
		c.root.Close()
	}
	clear(c.key)
}

// Process-restart recovery reads the original encrypted snapshot and EVERY
// original step to EOF. It creates no replacement original, held observation or
// copy operation. The fresh real D recovery owner must authorize the same op.
func OpenMinIOReadServiceRecovery(ctx context.Context, kube kubernetes.Interface, in MinIOReadGateInput, root, keeper, reader MinIOGateCredential, fresh TeamSourceCheck, key []byte) (*MinIOReadServiceGate, error) {
	if ctx == nil || kube == nil || fresh == nil || fresh(ctx) != nil || !minioGateInputValid(in) {
		return nil, ErrMinIOReadGate
	}
	until, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrMinIOReadGate
	}
	creds := [3]MinIOGateCredential{root, keeper, reader}
	for n, c := range creds {
		if !minioGateCredentialValid(c, time.Now()) {
			return nil, ErrMinIOReadGate
		}
		creds[n].SecretKey = append([]byte(nil), c.SecretKey...)
		if c.Until.Before(until) {
			until = c.Until
		}
	}
	g := &MinIOReadServiceGate{in: in, kube: kube, check: fresh, credentials: creds, until: until, recovering: true}
	g.origin = g
	g.in.BusinessBuckets = append([]string(nil), in.BusinessBuckets...)
	sort.Strings(g.in.BusinessBuckets)
	g.in.OutputAccounts = append([]string(nil), in.OutputAccounts...)
	sort.Strings(g.in.OutputAccounts)
	c, e := openMinioGateCustody(g, key)
	if e != nil {
		g.Close()
		return nil, e
	}
	g.custody = c
	b, e := c.read(ctx, minioGateOriginalName(in.Operation))
	if e != nil {
		g.Close()
		return nil, e
	}
	e = minioGateDecode(b, &g.original)
	clear(b)
	if e != nil || g.original.Version != "original-minio-read-gate-state.v1" || !reflect.DeepEqual(g.original.Input, g.in) || g.original.CredentialBinding != minioGateCredentialBinding(creds) || g.original.ContainerID == "" || g.original.CaptureUntil.IsZero() {
		g.Close()
		return nil, ErrMinIOReadGate
	}
	c.original = g.original
	g.containerID = g.original.ContainerID
	g.native, e = newMinioGateNative(ctx, g)
	if e != nil || g.identity(ctx, false) != nil {
		g.Close()
		return nil, ErrMinIOReadGate
	}
	if e = c.replay(ctx, g); e != nil {
		g.Close()
		return nil, e
	}
	if g.recheckRecoverable(ctx) != nil {
		g.Close()
		return nil, ErrMinIOReadGate
	}
	return g, nil
}
func (c *minioGateCustody) replay(ctx context.Context, g *MinIOReadServiceGate) error {
	f, e := c.root.Open(".")
	if e != nil {
		return ErrMinIOReadGate
	}
	entries, e := f.ReadDir(-1)
	ce := f.Close()
	if e != nil || ce != nil || len(entries) > 10000 {
		return ErrMinIOReadGate
	}
	type step struct{ sent, done *minioGateJournalRecord }
	steps := map[int]*step{}
	max := 0
	prefix := "minio-gate-" + g.in.Operation + "."
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || name == minioGateOriginalName(g.in.Operation) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(name, prefix), ".")
		if len(parts) != 3 || parts[2] != "sealed" || len(parts[0]) != 6 {
			return ErrMinIOReadGate
		}
		seq, e := strconv.Atoi(parts[0])
		if e != nil || seq < 1 || seq > 1000 || parts[1] != "send_unknown" && parts[1] != "resolved" {
			return ErrMinIOReadGate
		}
		b, e := c.read(ctx, name)
		if e != nil {
			return e
		}
		var r minioGateJournalRecord
		e = minioGateDecode(b, &r)
		clear(b)
		if e != nil || r.Version != "minio-read-gate-native-step.v1" || r.OriginalSHA256 != minioGateHash(g.original) || r.Sequence != seq || r.Phase != parts[1] {
			return ErrMinIOReadGate
		}
		if steps[seq] == nil {
			steps[seq] = &step{}
		}
		s := steps[seq]
		if parts[1] == "send_unknown" {
			if s.sent != nil {
				return ErrMinIOReadGate
			}
			s.sent = &r
		} else {
			if s.done != nil {
				return ErrMinIOReadGate
			}
			s.done = &r
		}
		if seq > max {
			max = seq
		}
	}
	for seq := 1; seq <= max; seq++ {
		s := steps[seq]
		if s == nil || s.sent == nil {
			return ErrMinIOReadGate
		}
		if s.done != nil {
			if s.done.Mutation != s.sent.Mutation {
				return ErrMinIOReadGate
			}
		} else {
			if seq != max {
				return ErrMinIOReadGate
			}
			m := s.sent.Mutation
			g.pending = &m
		}
	}
	g.sequence = max
	g.mutated = max > 0
	return nil
}
