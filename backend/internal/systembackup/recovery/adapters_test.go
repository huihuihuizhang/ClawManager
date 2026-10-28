package recovery

import (
	"bytes"
	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/staging"
	"context"
	"io"
	"testing"
)

func TestStagingCodecUnwrapsOnlyExactFrozenObjects(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{7}, 32)
	keys := artifact.SecretKeys{"kek": bytes.Repeat([]byte{8}, 32)}
	binding := staging.Binding{BackupID: "backup", Attempt: "1", Path: "mysql/data.enc", CaptureContextHash: ref("capture").SHA256, EnvelopeID: "mysql"}
	wrapped, e := keys.Wrap(ctx, binding, "kek", key)
	if e != nil {
		t.Fatal(e)
	}
	var ciphertext bytes.Buffer
	if e = staging.Seal(ctx, &ciphertext, key, binding, func(w io.Writer) error { _, e := w.Write([]byte("synthetic private content")); return e }); e != nil {
		t.Fatal(e)
	}
	object := Object{binding.Path, "immutable", int64(ciphertext.Len()), Hash(ciphertext.Bytes())}
	d := CodecDescriptor{StagingCodec, Identity{"origin", "backup", 1, "k8s", "cluster"}, binding.CaptureContextHash, 1024, []CodecEntry{{object, binding, wrapped}}}
	a, e := NewStagingAuthenticator(d, keys)
	if e != nil {
		t.Fatal(e)
	}
	m := Manifest{Identity: d.Identity, CaptureHash: d.CaptureSHA256}
	if e = a.Authenticate(ctx, m, object, bytes.NewReader(ciphertext.Bytes())); e != nil {
		t.Fatal(e)
	}
	wrong := object
	wrong.Version = "new"
	if a.Authenticate(ctx, m, wrong, bytes.NewReader(ciphertext.Bytes())) == nil {
		t.Fatal("replacement version accepted")
	}
	bad := append([]byte(nil), ciphertext.Bytes()...)
	bad[len(bad)-1] ^= 1
	if a.Authenticate(ctx, m, object, bytes.NewReader(bad)) == nil {
		t.Fatal("invalid final frame accepted")
	}
	d.Format = "owner-unknown.v1"
	if _, e = NewStagingAuthenticator(d, keys); e == nil {
		t.Fatal("unknown codec guessed")
	}
}

type redisArchiveFixture struct{ bad bool }

func (a redisArchiveFixture) ReadVerified(context.Context, Reference) ([]RedisItem, error) {
	_, v := redisFixture()
	if a.bad {
		v.SHA256 = "bad"
	}
	return []RedisItem{v}, nil
}

type redisTargetFixture struct {
	writes int
	fail   bool
}

func (d *redisTargetFixture) CheckIsolated(context.Context, RestoreTarget, Reference) error {
	return nil
}
func (d *redisTargetFixture) ServerTime(context.Context) (int64, error) { return 1050, nil }
func (d *redisTargetFixture) Restore(context.Context, RedisItem, int64) error {
	d.writes++
	if d.fail {
		return ErrUnavailable
	}
	return nil
}

type redisJournalFixture struct{ state, hash string }

func (j *redisJournalFixture) Begin(context.Context, RestoreTarget, Reference, RedisPolicy, []string) error {
	return nil
}

func (j *redisJournalFixture) Freeze(_ context.Context, _ RestoreTarget, _ Reference, _ int, hash string) (string, error) {
	if j.hash != "" && j.hash != hash {
		return "", ErrConflict
	}
	j.hash = hash
	if j.state == "" {
		j.state = "prepared"
	}
	return j.state, nil
}
func (j *redisJournalFixture) Sent(context.Context, RestoreTarget, Reference, int, string) error {
	j.state = "request_sent"
	return nil
}
func (j *redisJournalFixture) Done(context.Context, RestoreTarget, Reference, int, string, bool) error {
	j.state = "completed"
	return nil
}
func TestRedisArchiveRestoreChecksEverythingBeforeWritesAndNeverReplaysUnknown(t *testing.T) {
	p, _ := redisFixture()
	target := &redisTargetFixture{fail: true}
	j := &redisJournalFixture{}
	r := RedisRestorer{p, redisArchiveFixture{bad: true}, target, j, func(context.Context) (int64, error) { return 1050, nil }}
	destination := RestoreTarget{ID: "drill", Namespace: "cm-drill-test", Database: "redis-drill", Isolation: ref("isolation")}
	if e := r.Restore(context.Background(), ref("archive"), destination); e == nil || target.writes != 0 {
		t.Fatal("bad archive wrote target", e)
	}
	r.Source = redisArchiveFixture{}
	if e := r.Restore(context.Background(), ref("archive"), destination); e == nil || target.writes != 1 {
		t.Fatal(e)
	}
	target.fail = false
	if e := r.Restore(context.Background(), ref("archive"), destination); e == nil || target.writes != 1 {
		t.Fatal("unknown Redis write resent", e)
	}
}
