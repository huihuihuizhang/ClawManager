package systembackup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"k8s.io/client-go/kubernetes"
)

var ErrMinIOReadGate = errors.New("original MinIO read service unavailable; retain source admission")
var ErrMinIOReadGateUnknown = errors.New("original MinIO native outcome unknown; query the same operation and retain admission")

// Independently selected source inputs. The D owner check must bind the actual
// original server/whole-business bucket universe and stop all other source and
// administrative actors. This gate is native S3 admission, not a physical cut,
// original17 control or permission to omit logical history.
type MinIOReadGateInput struct {
	Namespace, NamespaceUID, Pod, PodUID, Container, ImageID                 string
	Endpoint, ServerName, Region, CAFile, CASHA256, SPKISHA256, DeploymentID string
	Operation, InventorySHA256, CustodyDirectory, MCFile, MCSHA256           string
	BusinessBuckets                                                          []string
	// Real existing publication identities may remain enabled only when their
	// complete current native policy permits no source-bucket mutation/admin.
	OutputAccounts []string
}

// Existing fixed credentials, supplied by the real source owner. Keeper must
// be an independent builtin non-root maintenance account, reader a distinct
// builtin read-only account. Credentials never enter public inspection output.
type MinIOGateCredential struct {
	AccessKey        string
	SecretKey        []byte
	Version          string
	NotBefore, Until time.Time
}

type minioGateUser struct {
	Name, Status, PolicyName string
	Policy                   json.RawMessage
}
type minioGateOriginal struct {
	Version                                                      string
	Input                                                        MinIOReadGateInput
	RootAccount, KeeperAccount, ReaderAccount, CredentialBinding string
	RootAccess                                                   string
	APIConfig                                                    json.RawMessage
	Users                                                        []minioGateUser
	BucketPolicies                                               map[string]string
	BucketNames                                                  []string
	ContainerID                                                  string
	CaptureUntil                                                 time.Time
}
type minioGateMutation struct{ Kind, Key, Target string }

type MinIOReadServiceGate struct {
	mu                                            sync.Mutex
	origin                                        *MinIOReadServiceGate
	in                                            MinIOReadGateInput
	kube                                          kubernetes.Interface
	check                                         TeamSourceCheck
	credentials                                   [3]MinIOGateCredential
	native                                        *minioGateNative
	reader, admin                                 *minio.Client
	original                                      minioGateOriginal
	custody                                       *minioGateCustody
	containerID                                   string
	started                                       time.Time
	until                                         time.Time
	sequence                                      int
	pending                                       *minioGateMutation
	held, restored, mutated, poisoned, recovering bool
}

func (*MinIOReadServiceGate) MarshalJSON() ([]byte, error) { return nil, ErrMinIOReadGate }
func (*MinIOReadServiceGate) String() string               { return "OriginalMinIOReadServiceGate" }
func minioGateHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func minioGateBytesHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// All actual reads, native version checks, complete builtin/derived identity
// enumeration and encrypted durable custody finish before the first mutation.
func PrepareMinIOReadServiceGate(ctx context.Context, kube kubernetes.Interface, in MinIOReadGateInput, root, keeper, reader MinIOGateCredential, check TeamSourceCheck, key []byte) (*MinIOReadServiceGate, error) {
	if ctx == nil || check == nil || kube == nil || check(ctx) != nil || !minioGateInputValid(in) || len(key) != 32 {
		return nil, ErrMinIOReadGate
	}
	until, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrMinIOReadGate
	}
	creds := [3]MinIOGateCredential{root, keeper, reader}
	seen := map[string]bool{}
	for n, c := range creds {
		if !minioGateCredentialValid(c, time.Now()) || seen[c.AccessKey] {
			return nil, ErrMinIOReadGate
		}
		seen[c.AccessKey] = true
		creds[n].SecretKey = append([]byte(nil), c.SecretKey...)
		if c.Until.Before(until) {
			until = c.Until
		}
	}
	g := &MinIOReadServiceGate{in: in, kube: kube, check: check, credentials: creds, until: until}
	g.origin = g
	g.in.BusinessBuckets = append([]string(nil), in.BusinessBuckets...)
	sort.Strings(g.in.BusinessBuckets)
	g.in.OutputAccounts = append([]string(nil), in.OutputAccounts...)
	sort.Strings(g.in.OutputAccounts)
	native, e := newMinioGateNative(ctx, g)
	if e != nil {
		g.Close()
		return nil, e
	}
	g.native = native
	if e = g.identity(ctx, true); e != nil {
		g.Close()
		return nil, e
	}
	first, e := g.collect(ctx)
	if e != nil {
		g.Close()
		return nil, e
	}
	second, e := g.collect(ctx)
	if e != nil || !reflect.DeepEqual(first, second) {
		g.Close()
		return nil, ErrMinIOReadGate
	}
	// The sealed journal has 1000 mutation slots. Reserve the entire possible
	// exact restore BEFORE accepting any mutation, including partial acquire
	// and process restart. Hitting the limit during restore is not recoverable
	// by inventing a new operation or dropping the original journal.
	if !g.planFits(first) {
		g.Close()
		return nil, ErrMinIOReadGate
	}
	g.original = *first
	if e = g.native.rootAccessProbe(ctx, g.original.RootAccess == "off"); e != nil {
		g.Close()
		return nil, e
	}
	g.custody, e = newMinioGateCustody(ctx, g, key)
	if e != nil {
		g.Close()
		return nil, e
	}
	if e = g.identity(ctx, false); e != nil {
		g.Close()
		return nil, e
	}
	return g, nil
}

func (g *MinIOReadServiceGate) planFits(original *minioGateOriginal) bool {
	if original == nil {
		return false
	}
	changes := 0
	if original.RootAccess != "off" {
		changes++
	}
	for _, user := range original.Users {
		if !g.keptAccount(user.Name) && user.Status == "enabled" {
			changes++
		}
	}
	for _, policy := range original.BucketPolicies {
		if policy != "" {
			changes++
		}
	}
	return changes <= 500
}

// S3 reads remain available through the separate native reader. Mutating an
// account/policy never substitutes for draining accepted S3 operations. The
// exact-version admin/API source also refuses active lifecycle/replication,
// derived credentials, external identity and unknown background task formats.
func (g *MinIOReadServiceGate) Acquire(ctx context.Context) error {
	if g == nil {
		return ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.held || g.restored || g.pending != nil || g.guard(ctx) != nil {
		return ErrMinIOReadGate
	}
	current, e := g.collect(ctx)
	if e != nil || !reflect.DeepEqual(*current, g.original) {
		return ErrMinIOReadGate
	}
	if g.original.RootAccess != "off" {
		if e = g.change(ctx, minioGateMutation{"root_access", "api", "off"}); e != nil {
			return e
		}
	}
	for _, u := range g.original.Users {
		if g.keptAccount(u.Name) || u.Status == "disabled" {
			continue
		}
		if e = g.change(ctx, minioGateMutation{"user_status", u.Name, "disabled"}); e != nil {
			return e
		}
	}
	for _, bucket := range g.in.BusinessBuckets {
		if g.original.BucketPolicies[bucket] != "" {
			if e = g.change(ctx, minioGateMutation{"bucket_policy", bucket, ""}); e != nil {
				return e
			}
		}
	}
	if e = g.recheckState(ctx, true); e != nil {
		return e
	}
	// A timeout is never an ACK. With all S3 writers fenced, a real current
	// zero from the fixed API metric contract drains prior accepted handlers.
	if e = g.native.waitS3Drain(ctx); e != nil {
		return e
	}
	if e = g.readProbe(ctx); e != nil {
		return e
	}
	if e = g.recheckState(ctx, true); e != nil {
		return e
	}
	g.held = true
	g.started = time.Now().UTC()
	return nil
}

func (g *MinIOReadServiceGate) guard(ctx context.Context) error {
	if g == nil || g.origin != g || g.poisoned || ctx == nil || ctx.Err() != nil || g.check == nil || g.check(ctx) != nil || !time.Now().Before(g.until) || g.native == nil || g.custody == nil || g.custody.recheckOriginal(ctx, g) != nil {
		return ErrMinIOReadGate
	}
	return g.identity(ctx, false)
}

func (g *MinIOReadServiceGate) change(ctx context.Context, m minioGateMutation) error {
	if g.pending != nil || g.guard(ctx) != nil {
		return ErrMinIOReadGate
	}
	g.sequence++
	g.pending = &m
	if e := g.custody.append(ctx, g.sequence, "send_unknown", m); e != nil {
		g.poisoned = true
		return e
	}
	g.mutated = true
	// Send once. On response loss, only this exact target's readback can
	// continue the operation; no duplicate write or guessed rollback is sent.
	_ = g.native.mutate(ctx, m)
	return g.resolvePending(ctx)
}
func (g *MinIOReadServiceGate) resolvePending(ctx context.Context) error {
	if g.pending == nil {
		return nil
	}
	ok, e := g.native.matches(ctx, *g.pending)
	if e != nil || !ok {
		return ErrMinIOReadGateUnknown
	}
	if e = g.custody.append(ctx, g.sequence, "resolved", *g.pending); e != nil {
		g.poisoned = true
		return ErrMinIOReadGateUnknown
	}
	g.pending = nil
	return nil
}

func (g *MinIOReadServiceGate) ResolvePending(ctx context.Context) error {
	if g == nil {
		return ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.guard(ctx) != nil {
		return ErrMinIOReadGate
	}
	return g.resolvePending(ctx)
}

// Fresh recovery authority/credentials replace expired capture authority only
// for restoring this SAME original operation and stored source identities.
// They never renew a capture observation or establish a new held gate.
func (g *MinIOReadServiceGate) RestoreWithFreshAuthority(ctx context.Context, root, keeper, reader MinIOGateCredential, fresh TeamSourceCheck) error {
	if g == nil || fresh == nil || fresh(ctx) != nil {
		return ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.origin != g || g.custody == nil || ctx == nil || ctx.Err() != nil || g.restored {
		return ErrMinIOReadGate
	}
	newCreds := [3]MinIOGateCredential{root, keeper, reader}
	until, bounded := ctx.Deadline()
	if !bounded {
		return ErrMinIOReadGate
	}
	for n, c := range newCreds {
		old := g.credentials[n]
		if !minioGateCredentialValid(c, time.Now()) || c.AccessKey != old.AccessKey || c.Version != old.Version || minioGateBytesHash(c.SecretKey) != minioGateBytesHash(old.SecretKey) {
			return ErrMinIOReadGate
		}
		newCreds[n].SecretKey = append([]byte(nil), c.SecretKey...)
		if c.Until.Before(until) {
			until = c.Until
		}
	}
	g.check = fresh
	g.until = until
	g.recovering = true
	for n := range g.credentials {
		clear(g.credentials[n].SecretKey)
	}
	g.credentials = newCreds
	if g.native != nil {
		g.native.close()
	}
	var e error
	g.native, e = newMinioGateNative(ctx, g)
	if e != nil {
		return e
	}
	if e = g.guard(ctx); e != nil {
		return e
	}
	if e = g.resolvePending(ctx); e != nil {
		return e
	}
	// Do not undo foreign state. Every current field must still equal either
	// its original value or this operation's exact gate target.
	if e = g.recheckRecoverable(ctx); e != nil {
		return e
	}
	for _, bucket := range g.in.BusinessBuckets {
		m := minioGateMutation{"bucket_policy", bucket, g.original.BucketPolicies[bucket]}
		if e = g.restoreOne(ctx, m); e != nil {
			return e
		}
	}
	for _, u := range g.original.Users {
		if u.Name == g.credentials[1].AccessKey || u.Name == g.credentials[2].AccessKey {
			continue
		}
		if e = g.restoreOne(ctx, minioGateMutation{"user_status", u.Name, u.Status}); e != nil {
			return e
		}
	}
	if e = g.restoreOne(ctx, minioGateMutation{"root_access", "api", g.original.RootAccess}); e != nil {
		return e
	}
	if e = g.recheckState(ctx, false); e != nil {
		return e
	}
	g.restored = true
	g.held = false
	return nil
}
func (g *MinIOReadServiceGate) restoreOne(ctx context.Context, m minioGateMutation) error {
	ok, e := g.native.matches(ctx, m)
	if e != nil {
		return e
	}
	if ok {
		return nil
	}
	return g.change(ctx, m)
}

func (g *MinIOReadServiceGate) ObserveHeld(ctx context.Context) (*VerifiedMinIOReadServiceObservation, error) {
	if g == nil {
		return nil, ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.held || g.restored || g.recovering || g.pending != nil || g.guard(ctx) != nil || g.recheckState(ctx, true) != nil {
		return nil, ErrMinIOReadGate
	}
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	if g.until.Before(until) {
		until = g.until
	}
	v := &VerifiedMinIOReadServiceObservation{gate: g, operation: g.in.Operation, inventory: g.in.InventorySHA256, source: minioGateHash(g.original), phase: "held", started: now, until: until}
	v.origin = v
	return v, nil
}
func (g *MinIOReadServiceGate) ObserveRecovered(ctx context.Context) (*VerifiedMinIOReadServiceObservation, error) {
	if g == nil {
		return nil, ErrMinIOReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.restored || g.pending != nil || g.guard(ctx) != nil || g.recheckState(ctx, false) != nil {
		return nil, ErrMinIOReadGate
	}
	now := time.Now().UTC()
	until := now.Add(10 * time.Second)
	if g.until.Before(until) {
		until = g.until
	}
	v := &VerifiedMinIOReadServiceObservation{gate: g, operation: g.in.Operation, inventory: g.in.InventorySHA256, source: minioGateHash(g.original), phase: "recovered", started: now, until: until}
	v.origin = v
	return v, nil
}

type VerifiedMinIOReadServiceObservation struct {
	origin                              *VerifiedMinIOReadServiceObservation
	gate                                *MinIOReadServiceGate
	operation, inventory, source, phase string
	started, until                      time.Time
}
type MinIOReadServiceObservationData struct {
	Version, Operation, InventorySHA256, PodUID, DeploymentID, OriginalSHA256, Phase string
	StartedAt, ValidUntil                                                            time.Time
}

func (*VerifiedMinIOReadServiceObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrMinIOReadGate
}
func (v *VerifiedMinIOReadServiceObservation) Data() MinIOReadServiceObservationData {
	if v == nil || v.origin != v || v.gate == nil {
		return MinIOReadServiceObservationData{}
	}
	g := v.gate
	return MinIOReadServiceObservationData{"minio-native-read-service-observation.v1", v.operation, v.inventory, g.in.PodUID, g.in.DeploymentID, v.source, v.phase, v.started, v.until}
}
func (v *VerifiedMinIOReadServiceObservation) Recheck(ctx context.Context, operation, inventory, phase string, now time.Time) error {
	if v == nil || v.origin != v || v.gate == nil || ctx == nil || ctx.Err() != nil || v.operation != operation || v.inventory != inventory || v.phase != phase || now.Before(v.started) || !now.Before(v.until) || !time.Now().Before(v.until) {
		return ErrMinIOReadGate
	}
	g := v.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.origin != g || g.poisoned || g.pending != nil || v.source != minioGateHash(g.original) || phase == "held" && (!g.held || g.restored || g.recovering) || phase == "recovered" && !g.restored {
		return ErrMinIOReadGate
	}
	return nil
}
func (g *MinIOReadServiceGate) keptAccount(name string) bool {
	if name == g.credentials[1].AccessKey || name == g.credentials[2].AccessKey {
		return true
	}
	for _, x := range g.in.OutputAccounts {
		if name == x {
			return true
		}
	}
	return false
}
func (g *MinIOReadServiceGate) OriginalDigest() string {
	if g == nil || g.origin != g {
		return ""
	}
	return minioGateHash(g.original)
}
func (g *MinIOReadServiceGate) Close() {
	if g == nil {
		return
	}
	g.poisoned = true
	if g.native != nil {
		g.native.close()
	}
	for n := range g.credentials {
		clear(g.credentials[n].SecretKey)
	}
	if g.custody != nil {
		g.custody.close()
	}
}
