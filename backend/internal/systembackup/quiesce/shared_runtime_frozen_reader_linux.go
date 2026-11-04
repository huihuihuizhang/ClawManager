//go:build linux

package quiesce

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

// Creates an independent read-only observer. It never acquires the mutating
// owner's guard, creates a store or writes cgroup.freeze.
func NewSharedRuntimeFrozenObserver(o *NodeObserver, c SharedRuntimeFrozenReaderConfig) (*NodeObserver, error) {
	if o == nil || len(o.key) != 32 || !absoluteObservationPath(c.Directory) || c.Directory == "/" || !absoluteObservationPath(c.CgroupMount) || len(c.Releases) == 0 {
		return nil, ErrNodeObservation
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(c.Directory, "/"), "/") {
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 || current == c.Directory && st.Mode&0777 != 0700 {
			return nil, ErrNodeObservation
		}
	}
	c.Releases = copySharedRuntimeReleases(c.Releases)
	if len(c.Releases) == 0 {
		return nil, ErrNodeObservation
	}
	clone := *o
	clone.key = append([]byte(nil), o.key...)
	clone.sharedFrozen = &c
	return &clone, nil
}

func copySharedRuntimeReleases(in map[string]SharedRuntimeAgentRelease) map[string]SharedRuntimeAgentRelease {
	out := map[string]SharedRuntimeAgentRelease{}
	for k, v := range in {
		if k != "openclaw" && k != "hermes" || !validObservationHash(v.ExecutableSHA256) || !absoluteObservationPath(v.DataDir) || v.DataDir == "/" {
			return nil
		}
		out[k] = v
	}
	return out
}

func sharedFrozenBindingMatches(cold, shared ObservationBinding) bool {
	if cold.Kind != NodeObservationWholePodColdCut || shared.Kind != SharedRuntimeNodeKind || cold.ReservationID == "" || shared.ReservationID == "" {
		return false
	}
	cold.Kind, shared.Kind = "", ""
	cold.ReservationID, shared.ReservationID = "", ""
	return reflect.DeepEqual(cold, shared)
}

func (o *NodeObserver) readSharedFrozenRecords(ctx context.Context, a nodeObservationAnchor, scopes []SharedRuntimeFrozenScope) ([]sharedRuntimeOwnerRecord, []*sharedCgroupHandle, error) {
	if o.sharedFrozen == nil || len(scopes) == 0 || len(scopes) > 128 {
		return nil, nil, ErrNodeObservation
	}
	c := o.sharedFrozen
	// This view has no guard and cannot run lifecycle mutations. Only the
	// domain-separated MAC and immutable original load helpers are used here.
	view := &sharedRuntimeNodeOwner{observer: o, directory: c.Directory, cgroupMount: c.CgroupMount, releases: map[string]sharedRuntimeAgentRelease{}}
	for k, v := range c.Releases {
		view.releases[k] = sharedRuntimeAgentRelease{v.ExecutableSHA256, v.DataDir}
	}
	paths := make([]string, len(a.Paths))
	for i, p := range a.Paths {
		paths[i] = p.Path
	}
	records := []sharedRuntimeOwnerRecord{}
	handles := []*sharedCgroupHandle{}
	fail := func() ([]sharedRuntimeOwnerRecord, []*sharedCgroupHandle, error) {
		for _, h := range handles {
			h.close()
		}
		return nil, nil, ErrNodeObservation
	}
	peers := []SharedRuntimeNodePeer{}
	for i, s := range scopes {
		if !sharedFrozenBindingMatches(a.Binding, s.Binding) || !validObservationPods([]PodIdentity{s.AgentPod}, o.Node) || len(s.AgentPod.Containers) != 1 || i > 0 && s.AgentPod.UID <= scopes[i-1].AgentPod.UID || len(s.Anchor) > 512<<10 {
			return fail()
		}
		parts := strings.Split(s.Anchor, ".")
		if len(parts) != 2 {
			return fail()
		}
		raw, e := base64.RawURLEncoding.DecodeString(parts[0])
		if e != nil || !hmac.Equal([]byte(parts[1]), []byte(view.mac(raw))) {
			return fail()
		}
		var pin struct {
			ID      string
			Binding ObservationBinding
			Pod     PodIdentity
			Cgroup  sharedCgroupPin
		}
		if json.Unmarshal(raw, &pin) != nil || !validObservationHash(pin.ID) || !reflect.DeepEqual(pin.Binding, s.Binding) || !reflect.DeepEqual(pin.Pod, s.AgentPod) {
			return fail()
		}
		raw, _, _, e = sharedRuntimeNativeRead(ctx, c.Directory, "/"+pin.ID+".json", 4<<20)
		if e != nil {
			return fail()
		}
		var envelope sharedRuntimeOwnerEnvelope
		var rec sharedRuntimeOwnerRecord
		if json.Unmarshal(raw, &envelope) != nil || !hmac.Equal([]byte(envelope.MAC), []byte(view.mac(envelope.Record))) || json.Unmarshal(envelope.Record, &rec) != nil || rec.Version != SharedRuntimeNodeProtocol || rec.ID != pin.ID || rec.ID != sharedRuntimeOwnerID(rec.Original) || rec.Anchor != s.Anchor || rec.Anchor != view.anchor(rec) || rec.Sequence == 0 || rec.Cgroup.BootID != o.BootID || rec.Phase != "frozen" && rec.Phase != "freezing" || !reflect.DeepEqual(rec.Original.Binding, s.Binding) || !reflect.DeepEqual(rec.Original.AgentPod, s.AgentPod) || !reflect.DeepEqual(rec.Original.SourcePaths, paths) || rec.Original.Original.OriginalSHA256 != s.OriginalSHA256 || rec.Witness.JournalSHA256 != s.NativeJournalSHA256 || rec.CohortSHA256 != s.CohortSHA256 || SharedRuntimeNodeSourcePathsSHA(rec.Original) != s.SourcePathsSHA256 {
			return fail()
		}
		h, e := openSharedCgroup(ctx, c.CgroupMount, o.HostProc, rec.Cgroup.Root, &rec.Cgroup)
		if e != nil {
			return fail()
		}
		handles = append(handles, h)
		if h.checkFrozen(ctx) != nil {
			return fail()
		}
		w, e := o.sharedRuntimeWitness(ctx, rec.Original, rec.Original.Original, view.releases)
		if e != nil || !reflect.DeepEqual(w, rec.Witness) {
			return fail()
		}
		records = append(records, rec)
		peers = append(peers, SharedRuntimeNodePeer{PodUID: s.AgentPod.UID, OriginalSHA256: s.OriginalSHA256, Anchor: s.Anchor})
	}
	for _, rec := range records {
		if rec.CohortSHA256 != observationDigest(peers) {
			return fail()
		}
	}
	return records, handles, nil
}

func (o *NodeObserver) stoppedWithSharedScopes(ctx context.Context, a nodeObservationAnchor, scopes []SharedRuntimeFrozenScope) (int, int, error) {
	if len(scopes) == 0 {
		return o.stopped(ctx, a)
	}
	records, handles, e := o.readSharedFrozenRecords(ctx, a, scopes)
	if e != nil {
		return 0, 0, e
	}
	defer func() {
		for _, h := range handles {
			h.close()
		}
	}()
	files, e := o.files(ctx, a.Paths)
	if e != nil {
		return 0, 0, e
	}
	n, _, e := o.scanWithSharedFrozen(ctx, a, files, handles)
	if e != nil {
		return 0, 0, e
	}
	after, e := o.files(ctx, a.Paths)
	if e != nil || !reflect.DeepEqual(files, after) {
		return 0, 0, ErrNodeObservation
	}
	last, tail, e := o.readSharedFrozenRecords(ctx, a, scopes)
	if e != nil {
		return 0, 0, e
	}
	defer func() {
		for _, h := range tail {
			h.close()
		}
	}()
	if !reflect.DeepEqual(records, last) {
		return 0, 0, ErrNodeObservation
	}
	for _, h := range handles {
		if h.checkFrozen(ctx) != nil {
			return 0, 0, ErrNodeObservation
		}
	}
	paths := make([]string, len(a.Paths))
	for i, p := range a.Paths {
		paths[i] = p.Path
	}
	current, e := o.paths(ctx, paths)
	if e != nil || !reflect.DeepEqual(current, a.Paths) {
		return 0, 0, ErrNodeObservation
	}
	return n, len(files), ctx.Err()
}
