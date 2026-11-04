//go:build linux

package quiesce

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// This is a distinct native MUTATING owner; NodeObserver stays read-only.
// Callers are the deployment's authenticated controller transport, not request-
// selected callbacks. Original SQL/object admission and reader-drain authority
// remain at the original controller. RecoveryBoundarySHA256 is correlation
// data, never a replacement for that concrete controller recovery fence.
type sharedRuntimeNodeOwner struct {
	observer               *NodeObserver
	cgroupMount, directory string
	releases               map[string]sharedRuntimeAgentRelease
	guard                  *os.File
	mu                     sync.Mutex
}
type sharedRuntimeOwnerRecord struct {
	Version, ID, Anchor, Phase, CohortSHA256, RecoveryBoundarySHA256 string
	Original                                                         SharedRuntimeNodeRequest
	Witness                                                          sharedRuntimeNativeWitness
	Cgroup                                                           sharedCgroupPin
	Sequence                                                         uint64
	UpdatedAt                                                        time.Time
	Tasks, Files                                                     int
}
type sharedRuntimeOwnerEnvelope struct {
	Record json.RawMessage
	MAC    string
}

const sharedRuntimeOwnerDomain = "shared-runtime-native-owner.v1\x00"

func newSharedRuntimeNodeOwner(o *NodeObserver, mount, directory string, releases map[string]sharedRuntimeAgentRelease) (*sharedRuntimeNodeOwner, error) {
	if o == nil || len(o.key) != 32 || !absoluteObservationPath(mount) || !absoluteObservationPath(directory) || directory == "/" || len(releases) == 0 {
		return nil, ErrNodeObservation
	}
	// Deployment configuration, never a lifecycle-request path. All ancestors
	// must be root-owned and non-writable by another principal.
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Dir(directory), "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		var st unix.Stat_t
		if unix.Lstat(current, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return nil, ErrNodeObservation
		}
	}
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return nil, ErrNodeObservation
	}
	var st unix.Stat_t
	if unix.Lstat(directory, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0777 != 0700 {
		return nil, ErrNodeObservation
	}
	copyReleases := map[string]sharedRuntimeAgentRelease{}
	for k, v := range releases {
		if k == "" || !validObservationHash(v.ExecutableSHA256) || !absoluteObservationPath(v.DataDir) {
			return nil, ErrNodeObservation
		}
		copyReleases[k] = v
	}
	fd, err := unix.Open(filepath.Join(directory, ".owner.guard"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrNodeObservation
	}
	f := os.NewFile(uintptr(fd), "shared-native-owner-guard")
	if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, ErrNodeObservation
	}
	return &sharedRuntimeNodeOwner{observer: o, cgroupMount: mount, directory: directory, releases: copyReleases, guard: f}, nil
}
func (o *sharedRuntimeNodeOwner) close() {
	if o != nil && o.guard != nil {
		o.guard.Close()
		o.guard = nil
	}
}

func sharedRuntimeOwnerOriginal(r SharedRuntimeNodeRequest) SharedRuntimeNodeRequest {
	r.Action = ""
	r.Nonce = ""
	r.Deadline = time.Time{}
	r.Current = nil
	r.CurrentRaw = nil
	r.Peers = nil
	r.Anchor = ""
	r.RecoveryBoundarySHA256 = ""
	return r
}
func sharedRuntimeOwnerID(r SharedRuntimeNodeRequest) string {
	return observationDigest(sharedRuntimeOwnerOriginal(r))
}
func (o *sharedRuntimeNodeOwner) mac(raw []byte) string {
	h := hmac.New(sha256.New, o.observer.key)
	h.Write([]byte(sharedRuntimeOwnerDomain))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}
func (o *sharedRuntimeNodeOwner) anchor(record sharedRuntimeOwnerRecord) string {
	b, _ := json.Marshal(struct {
		ID      string
		Binding ObservationBinding
		Pod     PodIdentity
		Cgroup  sharedCgroupPin
	}{record.ID, record.Original.Binding, record.Original.AgentPod, record.Cgroup})
	return base64.RawURLEncoding.EncodeToString(b) + "." + o.mac(b)
}
func sharedRuntimeOwnerSync(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	e := f.Sync()
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}

// Write immutable event, fsync it and its directory, then atomically replace
// current. An uncertain write leaves its original obligation, never permission
// to perform a new physical operation or erase an old record.
func (o *sharedRuntimeNodeOwner) save(record *sharedRuntimeOwnerRecord) error {
	if record == nil || !validObservationHash(record.ID) || record.Sequence == ^uint64(0) {
		return ErrNodeObservation
	}
	record.Sequence++
	record.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	envelope, err := json.Marshal(sharedRuntimeOwnerEnvelope{raw, o.mac(raw)})
	if err != nil || len(envelope) > 4<<20 {
		return ErrNodeObservation
	}
	event := filepath.Join(o.directory, record.ID+"-"+observationDigest(record)+".event")
	f, err := os.OpenFile(event, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, e := f.Write(envelope)
	s, c := f.Sync(), f.Close()
	if e != nil || s != nil || c != nil || n != len(envelope) || sharedRuntimeOwnerSync(o.directory) != nil {
		return ErrNodeObservation
	}
	tmp, err := os.CreateTemp(o.directory, ".pending-"+record.ID+"-")
	if err != nil {
		return err
	}
	// Retain uncertain files. They are not evidence of COMMIT or recovery.
	if tmp.Chmod(0600) != nil {
		tmp.Close()
		return ErrNodeObservation
	}
	n, e = tmp.Write(envelope)
	s, c = tmp.Sync(), tmp.Close()
	if e != nil || s != nil || c != nil || n != len(envelope) {
		return ErrNodeObservation
	}
	if os.Rename(tmp.Name(), filepath.Join(o.directory, record.ID+".json")) != nil || sharedRuntimeOwnerSync(o.directory) != nil {
		return ErrNodeObservation
	}
	return nil
}
func (o *sharedRuntimeNodeOwner) load(r SharedRuntimeNodeRequest) (sharedRuntimeOwnerRecord, error) {
	var record sharedRuntimeOwnerRecord
	id := sharedRuntimeOwnerID(r)
	raw, _, _, err := sharedRuntimeNativeRead(context.Background(), o.directory, "/"+id+".json", 4<<20)
	if err != nil {
		return record, err
	}
	var envelope sharedRuntimeOwnerEnvelope
	if json.Unmarshal(raw, &envelope) != nil || !hmac.Equal([]byte(envelope.MAC), []byte(o.mac(envelope.Record))) || json.Unmarshal(envelope.Record, &record) != nil || record.Version != SharedRuntimeNodeProtocol || record.ID != id || record.Sequence == 0 || record.Anchor != o.anchor(record) || observationDigest(record.Original) != observationDigest(sharedRuntimeOwnerOriginal(r)) || record.Cgroup.BootID != o.observer.BootID {
		return sharedRuntimeOwnerRecord{}, ErrNodeObservation
	}
	if r.Anchor != "" && r.Anchor != record.Anchor {
		return sharedRuntimeOwnerRecord{}, ErrNodeObservation
	}
	return record, nil
}

// A lost current-pointer replacement cannot permit another prepare. Events
// remain immutable; a pending file is harmless only after the SAME original
// operation has a later authenticated completed record. Recovery may still
// operate on its last known original record and exact pinned cgroup.
func (o *sharedRuntimeNodeOwner) prepareWriteBoundary(ctx context.Context) error {
	entries, err := os.ReadDir(o.directory)
	if err != nil || len(entries) > 4096 {
		return ErrNodeObservation
	}
	decode := func(raw []byte) (sharedRuntimeOwnerRecord, error) {
		var envelope sharedRuntimeOwnerEnvelope
		var record sharedRuntimeOwnerRecord
		if json.Unmarshal(raw, &envelope) != nil || !hmac.Equal([]byte(envelope.MAC), []byte(o.mac(envelope.Record))) || json.Unmarshal(envelope.Record, &record) != nil || record.Version != SharedRuntimeNodeProtocol || !validObservationHash(record.ID) || record.ID != sharedRuntimeOwnerID(record.Original) || record.Anchor != o.anchor(record) || record.Sequence == 0 {
			return record, ErrNodeObservation
		}
		return record, nil
	}
	for _, entry := range entries {
		pending := strings.HasPrefix(entry.Name(), ".pending-")
		if !pending && !strings.HasSuffix(entry.Name(), ".event") {
			continue
		}
		raw, _, _, e := sharedRuntimeNativeRead(ctx, o.directory, "/"+entry.Name(), 4<<20)
		if e != nil {
			return e
		}
		event, e := decode(raw)
		if e != nil {
			return e
		}
		raw, _, _, e = sharedRuntimeNativeRead(ctx, o.directory, "/"+event.ID+".json", 4<<20)
		if e != nil {
			return observationFailure("shared_original_recovery_pending")
		}
		current, e := decode(raw)
		if e != nil || current.ID != event.ID || current.Sequence < event.Sequence || pending && current.Phase != "completed" {
			return observationFailure("shared_original_recovery_pending")
		}
	}
	return nil
}
func sharedRuntimeOwnerSameOperation(a, b ObservationBinding) bool {
	a.ReservationID = ""
	b.ReservationID = ""
	return reflect.DeepEqual(a, b)
}

func (o *sharedRuntimeNodeOwner) peers(ctx context.Context, r SharedRuntimeNodeRequest) ([]sharedRuntimeOwnerRecord, error) {
	var out []sharedRuntimeOwnerRecord
	// The complete same-node cohort is also fixed in D's original authenticated
	// inventory. Native owner refuses any already-prepared local peer omission.
	listed := map[string]bool{}
	for _, peer := range r.Peers {
		parts := strings.Split(peer.Anchor, ".")
		if len(parts) != 2 {
			return nil, ErrNodeObservation
		}
		raw, e := base64.RawURLEncoding.DecodeString(parts[0])
		if e != nil || !hmac.Equal([]byte(parts[1]), []byte(o.mac(raw))) {
			return nil, ErrNodeObservation
		}
		var a struct {
			ID      string
			Binding ObservationBinding
			Pod     PodIdentity
			Cgroup  sharedCgroupPin
		}
		if json.Unmarshal(raw, &a) != nil || a.Pod.UID != peer.PodUID || !sharedRuntimeOwnerSameOperation(a.Binding, r.Binding) {
			return nil, ErrNodeObservation
		}
		file, _, _, e := sharedRuntimeNativeRead(ctx, o.directory, "/"+a.ID+".json", 4<<20)
		if e != nil {
			return nil, e
		}
		var envelope sharedRuntimeOwnerEnvelope
		var rec sharedRuntimeOwnerRecord
		if json.Unmarshal(file, &envelope) != nil || !hmac.Equal([]byte(envelope.MAC), []byte(o.mac(envelope.Record))) || json.Unmarshal(envelope.Record, &rec) != nil || rec.ID != a.ID || rec.Anchor != peer.Anchor || rec.Anchor != o.anchor(rec) || rec.Original.Original.OriginalSHA256 != peer.OriginalSHA256 || !reflect.DeepEqual(rec.Original.SourcePaths, r.SourcePaths) {
			return nil, ErrNodeObservation
		}
		listed[rec.ID] = true
		out = append(out, rec)
	}
	files, e := os.ReadDir(o.directory)
	if e != nil {
		return nil, e
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		raw, _, _, e := sharedRuntimeNativeRead(ctx, o.directory, "/"+f.Name(), 4<<20)
		if e != nil {
			return nil, e
		}
		var envelope sharedRuntimeOwnerEnvelope
		var rec sharedRuntimeOwnerRecord
		if json.Unmarshal(raw, &envelope) != nil || !hmac.Equal([]byte(envelope.MAC), []byte(o.mac(envelope.Record))) || json.Unmarshal(envelope.Record, &rec) != nil {
			return nil, ErrNodeObservation
		}
		if sharedRuntimeOwnerSameOperation(rec.Original.Binding, r.Binding) && rec.Phase != "completed" && !listed[rec.ID] {
			return nil, ErrNodeObservation
		}
	}
	return out, nil
}

func (o *sharedRuntimeNodeOwner) run(ctx context.Context, r SharedRuntimeNodeRequest) (SharedRuntimeNodeResponse, error) {
	var response SharedRuntimeNodeResponse
	started := time.Now().UTC()
	if o == nil || o.guard == nil || ctx == nil || ctx.Err() != nil || ValidateSharedRuntimeNodeRequest(r, started) != nil || r.Binding.Node != o.observer.Node || r.Binding.NodeUID != o.observer.NodeUID || o.observer.hostIdentity(ctx) != nil || !o.mu.TryLock() {
		return response, ErrNodeObservation
	}
	defer o.mu.Unlock()
	if o.guard == nil {
		return response, ErrNodeObservation
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(r.Deadline) {
		return response, ErrNodeObservation
	}
	for _, p := range r.SourcePaths {
		if observationRangesOverlap(p, o.directory) {
			return response, ErrNodeObservation
		}
	}
	var rec sharedRuntimeOwnerRecord
	if r.Action == "prepare" {
		if e := o.prepareWriteBoundary(ctx); e != nil {
			return response, e
		}
		if _, e := os.Lstat(filepath.Join(o.directory, sharedRuntimeOwnerID(r)+".json")); e == nil {
			return response, ErrNodeObservation
		} else if !os.IsNotExist(e) {
			return response, ErrNodeObservation
		}
		w, e := o.observer.sharedRuntimeWitness(ctx, r, r.Original, o.releases)
		if e != nil {
			return response, e
		}
		h, e := openSharedCgroup(ctx, o.cgroupMount, o.observer.HostProc, w.Container, nil)
		if e != nil {
			return response, e
		}
		pin := h.pin
		h.close()
		entries, e := os.ReadDir(o.directory)
		if e != nil {
			return response, e
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			raw, _, _, e := sharedRuntimeNativeRead(ctx, o.directory, "/"+entry.Name(), 4<<20)
			if e != nil {
				return response, e
			}
			var envelope sharedRuntimeOwnerEnvelope
			var pending sharedRuntimeOwnerRecord
			if json.Unmarshal(raw, &envelope) != nil || !hmac.Equal([]byte(envelope.MAC), []byte(o.mac(envelope.Record))) || json.Unmarshal(envelope.Record, &pending) != nil {
				return response, ErrNodeObservation
			}
			if pending.Phase != "completed" && pending.Cgroup.Device == pin.Device && pending.Cgroup.Inode == pin.Inode {
				return response, observationFailure("shared_original_recovery_pending")
			}
		}
		files, e := o.observer.files(ctx, w.Paths)
		if e != nil {
			return response, e
		}
		rec = sharedRuntimeOwnerRecord{Version: SharedRuntimeNodeProtocol, ID: sharedRuntimeOwnerID(r), Phase: "prepared", Original: sharedRuntimeOwnerOriginal(r), Witness: w, Cgroup: pin, Tasks: len(w.Gateways) + 1, Files: len(files)}
		rec.Anchor = o.anchor(rec)
		if e = o.save(&rec); e != nil {
			return response, e
		}
	} else {
		var e error
		rec, e = o.load(r)
		if e != nil {
			return response, e
		}
		if r.Action != "state" {
			if _, e = o.peers(ctx, r); e != nil {
				return response, e
			}
		}
		switch r.Action {
		case "freeze":
			if rec.Phase != "prepared" {
				return response, ErrNodeObservation
			}
			w, e := o.observer.sharedRuntimeWitness(ctx, r, r.Original, o.releases)
			if e != nil || !reflect.DeepEqual(w, rec.Witness) {
				return response, ErrNodeObservation
			}
			h, e := openSharedCgroup(ctx, o.cgroupMount, o.observer.HostProc, rec.Cgroup.Root, &rec.Cgroup)
			if e != nil {
				return response, e
			}
			defer h.close()
			rec.CohortSHA256 = SharedRuntimeNodeCohortSHA(r)
			rec.Phase = "freezing"
			if e = o.save(&rec); e != nil {
				return response, e
			}
			if e = h.freeze(ctx); e != nil {
				return response, e
			}
			rec.Phase = "frozen"
			if e = o.save(&rec); e != nil {
				return response, e
			}
		case "check-frozen":
			if rec.Phase != "frozen" && rec.Phase != "freezing" {
				return response, ErrNodeObservation
			}
			peers, e := o.peers(ctx, r)
			if e != nil {
				return response, e
			}
			n, files, e := o.checkFrozenSources(ctx, r, peers)
			if e != nil {
				return response, e
			}
			rec.Tasks = n
			rec.Files = files
			rec.Phase = "frozen"
		case "thaw", "orphan-thawed":
			if rec.Phase == "completed" || rec.Phase == "recovered" {
				return response, ErrNodeObservation
			}
			// A still-live original Agent must still own THIS reservation before
			// releasing a freeze. Never thaw a successor operation in the same CG.
			oldAgent, ae := observationProcess(ctx, filepath.Join(o.observer.HostProc, strconv.Itoa(rec.Witness.Agent.PID)))
			if ae == nil && oldAgent == rec.Witness.Agent {
				if _, e := o.observer.sharedRuntimeWitness(ctx, r, r.Original, o.releases); e != nil {
					return response, e
				}
			}
			h, e := openSharedCgroup(ctx, o.cgroupMount, o.observer.HostProc, rec.Cgroup.Root, &rec.Cgroup)
			if e != nil {
				return response, e
			}
			defer h.close()
			rec.RecoveryBoundarySHA256 = r.RecoveryBoundarySHA256
			rec.Phase = "thawing"
			if e = o.save(&rec); e != nil {
				return response, e
			}
			e = h.thaw(ctx)
			if e != nil {
				frozen, _, se := h.state(ctx)
				if se != nil || frozen {
					return response, ErrNodeObservation
				}
				rec.Phase = "orphan-thawed"
			} else {
				rec.Phase = "thawed"
				w, we := o.observer.sharedRuntimeWitness(ctx, r, r.Original, o.releases)
				if we != nil || !reflect.DeepEqual(w, rec.Witness) {
					rec.Phase = "orphan-thawed"
				}
			}
			if e = o.save(&rec); e != nil {
				return response, e
			}
		case "recovered", "complete":
			alreadyCompleted := r.Action == "complete" && rec.Phase == "completed"
			if r.Current == nil || rec.RecoveryBoundarySHA256 != r.RecoveryBoundarySHA256 || r.Action == "recovered" && rec.Phase != "thawed" || r.Action == "complete" && rec.Phase != "recovered" && !alreadyCompleted {
				return response, ErrNodeObservation
			}
			w, e := o.observer.sharedRuntimeWitness(ctx, r, *r.Current, o.releases)
			if e != nil || w.Container != rec.Witness.Container || w.Agent != rec.Witness.Agent || w.Guard != rec.Witness.Guard || !reflect.DeepEqual(w.Gateways, rec.Witness.Gateways) || !reflect.DeepEqual(w.Paths, rec.Witness.Paths) || !reflect.DeepEqual(w.LoadedEnvironmentSHA256, rec.Witness.LoadedEnvironmentSHA256) {
				return response, ErrNodeObservation
			}
			h, e := openSharedCgroup(ctx, o.cgroupMount, o.observer.HostProc, rec.Cgroup.Root, &rec.Cgroup)
			if e != nil {
				return response, e
			}
			frozen, _, e := h.state(ctx)
			h.close()
			if e != nil || frozen {
				return response, ErrNodeObservation
			}
			// Refresh only an already durable original completion after rereading
			// its real completed Agent journal/process/guard/mounts and kernel
			// state. This cannot re-close, thaw, renew or replace an operation.
			if alreadyCompleted {
				if w.JournalSHA256 != rec.Witness.JournalSHA256 {
					return response, ErrNodeObservation
				}
				break
			}
			rec.Witness.JournalSHA256 = w.JournalSHA256
			rec.Phase = "recovered"
			if r.Action == "complete" {
				rec.Phase = "completed"
			}
			if e = o.save(&rec); e != nil {
				return response, e
			}
		case "state":
			h, e := openSharedCgroup(ctx, o.cgroupMount, o.observer.HostProc, rec.Cgroup.Root, &rec.Cgroup)
			if e != nil {
				rec.Phase = "uncertain"
			} else {
				frozen, _, e := h.state(ctx)
				h.close()
				if e != nil {
					rec.Phase = "uncertain"
				} else if frozen {
					rec.Phase = "frozen"
				} else if rec.Phase == "freezing" || rec.Phase == "thawing" {
					rec.Phase = "uncertain"
				}
			}
		default:
			return response, ErrNodeObservation
		}
	}
	finished := time.Now().UTC()
	if ctx.Err() != nil || !finished.Before(r.Deadline) {
		return response, ErrNodeObservation
	}
	facts := SharedRuntimeNodeFacts(r.Action)
	if rec.Phase == "orphan-thawed" && r.Action != "state" {
		facts = SharedRuntimeNodeFacts("orphan-thawed")
	}
	response = SharedRuntimeNodeResponse{Version: SharedRuntimeNodeProtocol, Action: r.Action, Nonce: r.Nonce, RequestSHA256: observationDigest(r), Binding: r.Binding, Anchor: rec.Anchor, BootID: o.observer.BootID, OriginalSHA256: r.Original.OriginalSHA256, OriginalRawSHA256: sharedRuntimeBytesSHA(r.OriginalRaw), CurrentRawSHA256: sharedRuntimeBytesSHA(r.CurrentRaw), CohortSHA256: SharedRuntimeNodeCohortSHA(r), SourcePathsSHA256: SharedRuntimeNodeSourcePathsSHA(r), NativeJournalSHA256: rec.Witness.JournalSHA256, Phase: rec.Phase, StartedAt: started, FinishedAt: finished, ValidUntil: r.Deadline, TasksChecked: rec.Tasks, Files: rec.Files, Facts: facts}
	return response, nil
}
func sharedRuntimeBytesSHA(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}

// Concrete kernel/source work. Every known same-node container must still be
// frozen, with its exact original native Agent reservation. Other live tasks
// are inspected through the existing FD/shared-map source writer reader.
func (o *sharedRuntimeNodeOwner) checkFrozenSources(ctx context.Context, r SharedRuntimeNodeRequest, peers []sharedRuntimeOwnerRecord) (int, int, error) {
	if len(peers) == 0 {
		return 0, 0, ErrNodeObservation
	}
	handles := []*sharedCgroupHandle{}
	defer func() {
		for _, h := range handles {
			h.close()
		}
	}()
	for _, p := range peers {
		if p.Phase != "frozen" && p.Phase != "freezing" || p.CohortSHA256 != SharedRuntimeNodeCohortSHA(r) {
			return 0, 0, ErrNodeObservation
		}
		h, e := openSharedCgroup(ctx, o.cgroupMount, o.observer.HostProc, p.Cgroup.Root, &p.Cgroup)
		if e != nil {
			return 0, 0, e
		}
		handles = append(handles, h)
		if h.checkFrozen(ctx) != nil {
			return 0, 0, ErrNodeObservation
		}
		w, e := o.observer.sharedRuntimeWitness(ctx, p.Original, p.Original.Original, o.releases)
		if e != nil || !reflect.DeepEqual(w, p.Witness) {
			return 0, 0, ErrNodeObservation
		}
	}
	paths, e := o.observer.paths(ctx, r.SourcePaths)
	if e != nil {
		return 0, 0, e
	}
	for _, p := range paths {
		native, e := o.observer.sourceNativePath(p.Path)
		if e != nil {
			return 0, 0, e
		}
		fd, e := unix.Open(native, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			return 0, 0, e
		}
		e = unix.Syncfs(fd)
		unix.Close(fd)
		if e != nil || ctx.Err() != nil {
			return 0, 0, ErrNodeObservation
		}
	}
	files, e := o.observer.files(ctx, paths)
	if e != nil {
		return 0, 0, e
	}
	checked := 0
	for round := 0; round < 2; round++ {
		tasks, e := o.observer.tasks(ctx)
		if e != nil {
			return 0, 0, e
		}
		for _, base := range tasks {
			task, e := observationPinTask(ctx, base, o.observer.HostProc)
			if e != nil {
				return 0, 0, e
			}
			e = func() error {
				defer task.close()
				allowed := false
				for _, p := range peers {
					if withinObservation(task.process.Cgroup, p.Cgroup.Path) {
						allowed = true
						break
					}
				}
				if !allowed {
					if e := observationWritableHandles(ctx, task.base, o.observer.HostProc, files, paths); e != nil {
						return e
					}
				}
				after, e := observationProcess(ctx, task.base)
				if e != nil && task.exited() {
					return nil
				}
				if e != nil || after != task.process {
					return ErrNodeObservation
				}
				checked++
				return nil
			}()
			if e != nil {
				return 0, 0, e
			}
		}
	}
	last, e := o.observer.files(ctx, paths)
	if e != nil || !reflect.DeepEqual(last, files) {
		return 0, 0, ErrNodeObservation
	}
	for _, h := range handles {
		if h.checkFrozen(ctx) != nil {
			return 0, 0, ErrNodeObservation
		}
	}
	return checked, len(files), nil
}
