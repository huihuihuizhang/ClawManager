//go:build linux

package quiesce

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Installation input to the existing Node owner, never HTTP request paths.
// The installer authenticates the actual Longhorn/PVC/PV/CRI chain before
// installing a source. Identity is the frozen provider/volume/source digest.
type LonghornExt4Source struct {
	Binding                                                                 ObservationBinding
	Attempt                                                                 uint64
	Claim                                                                   LonghornExt4Claim
	Identity                                                                string
	VolumeHandle, PVCUID, PVUID                                             string
	ProviderNamespace, ProviderPodName, ProviderPodUID, ProviderContainerID string
	Pin                                                                     LonghornExt4NativePin
	MountFD, BlockFD, HostRootFD                                            int
	MountOwnerPID                                                           int
	MountOwnerStart, MountNamespace                                         string
	OriginalSourceSHA256                                                    string              `json:",omitempty"`
	ProviderNamespaceUID                                                    string              `json:",omitempty"`
	Keeper                                                                  *LonghornExt4Keeper `json:",omitempty"`
}

// These fields are read from the qualified provider namespace, device and
// mounted filesystem. They are comparison data, never capture authority.
type LonghornExt4NativePin = longhornExt4Pin

type longhornExt4Event struct {
	Version, Key                                string
	Source                                      LonghornExt4Source
	Hold                                        longhornExt4Hold
	Sequence                                    uint64
	DrainBoundarySHA256, RecoveryBoundarySHA256 string
	RegistrationBoundarySHA256                  string
}

type longhornExt4Actions struct {
	parent          *SharedRuntimeNodeHandler
	directory       string
	sources         map[string]LonghornExt4Source
	volumes         map[string]longhornExt4Volume
	guards          []*os.File
	recoveryURI     string
	templates       map[string]LonghornExt4Source
	clients         map[string]longhornRWXClient
	clientTemplates map[string]LonghornRWXClientCoordinates
}

func longhornExt4SourceKey(s LonghornExt4Source) string {
	key := []any{LonghornExt4Protocol, s.Binding, s.Attempt, s.Claim, s.Identity, s.VolumeHandle, s.PVCUID, s.PVUID, s.Pin}
	if s.Keeper != nil {
		key = append(key, s.Keeper)
	}
	return observationDigest(key)
}

func longhornExt4StableSource(s LonghornExt4Source) LonghornExt4Source {
	s.MountFD, s.BlockFD, s.HostRootFD = -1, -1, -1
	return s
}

// Configure once before serving. Descriptors are duplicated into the existing
// owner. Shutdown waits for the owner's mutex before closing them.
func (h *SharedRuntimeNodeHandler) ConfigureLonghornExt4(ctx context.Context, recoveryURI string, sources []LonghornExt4Source) error {
	if h == nil || h.owner == nil || h.longhorn != nil || ctx == nil || len(sources) > 8 {
		return ErrNodeObservation
	}
	h.owner.mu.Lock()
	defer h.owner.mu.Unlock()
	o := h.owner.observer
	if o.hostIdentity(ctx) != nil {
		return ErrNodeObservation
	}
	recovery, err := url.Parse(recoveryURI)
	if err != nil || recovery.Scheme != "spiffe" || recovery.Host == "" || recovery.Path == "" ||
		recovery.User != nil || recovery.RawQuery != "" || recovery.Fragment != "" {
		return ErrNodeObservation
	}
	directory := filepath.Join(h.owner.directory, "longhorn-ext4")
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	var st unix.Stat_t
	if unix.Lstat(directory, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0777 != 0700 {
		return ErrNodeObservation
	}
	a := &longhornExt4Actions{parent: h, directory: directory, recoveryURI: recoveryURI, sources: map[string]LonghornExt4Source{}, volumes: map[string]longhornExt4Volume{},
		templates: map[string]LonghornExt4Source{}, clients: map[string]longhornRWXClient{}, clientTemplates: map[string]LonghornRWXClientCoordinates{}}
	ok := false
	defer func() {
		if !ok {
			a.close()
		}
	}()
	for _, s := range sources {
		b := s.Binding
		if b.Node != o.Node || b.NodeUID != o.NodeUID || b.InstallationID == "" ||
			b.Namespace == "" || b.NamespaceUID == "" || b.OperationID != "" || b.Generation != 0 || b.InventorySHA256 != "" ||
			!b.ExpiresAt.IsZero() || s.Attempt != 0 || s.Claim != (LonghornExt4Claim{}) || !validObservationHash(s.Identity) || s.Pin.BootID != o.BootID || s.MountOwnerPID <= 0 ||
			!strings.HasPrefix(s.VolumeHandle, "pvc-") || strings.ContainsAny(s.VolumeHandle, "/\\\x00\r\n") || s.PVCUID == "" || s.PVUID == "" {
			return ErrNodeObservation
		}
		proc := filepath.Join(o.HostProc, fmt.Sprint(s.MountOwnerPID))
		p, err := observationProcess(ctx, proc)
		if err != nil || p.Start != s.MountOwnerStart || p.MountNamespace != s.MountNamespace {
			return ErrNodeObservation
		}
		if err := longhornExt4ProviderCurrent(ctx, o, s); err != nil {
			return err
		}
		alias, err := unix.Openat2(s.HostRootFD, "dev/longhorn/"+s.VolumeHandle, &unix.OpenHow{
			Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return err
		}
		var aliasInfo, blockInfo, actualRoot, suppliedRoot unix.Stat_t
		valid := unix.Fstat(alias, &aliasInfo) == nil && unix.Fstat(s.BlockFD, &blockInfo) == nil &&
			unix.Stat(o.HostRoot, &actualRoot) == nil && unix.Fstat(s.HostRootFD, &suppliedRoot) == nil &&
			aliasInfo.Mode&unix.S_IFMT == unix.S_IFBLK && aliasInfo.Rdev == blockInfo.Rdev &&
			actualRoot.Dev == suppliedRoot.Dev && actualRoot.Ino == suppliedRoot.Ino
		unix.Close(alias)
		if !valid {
			return ErrNodeObservation
		}
		key := longhornExt4SourceKey(s)
		if _, exists := a.sources[key]; exists {
			return ErrNodeObservation
		}
		// Device-wide process guard survives controller reconnects and excludes
		// another task in this Node owner store. It is never removed.
		guardName := filepath.Join(directory, fmt.Sprintf("device-%d-%d.guard", s.Pin.Device, s.Pin.DiskSequence))
		fd, err := unix.Open(guardName, unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err != nil {
			return err
		}
		guard := os.NewFile(uintptr(fd), "longhorn-device-guard")
		a.guards = append(a.guards, guard)
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0777 != 0600 ||
			unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
			return ErrNodeObservation
		}
		v := longhornExt4Volume{freeze: &longhornExt4FreezeCustody{}, pin: s.Pin, mountFD: -1, blockFD: -1, hostRootFD: -1, mountProc: proc}
		a.volumes[key] = v
		for _, pair := range []struct {
			from int
			to   *int
		}{{s.MountFD, &v.mountFD}, {s.BlockFD, &v.blockFD}, {s.HostRootFD, &v.hostRootFD}} {
			dup, err := unix.FcntlInt(uintptr(pair.from), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				a.volumes[key] = v
				return err
			}
			*pair.to = dup
		}
		a.volumes[key] = v
		if _, err := v.observe(ctx); err != nil {
			return err
		}
		var journal unix.Stat_t
		if unix.Stat(directory, &journal) != nil || uint64(journal.Dev) == s.Pin.Device {
			return ErrNodeObservation
		}
		if _, exists := a.templates[s.Identity]; exists {
			return ErrNodeObservation
		}
		a.templates[s.Identity] = longhornExt4StableSource(s)
	}
	h.longhorn = a
	ok = true
	return nil
}

func (a *longhornExt4Actions) close() {
	seen := map[int]bool{}
	for _, v := range a.volumes {
		for _, fd := range []int{v.mountFD, v.blockFD, v.hostRootFD} {
			if fd >= 0 && !seen[fd] {
				_ = unix.Close(fd)
				seen[fd] = true
			}
		}
	}
	for _, client := range a.clients {
		if !seen[client.fd] {
			_ = unix.Close(client.fd)
			seen[client.fd] = true
		}
	}
	for _, g := range a.guards {
		_ = g.Close()
	}
}

func longhornExt4ProviderCurrent(ctx context.Context, o *NodeObserver, s LonghornExt4Source) error {
	p, err := longhornExt4ProviderProcess(ctx, o, s)
	if err != nil || p.PID != s.MountOwnerPID || p.Start != s.MountOwnerStart || p.MountNamespace != s.MountNamespace {
		return ErrNodeObservation
	}
	return nil
}

// Append-only events reuse the original owner's authenticated envelope and
// directory sync. Partial, conflicting or gapped events stop all transitions.
func (a *longhornExt4Actions) load(key string) (longhornExt4Event, bool, error) {
	var out longhornExt4Event
	entries, err := os.ReadDir(a.directory)
	if err != nil || len(entries) > 8192 {
		return out, false, ErrNodeObservation
	}
	names := []string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), key+"-") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for i, name := range names {
		raw, _, _, err := sharedRuntimeNativeRead(context.Background(), a.directory, "/"+name, 1<<20)
		if err != nil {
			return out, false, err
		}
		var envelope sharedRuntimeOwnerEnvelope
		var event longhornExt4Event
		if sharedRuntimeNodeJSON(raw, &envelope) != nil ||
			!hmac.Equal([]byte(envelope.MAC), []byte(a.parent.owner.mac(envelope.Record))) ||
			sharedRuntimeNodeJSON(envelope.Record, &event) != nil || event.Version != LonghornExt4Protocol ||
			event.Key != key || event.Sequence != uint64(i+1) || event.Hold.Pin != event.Source.Pin ||
			!event.Source.Claim.valid() || !event.Hold.ExpiresAt.Equal(longhornExt4ForwardUntil(event.Source.Binding, event.Source.Claim)) ||
			event.Key != longhornExt4SourceKey(event.Source) ||
			(i > 0 && observationDigest(event.Source) != observationDigest(out.Source)) ||
			name != fmt.Sprintf("%s-%020d-%s.event", key, event.Sequence, observationDigest(event)) {
			return out, false, observationFailure("longhorn_ext4_journal_unconfirmed")
		}
		out = event
		fd, err := unix.Open(filepath.Join(a.directory, name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return out, false, err
		}
		syncErr := unix.Fsync(fd)
		unix.Close(fd)
		if syncErr != nil {
			return out, false, syncErr
		}
	}
	if expected, installed := a.sources[key]; installed && len(names) > 0 && observationDigest(expected) != observationDigest(out.Source) {
		return out, false, ErrNodeObservation
	}
	if err := sharedRuntimeOwnerSync(a.directory); err != nil {
		return out, false, err
	}
	return out, len(names) > 0, nil
}

func (a *longhornExt4Actions) checkDeviceObligations(current string, source LonghornExt4Source) error {
	entries, err := os.ReadDir(a.directory)
	if err != nil || len(entries) > 8192 {
		return ErrNodeObservation
	}
	keys := map[string]bool{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".event") {
			continue
		}
		key, _, _ := strings.Cut(entry.Name(), "-")
		if !validObservationHash(key) {
			return ErrNodeObservation
		}
		keys[key] = true
	}
	for key := range keys {
		record, found, err := a.load(key)
		if err != nil || !found {
			return ErrNodeObservation
		}
		sameHandle := record.Source.VolumeHandle != "" && record.Source.VolumeHandle == source.VolumeHandle
		sameDevice := record.Source.Pin.Device == source.Pin.Device && record.Source.Pin.DiskSequence == source.Pin.DiskSequence
		if key != current && (sameHandle || sameDevice) && record.Hold.Phase != "released" {
			return observationFailure("longhorn_ext4_original_recovery_pending")
		}
	}
	return nil
}

func (a *longhornExt4Actions) persist(event *longhornExt4Event) error {
	if event.Sequence >= 4096 {
		return ErrNodeObservation
	}
	event.Sequence++
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	envelope, err := json.Marshal(sharedRuntimeOwnerEnvelope{raw, a.parent.owner.mac(raw)})
	if err != nil {
		return err
	}
	name := filepath.Join(a.directory, fmt.Sprintf("%s-%020d-%s.event", event.Key, event.Sequence, observationDigest(event)))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(envelope)
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || n != len(envelope) {
		return ErrNodeObservation
	}
	return sharedRuntimeOwnerSync(a.directory)
}

func (a *longhornExt4Actions) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != LonghornExt4Route {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	h := a.parent
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 ||
		len(r.TLS.PeerCertificates[0].URIs) != 1 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	var request LonghornExt4Request
	if err != nil || len(raw) > 64<<10 || sharedRuntimeNodeJSON(raw, &request) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	wantURI := h.controllerURI
	if request.Action == "release" {
		wantURI = a.recoveryURI
	}
	peer := r.TLS.PeerCertificates[0].URIs[0].String()
	if peer != wantURI && !(request.Action == "state" && peer == a.recoveryURI) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	now := time.Now().UTC()
	if request.Version != LonghornExt4Protocol || !validObservationHash(request.Nonce) ||
		!now.Before(request.Deadline) || request.Deadline.After(now.Add(15*time.Second)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.owner.mu.Lock()
	defer h.owner.mu.Unlock()
	if !time.Now().Before(request.Deadline) {
		w.WriteHeader(http.StatusRequestTimeout)
		return
	}
	response, err := a.run(request)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (a *longhornExt4Actions) run(r LonghornExt4Request) (LonghornExt4Response, error) {
	var response LonghornExt4Response
	if r.Keeper != nil && (r.Action == "register-client" || r.Action == "sync-client") {
		return response, ErrNodeObservation
	}
	if r.Action == "register-client" {
		return a.registerClient(r)
	}
	if r.Action == "sync-client" {
		return a.syncClient(r)
	}
	recovery := r.Action == "release"
	switch r.Action {
	case "register", "qualify", "acquire", "check-held", "state", "release":
	default:
		return response, ErrNodeObservation
	}
	if recovery {
		if !validObservationHash(r.RecoveryBoundarySHA256) || r.DrainBoundarySHA256 != "" {
			return response, ErrNodeObservation
		}
	} else if r.RecoveryBoundarySHA256 != "" {
		return response, ErrNodeObservation
	}
	if r.Action != "state" && !recovery && !time.Now().Before(longhornExt4ForwardUntil(r.Binding, r.Claim)) {
		return response, ErrNodeObservation
	}
	if r.Action == "acquire" && !validObservationHash(r.DrainBoundarySHA256) {
		return response, ErrNodeObservation
	}
	// Physical calls complete under the owner lock after HTTP disconnect. A
	// blocked kernel call retains the event and blocks every competing action.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	key, err := a.sourceForRequest(ctx, r)
	if err != nil {
		return response, err
	}
	o := a.parent.owner.observer
	s := a.sources[key]
	v, attached := a.volumes[key]
	event, found, err := a.load(key)
	if err != nil {
		return response, err
	}
	if found && event.Hold.Mechanism != longhornFreezeCounterMechanism {
		return response, ErrNodeObservation
	}
	if !attached {
		if s.Keeper == nil || !found || event.Hold.Phase != "released" || (r.Action != "state" && r.Action != "release") {
			return response, ErrNodeObservation
		}
		return longhornExt4JournalResponse(r, event, longhornExt4ReleasedState(event), time.Time{}), nil
	}
	physicalErr := o.hostIdentity(ctx)
	p, processErr := observationProcess(ctx, v.mountProc)
	if physicalErr == nil && (processErr != nil || p.Start != s.MountOwnerStart || p.MountNamespace != s.MountNamespace) {
		physicalErr = ErrNodeObservation
	}
	if physicalErr == nil {
		physicalErr = longhornExt4ProviderCurrent(ctx, o, s)
	}
	if physicalErr != nil && r.Action != "state" {
		if s.Keeper != nil && !found {
			delete(a.sources, key)
			delete(a.volumes, key)
			closeLonghornExt4Volume(v)
		}
		return response, physicalErr
	}
	if !found {
		if r.Action != "register" {
			return response, observationFailure("longhorn_ext4_original_record_required")
		}
		if err := v.qualify(ctx); err != nil {
			if s.Keeper != nil {
				delete(a.sources, key)
				delete(a.volumes, key)
				closeLonghornExt4Volume(v)
			}
			return response, err
		}
		event = longhornExt4Event{Version: LonghornExt4Protocol, Key: key, Source: s,
			RegistrationBoundarySHA256: r.RegistrationBoundarySHA256,
			Hold:                       longhornExt4Hold{Mechanism: longhornFreezeCounterMechanism, Pin: v.pin, Phase: "prepared", ExpiresAt: longhornExt4ForwardUntil(r.Binding, r.Claim)}}
		if err := a.persist(&event); err != nil {
			return response, err
		}
	}
	if r.Action == "register" && event.RegistrationBoundarySHA256 != r.RegistrationBoundarySHA256 {
		return response, ErrNodeObservation
	}
	if event.Hold.Mechanism == longhornFreezeCounterMechanism && v.freeze != nil {
		if event.Hold.Phase == "prepared" && !v.freeze.owned && (!v.freeze.freezeSent || v.freeze.thawSucceeded) {
			*v.freeze = longhornExt4FreezeCustody{key: key}
		}
		if v.freeze.key != key && event.Hold.Phase != "released" && r.Action != "state" {
			return response, observationFailure("longhorn_ext4_freeze_custody_lost")
		}
	}
	save := func(next longhornExt4Hold) error { event.Hold = next; return a.persist(&event) }
	switch r.Action {
	case "register", "qualify":
		if event.Hold.Phase != "prepared" {
			return response, ErrNodeObservation
		}
		if err := v.qualify(ctx); err != nil {
			return response, err
		}
	case "acquire":
		if event.Hold.Phase == "prepared" {
			event.DrainBoundarySHA256 = r.DrainBoundarySHA256
			if _, err := v.freezeAcquire(ctx, event.Hold, save); err != nil {
				return response, err
			}
		} else if event.DrainBoundarySHA256 != r.DrainBoundarySHA256 || event.Hold.Phase != "held" {
			return response, ErrNodeObservation
		}
		if _, err := v.freezeRecheck(ctx, event.Hold); err != nil {
			return response, err
		}
	case "check-held":
		if _, err := v.freezeRecheck(ctx, event.Hold); err != nil {
			return response, err
		}
	case "release":
		event.RecoveryBoundarySHA256 = r.RecoveryBoundarySHA256
		if _, err := v.freezeRelease(ctx, event.Hold, save); err != nil {
			return response, err
		}
	}
	// Always respond from the durable journal, never an in-memory post-ioctl
	// phase whose persistence failed.
	event, found, err = a.load(key)
	if err != nil || !found {
		return response, ErrNodeObservation
	}
	ro, err := v.observe(ctx)
	if physicalErr != nil {
		err = physicalErr
	}
	if err != nil && r.Action != "state" {
		return response, err
	}
	native := "unconfirmed"
	if err == nil && !ro {
		switch event.Hold.Phase {
		case "prepared":
			native = "rw"
		case "held":
			if v.freeze != nil && v.freeze.key == key {
				if _, proofErr := v.freezeRecheck(ctx, event.Hold); proofErr == nil {
					native = "freeze-stable"
				}
			}
		case "released":
			native = longhornExt4ReleasedState(event)
		}
	}
	var heldAt time.Time
	if r.Action == "acquire" || r.Action == "check-held" {
		heldAt, err = v.freezeRecheck(ctx, event.Hold)
		if err != nil {
			return response, err
		}
	}
	if s.Keeper != nil && event.Hold.Phase == "released" && native != "unconfirmed" {
		// The Pod retains the attachment until controller-side source recovery.
		// Drop the Node's own descriptors after durable release. Exact retries
		// continue to read the original event and cannot reopen custody.
		delete(a.volumes, key)
		closeLonghornExt4Volume(v)
	}
	return longhornExt4JournalResponse(r, event, native, heldAt), nil
}

func longhornExt4ReleasedState(event longhornExt4Event) string {
	if event.Hold.StartedAt.IsZero() {
		return "rw"
	}
	return "thaw-acknowledged"
}

func longhornExt4JournalResponse(r LonghornExt4Request, event longhornExt4Event, native string, heldAt time.Time) LonghornExt4Response {
	return LonghornExt4Response{Version: LonghornExt4Protocol, Action: r.Action, Nonce: r.Nonce,
		RequestSHA256: observationDigest(r), SourceIdentity: r.SourceIdentity, Binding: r.Binding, Attempt: r.Attempt, Claim: r.Claim,
		Sequence: event.Sequence, Phase: event.Hold.Phase, NativeState: native,
		ProviderObservedAt: time.Now().UTC(), HeldObservedAt: heldAt, StartedAt: event.Hold.StartedAt,
		ExpiresAt: event.Hold.ExpiresAt, JournalSHA256: observationDigest(event)}
}

func longhornExt4RequestMatches(s LonghornExt4Source, r LonghornExt4Request) bool {
	return s.Claim.valid() && r.Claim.valid() && s.Identity == r.SourceIdentity && s.Attempt == r.Attempt &&
		observationDigest(s.Claim) == observationDigest(r.Claim) && observationDigest(s.Binding) == observationDigest(r.Binding) &&
		observationDigest(s.Keeper) == observationDigest(r.Keeper)
}
