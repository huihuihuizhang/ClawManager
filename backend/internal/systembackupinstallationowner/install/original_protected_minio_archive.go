package install

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"time"

	backup "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
	archive "clawreef/internal/systembackuphostpatharchive"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalMinIOFullTree struct {
	raw        []byte          // exact native DATA; never JCS-canonicalize this byte stream
	Profile    string          `json:"profile"`
	Phase      string          `json:"phase"`
	PlanSHA256 string          `json:"plan_sha256"`
	Node       json.RawMessage `json:"node"`
	Root       string          `json:"root"`
	Mount      json.RawMessage `json:"mount"`
	Format     json.RawMessage `json:"format"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	Tree       json.RawMessage `json:"complete_reachable_tree"`
	TreeSHA256 string          `json:"tree_sha256"`
	Excluded   []string        `json:"excluded_paths"`
}

type originalHistoryLimitedOutput struct{ bytes.Buffer }

func (b *originalHistoryLimitedOutput) Write(p []byte) (int, error) {
	if len(p) > (32<<20)-b.Len() {
		return 0, ErrInstall
	}
	return b.Buffer.Write(p)
}

func readOriginalMinIOFullTree(ctx context.Context, native archive.NativeStream, phase string) (originalMinIOFullTree, error) {
	var out originalMinIOFullTree
	if phase != "warm" && phase != "cold" || native.MaxFiles <= 0 || native.MaxBytes <= 0 || native.MaxSeconds < 1 || native.MaxSeconds > 600 || originalReaderExecutable(native.PythonFile, native.PythonSHA256) != nil || originalReaderExecutable(native.ScriptFile, native.ScriptSHA256) != nil {
		return out, ErrInstall
	}
	plan, err := ReadPrivateFile(native.PlanFile, 262144)
	if err != nil || hash(plan) != native.PlanSHA256 {
		return out, ErrInstall
	}
	child, cancel := context.WithTimeout(ctx, time.Duration(native.MaxSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(child, native.PythonFile, "-I", "-B", native.ScriptFile, "inventory", "--phase", phase, "--plan-file", native.PlanFile, "--plan-sha256", native.PlanSHA256, "--max-files", strconv.Itoa(native.MaxFiles), "--max-bytes", strconv.FormatInt(native.MaxBytes, 10), "--max-seconds", strconv.Itoa(native.MaxSeconds))
	var output originalHistoryLimitedOutput
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &output, io.Discard
	cmd.WaitDelay = 5 * time.Second
	if cmd.Run() != nil || child.Err() != nil || decodeOriginalMinIOFullInventory(output.Bytes(), &out) != nil || out.Profile != "original-minio-hostpath-native-raw-cut.v1" || out.Phase != phase || out.PlanSHA256 != native.PlanSHA256 || !filepath.IsAbs(out.Root) || filepath.Clean(out.Root) != out.Root || out.Root == "/" || len(out.Tree) == 0 || hash(out.Tree) != out.TreeSHA256 || out.Excluded == nil || len(out.Excluded) != 0 {
		return originalMinIOFullTree{}, ErrInstall
	}
	again, err := ReadPrivateFile(native.PlanFile, 262144)
	if err != nil || !bytes.Equal(plan, again) || originalReaderExecutable(native.PythonFile, native.PythonSHA256) != nil || originalReaderExecutable(native.ScriptFile, native.ScriptSHA256) != nil {
		return originalMinIOFullTree{}, ErrInstall
	}
	out.raw = bytes.Clone(output.Bytes())
	return out, nil
}

func sameOriginalMinIOTree(a, b originalMinIOFullTree) bool {
	return a.Root == b.Root && a.TreeSHA256 == b.TreeSHA256 && bytes.Equal(a.Tree, b.Tree) && bytes.Equal(a.Node, b.Node) && bytes.Equal(a.Mount, b.Mount) && bytes.Equal(a.Format, b.Format) && a.Excluded != nil && b.Excluded != nil && len(a.Excluded) == 0 && len(b.Excluded) == 0
}

// Only actual complete native S3 reads plus the actual original running-Pod
// physical reads can construct this. It is not yet a cold or retained source.
type OriginalProtectedMinIOWarmHistory struct {
	origin       *OriginalProtectedMinIOWarmHistory
	ctx          context.Context
	set          *PreparedOriginalWriterSet
	protected    *backup.OriginalProtectedMinIOHistory
	facts        backup.OriginalProtectedMinIOHistoryFacts
	warm         originalMinIOFullTree
	native       archive.NativeStream
	directory    string
	warmEvidence BootstrapSourceFilePin
	until        time.Time
	used, failed bool
}

func (*OriginalProtectedMinIOWarmHistory) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

// Original admission and full native PREPAREs must already exist. The
// concrete Acquire lifecycle invokes the locked implementation; a pre-admission
// external call cannot qualify history. No MinIOReadKeeper exemption enters.
func (s *PreparedOriginalWriterSet) PrepareOriginalProtectedMinIOWarmHistory(ctx context.Context, gate *backup.MinIOReadServiceGate, native archive.NativeStream, directory string) (*OriginalProtectedMinIOWarmHistory, error) {
	if s == nil || gate == nil {
		return nil, ErrInstall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prepareOriginalProtectedMinIOWarmHistoryLocked(ctx, gate, native, directory)
}

// Only original Acquire calls this after real maintenance/application admission
// closes and complete native PREPAREs, before any ordinary cold stop dispatch.
func (s *PreparedOriginalWriterSet) prepareOriginalProtectedMinIOWarmHistoryLocked(ctx context.Context, gate *backup.MinIOReadServiceGate, native archive.NativeStream, directory string) (*OriginalProtectedMinIOWarmHistory, error) {
	if s.origin != s || !s.used || s.actualHold != nil || s.owner == nil || !consumerSameContext(ctx, s.owner.ctx) || s.owner.check(ctx) != nil || s.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil || s.checkApplicationGate(ctx, "acquiring") != nil || privateDirectory(directory) != nil {
		return nil, ErrInstall
	}
	protected, err := gate.CollectOriginalProtectedHistory(ctx)
	if err != nil {
		return nil, err
	}
	facts, err := protected.OriginalHistoryData(ctx)
	if err != nil || facts.Operation != s.owner.operation || facts.InventorySHA256 != s.inventorySHA || facts.NamespaceUID != s.owner.operator.installer.plan.Target.NamespaceUID {
		return nil, ErrInstall
	}
	var plan struct {
		Root        string `json:"root"`
		PodUID      string `json:"pod_uid"`
		Container   string `json:"container_name"`
		ContainerID string `json:"container_id"`
	}
	raw, err := ReadPrivateFile(native.PlanFile, 262144)
	if err != nil || hash(raw) != native.PlanSHA256 || json.Unmarshal(raw, &plan) != nil || plan.PodUID != facts.PodUID || plan.Container != facts.Container {
		return nil, ErrInstall
	}
	// Require the SAME real original Pod in the ordinary stop roster. A kept
	// server, selected name or arbitrary native path does not satisfy this.
	found := false
	for _, w := range s.deployments {
		for _, pod := range w.pods {
			if pod.UID != facts.PodUID {
				continue
			}
			if found || w.stopDispatched || w.minio != nil || w.redis != nil {
				return nil, ErrInstall
			}
			found = true
			actual, e := s.owner.operator.installer.kube.CoreV1().Pods(w.namespace).Get(ctx, pod.Name, metav1.GetOptions{})
			if e != nil || string(actual.UID) != facts.PodUID || actual.DeletionTimestamp != nil {
				return nil, ErrInstall
			}
			matched := false
			for _, status := range actual.Status.ContainerStatuses {
				if status.Name == facts.Container && status.ImageID == facts.ImageID && status.ContainerID == "containerd://"+plan.ContainerID && status.State.Running != nil {
					matched = true
				}
			}
			if !matched {
				return nil, ErrInstall
			}
			roots, e := s.actualPodPersistentRoots(ctx, actual)
			if e != nil {
				return nil, e
			}
			covered := false
			for _, root := range roots {
				if custodyWithin(root, plan.Root) {
					covered = true
				}
			}
			if !covered {
				return nil, ErrInstall
			}
		}
	}
	if !found || custodyWithin(plan.Root, directory) || protected.RecheckProtectedBeforeCold(ctx) != nil {
		return nil, ErrInstall
	}
	warm, err := readOriginalMinIOFullTree(ctx, native, "warm")
	if err != nil || warm.Root != plan.Root || protected.RecheckProtectedBeforeCold(ctx) != nil {
		return nil, ErrInstall
	}
	// Warm physical bytes are independent comparison data. Normal graceful
	// shutdown may legitimately change internal metadata. Do not bind an archive
	// to a running tree or omit internal files to make cold match warm.
	var fields map[string]json.RawMessage
	if decodeOriginalNativeJSON(raw, &fields, 262144) != nil || fields["original_history_tree_sha256"] != nil {
		return nil, ErrInstall
	}
	for k, v := range map[string]string{"original_history_warm_tree_sha256": warm.TreeSHA256, "original_history_snapshot_sha256": facts.SnapshotSHA256, "original_history_inventory_sha256": s.inventorySHA} {
		fields[k], err = json.Marshal(v)
		if err != nil {
			return nil, ErrInstall
		}
	}
	// This is exact native integer DATA, not a signed JCS record. Marshal keeps
	// the original observed_unix_ns RawMessage unchanged instead of rounding it.
	bound, err := json.Marshal(fields)
	if err != nil || writeNewFiles(directory, map[string][]byte{"original-protected-history.native-plan.json": bound, "original-protected-history.warm-inventory.json": warm.raw}) != nil {
		return nil, ErrInstall
	}
	native.PlanFile = filepath.Join(directory, "original-protected-history.native-plan.json")
	native.PlanSHA256 = hash(bound)
	until := minTime(s.owner.until, facts.Until)
	if deadline, ok := ctx.Deadline(); !ok {
		return nil, ErrInstall
	} else {
		until = minTime(until, deadline)
	}
	if !time.Now().Before(until) {
		return nil, ErrInstall
	}
	r := &OriginalProtectedMinIOWarmHistory{ctx: ctx, set: s, protected: protected, facts: facts, warm: warm, native: native, directory: directory, warmEvidence: BootstrapSourceFilePin{File: filepath.Join(directory, "original-protected-history.warm-inventory.json"), SHA256: hash(warm.raw)}, until: until}
	r.origin = r
	return r, nil
}

type originalProtectedMinIOArchive struct {
	origin                      *originalProtectedMinIOArchive
	warm                        *OriginalProtectedMinIOWarmHistory
	hold                        *OriginalWriterHold
	archive                     *NativeObservedOriginalArchive
	cold                        originalMinIOFullTree
	native                      archive.NativeStream
	coldEvidence, afterEvidence BootstrapSourceFilePin
	until                       time.Time
}

func (h *OriginalWriterHold) createOriginalProtectedMinIOArchive(ctx context.Context, warm *OriginalProtectedMinIOWarmHistory, provider *OriginalAdoptionArchiveProvider, readerFile, readerSHA string) (*originalProtectedMinIOArchive, error) {
	if h == nil || h.set == nil || warm == nil || warm.origin != warm || warm.failed || warm.used || warm.set != h.set || !consumerSameContext(ctx, warm.ctx) || provider == nil || provider.origin != provider || !consumerSameContext(ctx, provider.outer) || provider.reservation.OperationID != h.set.owner.operation || h.recheckBeforeSQL(ctx) != nil || !time.Now().Before(warm.until) {
		return nil, ErrInstall
	}
	warm.used = true
	facts, err := warm.protected.OriginalHistoryData(ctx)
	if err != nil || !reflect.DeepEqual(facts, warm.facts) {
		warm.failed = true
		return nil, ErrInstall
	}
	cold, err := readOriginalMinIOFullTree(ctx, warm.native, "cold")
	if err != nil || !sameOriginalMinIOSource(warm.warm, cold) {
		warm.failed = true
		return nil, ErrInstall
	}
	var node *originalWholeNodeScope
	for _, n := range h.set.nodes {
		if n != nil && n.request.Binding.Node == provider.minio.Grant.Provider.Node {
			if node != nil {
				return nil, ErrInstall
			}
			node = n
		}
	}
	if node == nil || node.prepare == nil || node.current == nil {
		return nil, ErrInstall
	}
	// FIRST complete native cold tree is the physical source cut. Actual B
	// complete hold/stopped proof and the unchanged original root/mount/node/
	// format remain mandatory; no warm/cold internal-file exceptions exist.
	coldNative, err := sealOriginalMinIOColdPlan(warm, cold)
	if err != nil || h.recheckBeforeSQL(ctx) != nil {
		warm.failed = true
		return nil, ErrInstall
	}
	beforeArchive, err := readOriginalMinIOFullTree(ctx, coldNative, "cold")
	if err != nil || !sameOriginalMinIOTree(cold, beforeArchive) {
		warm.failed = true
		return nil, ErrInstall
	}
	observed, err := provider.CreateNativeObservedOriginalArchive(ctx, coldNative, readerFile, readerSHA, h.set.wholePodClient, node.request, node.prepare)
	if err != nil {
		warm.failed = true
		return nil, err
	}
	after, err := readOriginalMinIOFullTree(ctx, coldNative, "cold")
	if err != nil || !sameOriginalMinIOTree(beforeArchive, after) || observed.retained.data.Copy.NativePlanSHA256 != coldNative.PlanSHA256 || observed.retained.data.Readback.NativePlanSHA256 != coldNative.PlanSHA256 || observed.RecheckBeforeOriginalSQL(ctx) != nil {
		warm.failed = true
		return nil, ErrInstall
	}
	if writeNewFiles(warm.directory, map[string][]byte{"original-protected-history.cold-before-inventory.json": beforeArchive.raw, "original-protected-history.cold-after-inventory.json": after.raw}) != nil {
		warm.failed = true
		return nil, ErrInstall
	}
	r := &originalProtectedMinIOArchive{warm: warm, hold: h, archive: observed, cold: after, native: coldNative, coldEvidence: BootstrapSourceFilePin{File: filepath.Join(warm.directory, "original-protected-history.cold-before-inventory.json"), SHA256: hash(beforeArchive.raw)}, afterEvidence: BootstrapSourceFilePin{File: filepath.Join(warm.directory, "original-protected-history.cold-after-inventory.json"), SHA256: hash(after.raw)}, until: minTime(warm.until, provider.until)}
	r.origin = r
	if h.set.minioHistory == nil || h.set.minioHistory.warm != warm {
		return nil, ErrInstall
	}
	h.set.minioHistory.archiveSource = r
	return r, nil
}

// Compare stable source identity across running -> stopped transition, never
// file/dir metadata. Full tree equality applies only within the actual cold cut.
func sameOriginalMinIOSource(a, b originalMinIOFullTree) bool {
	return a.Root == b.Root && bytes.Equal(a.Node, b.Node) && bytes.Equal(a.Mount, b.Mount) && bytes.Equal(a.Format, b.Format) && a.Excluded != nil && b.Excluded != nil && len(a.Excluded) == 0 && len(b.Excluded) == 0
}

func sealOriginalMinIOColdPlan(warm *OriginalProtectedMinIOWarmHistory, cold originalMinIOFullTree) (archive.NativeStream, error) {
	var zero archive.NativeStream
	if warm == nil || warm.origin != warm || cold.Phase != "cold" || cold.PlanSHA256 != warm.native.PlanSHA256 || !sameOriginalMinIOSource(warm.warm, cold) || privateDirectory(warm.directory) != nil {
		return zero, ErrInstall
	}
	raw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: warm.native.PlanFile, SHA256: warm.native.PlanSHA256}, 262144)
	var fields map[string]json.RawMessage
	if e != nil || decodeOriginalNativeJSON(raw, &fields, 262144) != nil || fields["original_history_tree_sha256"] != nil {
		return zero, ErrInstall
	}
	for k, v := range map[string]string{"original_history_tree_sha256": cold.TreeSHA256, "original_history_cut_phase": "cold", "original_history_cold_origin_plan_sha256": warm.native.PlanSHA256, "original_history_first_cold_inventory_sha256": hash(cold.raw)} {
		fields[k], e = json.Marshal(v)
		if e != nil {
			return zero, ErrInstall
		}
	}
	bound, e := json.Marshal(fields)
	if e != nil || writeNewFiles(warm.directory, map[string][]byte{"original-protected-history.cold-native-plan.json": bound, "original-protected-history.first-cold-inventory.json": cold.raw}) != nil {
		return zero, ErrInstall
	}
	native := warm.native
	native.PlanFile = filepath.Join(warm.directory, "original-protected-history.cold-native-plan.json")
	native.PlanSHA256 = hash(bound)
	return native, nil
}

// Dedicated native DATA custody reader; no widening of generic grant/key limits.
func recheckOriginalNativeInventoryFile(pin BootstrapSourceFilePin, exact []byte) error {
	if !bootstrapSourcePinValid(pin) || len(exact) == 0 || len(exact) > 32<<20 || hash(exact) != pin.SHA256 {
		return ErrInstall
	}
	before, e := os.Lstat(pin.File)
	if e != nil || !before.Mode().IsRegular() || before.Size() != int64(len(exact)) || runtime.GOOS == "linux" && before.Mode().Perm()&0077 != 0 {
		return ErrInstall
	}
	f, e := os.Open(pin.File)
	if e != nil {
		return ErrInstall
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return ErrInstall
	}
	raw, e := io.ReadAll(io.LimitReader(f, 32<<20+1))
	after, se := f.Stat()
	if e != nil || se != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || !bytes.Equal(raw, exact) {
		return ErrInstall
	}
	return nil
}

type originalMinIOExactInventoryCommitment struct {
	Profile, Phase, PlanSHA256, Root, TreeSHA256, ExactNativeSHA256 string
	Evidence                                                        BootstrapSourceFilePin
}

func originalMinIOInventoryCommitment(tree originalMinIOFullTree, pin BootstrapSourceFilePin) originalMinIOExactInventoryCommitment {
	return originalMinIOExactInventoryCommitment{tree.Profile, tree.Phase, tree.PlanSHA256, tree.Root, tree.TreeSHA256, hash(tree.raw), pin}
}
