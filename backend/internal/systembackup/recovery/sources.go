package recovery

import (
	"context"
	"sort"
	"strings"
)

// RedisItem is private encrypted payload, never a public manifest/log field.
// Adapter Sample must atomically obtain DUMP/type/PTTL/server time, including
// stream/group recovery information. Separate GETs cannot implement Sample.
type RedisItem struct {
	Key          []byte `json:"key"`
	Type         string `json:"type"`
	Dump         []byte `json:"dump"`
	SHA256       string `json:"sha256"`
	CapturedAt   int64  `json:"captured_at_ms"`
	PTTL         int64  `json:"pttl_ms"`
	ExpiresAt    int64  `json:"expires_at_ms"`
	StreamGroups []byte `json:"stream_groups,omitempty"`
}
type RedisPolicy struct {
	Source                                    Reference
	Topology, CaptureMode, TTLPolicy, Purpose string
	DB                                        int
	Prefixes                                  []string
	MaxItems, MaxBytes, MaxClockSkew          int64
}

func (p RedisPolicy) Validate() error {
	if !p.Source.valid() || p.DB < 0 || p.DB > 65535 || len(p.Prefixes) == 0 || p.MaxItems < 1 || p.MaxItems > 100000 || p.MaxBytes < 1 || p.MaxBytes > 1<<30 || p.MaxClockSkew < 0 {
		return ErrContract
	}
	if p.Topology != "dedicated_instance" && p.Topology != "shared_keyspace" {
		return ErrContract
	}
	if p.CaptureMode != "scan_dump" && (p.Topology != "dedicated_instance" || p.CaptureMode != "rdb" && p.CaptureMode != "aof") {
		return ErrContract
	}
	if p.Purpose != "acceptance" && p.Purpose != "functional_test" || p.TTLPolicy != "preserve_absolute" && (p.TTLPolicy != "restart_remaining" || p.Purpose != "functional_test") {
		return ErrContract
	}
	seen := map[string]bool{}
	for _, prefix := range p.Prefixes {
		if prefix == "" || seen[prefix] || strings.ContainsAny(prefix, "*?[]\\\x00\r\n") {
			return ErrContract
		}
		seen[prefix] = true
	}
	return nil
}
func (p RedisPolicy) ValidateItem(v RedisItem, controllerTime int64) error {
	if p.Validate() != nil || p.CaptureMode != "scan_dump" || v.CapturedAt <= 0 || controllerTime <= 0 || v.CapturedAt-controllerTime > p.MaxClockSkew || controllerTime-v.CapturedAt > p.MaxClockSkew || len(v.Key) == 0 || len(v.Key) > 4096 || len(v.Dump) == 0 || int64(len(v.Dump)) > p.MaxBytes || Hash(v.Dump) != v.SHA256 {
		return ErrContract
	}
	match := false
	for _, prefix := range p.Prefixes {
		if strings.HasPrefix(string(v.Key), prefix) {
			match = true
		}
	}
	if !match {
		return ErrContract
	}
	switch v.Type {
	case "string", "list", "set", "zset", "hash":
		if len(v.StreamGroups) > 0 {
			return ErrContract
		}
	case "stream":
		if len(v.StreamGroups) == 0 {
			return ErrContract
		}
	default:
		return ErrContract
	}
	if v.PTTL == -1 {
		if v.ExpiresAt != 0 {
			return ErrContract
		}
	} else if v.PTTL < 0 || v.PTTL > 9007199254740991-v.CapturedAt || v.ExpiresAt != v.CapturedAt+v.PTTL {
		return ErrContract
	}
	return nil
}

// RemainingTTL never silently clamps clock drift. Expired keys are explicit
// skips; persistent keys use -1. Restoration must use a dedicated isolated DB.
func (p RedisPolicy) RemainingTTL(v RedisItem, targetTime, controllerTime int64) (int64, bool, error) {
	if p.Validate() != nil || targetTime <= 0 || controllerTime <= 0 || targetTime-controllerTime > p.MaxClockSkew || controllerTime-targetTime > p.MaxClockSkew {
		return 0, false, ErrUnavailable
	}
	if p.ValidateItem(v, v.CapturedAt) != nil {
		return 0, false, ErrContract
	}
	if v.PTTL == -1 {
		return -1, false, nil
	}
	if p.TTLPolicy == "restart_remaining" {
		return v.PTTL, v.PTTL == 0, nil
	}
	if v.ExpiresAt <= targetTime {
		return 0, true, nil
	}
	return v.ExpiresAt - targetTime, false, nil
}

type RedisReader interface {
	// Plain SCAN is bounded consistency only, never a strong snapshot claim.
	ScanDump(context.Context, RedisPolicy, string) ([]RedisItem, string, error)
	ServerTime(context.Context) (int64, error)
}
type RedisRestore interface {
	CheckIsolated(context.Context, RestoreTarget, Reference) error
	ServerTime(context.Context) (int64, error)
	Restore(context.Context, RedisItem, int64) error
}
type RedisSnapshotProvider interface {
	// Only a dedicated source may implement RDB/AOF checkpoint capture.
	CaptureSnapshot(context.Context, CaptureRequest, RedisPolicy) (PartResult, error)
}
type SourceObject struct {
	Key, VersionID, SHA256, ETag string
	Size, ModifiedAt             int64
	Metadata                     map[string]string
}
type ObjectSnapshot interface {
	// Return a fixed, bounded, sorted key/version/size inventory with proof that
	// every writer was paused. Missing immutable versions cannot report strong.
	Freeze(context.Context, CaptureRequest) (Reference, []SourceObject, error)
	Collector
}
type SharedWorkspace interface {
	Collector
	// Result maps a source Team ID to a provisioned isolated volume, with
	// independently verified content/UID/GID and mount identity evidence.
	RestoreShared(context.Context, RestoreTarget, string) (Reference, error)
}

// Registry separates six data verifiers from six physical collectors. There is
// one owner per part; a missing module is a readiness failure, not an empty part.
type Registry struct {
	Collectors map[string]Collector
	Verifiers  map[string]Verifier
}

func (r Registry) Validate() error {
	if len(r.Collectors) != 6 || len(r.Verifiers) != 7 {
		return ErrUnavailable
	}
	for _, p := range RequiredParts() {
		if r.Collectors[p] == nil {
			return ErrUnavailable
		}
	}
	for _, d := range append(SixDomains(), "control_plane") {
		if r.Verifiers[d] == nil {
			return ErrUnavailable
		}
	}
	return nil
}

type CaptureBatch struct {
	Parts       map[string]PartSummary
	Objects     []Object
	Warnings    []Warning
	Consistency string
}

func (r Registry) Capture(ctx context.Context, request CaptureRequest) (*CaptureBatch, error) {
	if r.Validate() != nil || request.Validate() != nil {
		return nil, ErrUnavailable
	}
	out := &CaptureBatch{Parts: map[string]PartSummary{}, Warnings: []Warning{}, Consistency: "strong"}
	seen := map[string]bool{}
	for _, name := range RequiredParts() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		result, e := r.Collectors[name].Capture(ctx, request)
		if e != nil {
			return nil, e
		}
		if result.Schema != Version || result.Part != name || result.Status != "completed" || !result.Checkpoint.valid() || len(result.Objects) == 0 || result.Consistency != "strong" && result.Consistency != "bounded" {
			return nil, ErrContract
		}
		keys := []string{}
		for _, o := range result.Objects {
			if !o.valid() || seen[o.Key] {
				return nil, ErrContract
			}
			seen[o.Key] = true
			keys = append(keys, o.Key)
		}
		out.Parts[name] = PartSummary{result.Status, keys, result.Checkpoint, result.Consistency}
		sort.Strings(keys)
		out.Objects = append(out.Objects, result.Objects...)
		out.Warnings = append(out.Warnings, result.Warnings...)
		if result.Consistency == "bounded" {
			out.Consistency = "bounded"
		}
	}
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].Key < out.Objects[j].Key })
	return out, nil
}
func (r Registry) Verify(ctx context.Context, target ReadOnlyTarget, mode string) (map[string]Summary, error) {
	if r.Validate() != nil || !validID(target.ID) || !target.ReadCredential.valid() || !target.Isolation.valid() {
		return nil, ErrUnavailable
	}
	switch mode {
	case "backup_validate", "restore_validate", "preflight_diff":
	default:
		return nil, ErrContract
	}
	out := map[string]Summary{}
	for _, name := range append(SixDomains(), "control_plane") {
		s, e := r.Verifiers[name].Verify(ctx, target, mode)
		if e != nil {
			return nil, e
		}
		if s.Status != "passed" || s.Count < 0 || !s.Evidence.valid() {
			return nil, ErrContract
		}
		out[name] = s
	}
	return out, nil
}
