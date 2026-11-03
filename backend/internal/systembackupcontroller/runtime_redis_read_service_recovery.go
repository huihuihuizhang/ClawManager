package systembackupcontroller

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	sb "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

const RedisReadServiceRecoveryScope = "original_redis_active_acl_and_kept_native_source_bindings"

// The full original source inventory is never replaced with a platform subset.
// This stable binding deliberately excludes mutable task phase/row version and
// later capture metadata, which is produced only AFTER writer Observe.
func RedisReadServiceInventorySHA(a d.Authority, source b.SourceInventory, writer string) string {
	raw, _ := json.Marshal(struct {
		Version, Task, Config, Writer, Database, Server string
		Attempt                                         uint64
		Users                                           []int
		Instances                                       []b.InstanceIdentity
	}{"formal-native-redis-source-binding.v1", a.TaskPublicID, a.ConfigSHA256, writer, source.Database, source.ServerUUID, a.AttemptNo, source.Users, source.Instances})
	return recordHash(raw)
}

type RedisReadServiceRecoveryFacts struct {
	Version, Kind, TaskPublicID, ConfigSHA256, InventorySHA256, PolicySHA256, OriginalACLSHA256 string
	AttemptNo                                                                                   uint64
	Native                                                                                      sb.RedisReadServiceObservationData
	Recovered                                                                                   []json.RawMessage
}

// Only an actual sb-minted opaque observation enters the new proof branch.
// Supplying the public Native DATA cannot construct a prepared checkpoint.
func NewRedisReadServiceRecoveryObservation(ctx context.Context, a d.Authority, writer b.FrozenWriter, facts RedisReadServiceRecoveryFacts, native *sb.VerifiedRedisReadServiceObservation) (SourceRecoveryObservation, error) {
	var zero SourceRecoveryObservation
	if native == nil || !sourceRecoveryEqual(native.Data(), facts.Native) || native.Recheck(ctx, facts.Native.Operation, facts.InventorySHA256, "recovered", time.Now()) != nil || facts.TaskPublicID != a.TaskPublicID || facts.AttemptNo != a.AttemptNo || facts.ConfigSHA256 != a.ConfigSHA256 {
		return zero, ErrSourceRecoveryProofRequired
	}
	raw, e := json.Marshal(facts)
	if e != nil {
		return zero, e
	}
	return SourceRecoveryObservation{WriterID: writer.ID, OriginalSHA256: sourceRecoveryOriginalSHA(writer), Scope: RedisReadServiceRecoveryScope, Facts: raw, redisNative: native}, nil
}

func redisReadServiceFacts(ob SourceRecoveryObservation) (RedisReadServiceRecoveryFacts, error) {
	var facts RedisReadServiceRecoveryFacts
	if ob.Scope != RedisReadServiceRecoveryScope || json.Unmarshal(ob.Facts, &facts) != nil || facts.Version != "source-recovery-redis-native-acl.v1" || facts.Kind != "redis_read_service" || len(ob.References) != 0 || len(facts.Recovered) != 1 || !executionHash.MatchString(facts.OriginalACLSHA256) || !executionHash.MatchString(facts.InventorySHA256) || !executionHash.MatchString(facts.PolicySHA256) || facts.Native.Version != "redis-native-read-service-observation.v1" || facts.Native.Phase != "recovered" || facts.Native.ACLStateSHA256 != facts.OriginalACLSHA256 || facts.Native.InventorySHA256 != facts.InventorySHA256 || facts.Native.PodUID == "" || len(facts.Native.ServerRunID) != 40 || len(facts.Native.Operation) != 32 || facts.Native.StartedAt.IsZero() || !facts.Native.ValidUntil.After(facts.Native.StartedAt) || facts.Native.ValidUntil.Sub(facts.Native.StartedAt) > 10*time.Second {
		return facts, ErrSourceRecoveryProofRequired
	}
	return facts, nil
}

func (p *PreparedSourceRecovery) validateRedisReadServiceLeaf(writer b.FrozenWriter, leaf sourceRecoveryLeaf, source b.SourceInventory) error {
	facts, e := redisReadServiceFacts(leaf.SourceRecoveryObservation)
	if e != nil || facts.TaskPublicID != p.a.TaskPublicID || facts.AttemptNo != p.a.AttemptNo || facts.ConfigSHA256 != p.a.ConfigSHA256 || facts.InventorySHA256 != RedisReadServiceInventorySHA(p.a, source, writer.ID) || facts.Native.Operation != facts.InventorySHA256[:32] || facts.Native.StartedAt.Before(p.root.SourceResumedAt) || p.root.ObservedAt.Before(facts.Native.StartedAt) || !p.root.ObservedAt.Before(facts.Native.ValidUntil) || !writer.Original.Running {
		return ErrSourceRecoveryProofRequired
	}
	var cp struct {
		Version, Namespace, Name, FenceID, SpecSHA256 string
		Replicas                                      int32
		Pods                                          []quiesce.PodIdentity
	}
	var metadata struct {
		Redis          sb.RedisCapturePolicy
		PlatformMounts []struct {
			WriterID, Namespace, DeploymentUID, OriginalSpecSHA256 string
			Claim                                                  *struct{ Name, UID, PVName, PVUID, SHA256 string }
			Source                                                 struct{ Name string }
		}
	}
	if json.Unmarshal([]byte(writer.Original.Checkpoint), &cp) != nil || cp.Version != "deployment-quiesce.v1" || cp.Replicas != 1 || len(cp.Pods) != 1 || writer.ID != "deployment/"+cp.Namespace+"/"+cp.Name || cp.FenceID != p.a.TaskPublicID+"/attempt/"+strconv.FormatUint(p.a.AttemptNo, 10)+"/redis/"+facts.OriginalACLSHA256 || json.Unmarshal(source.CaptureMetadata, &metadata) != nil || metadata.Redis.Validate() != nil || facts.Native.ServerRunID != metadata.Redis.ServerID {
		return ErrSourceRecoveryProofRequired
	}
	policy, _ := json.Marshal(metadata.Redis)
	if recordHash(policy) != facts.PolicySHA256 {
		return ErrSourceRecoveryProofRequired
	}
	var pod sourceRecoverySemanticPod
	if json.Unmarshal(facts.Recovered[0], &pod) != nil || pod.Namespace != cp.Namespace || pod.Name != cp.Pods[0].Name || pod.UID != cp.Pods[0].UID || pod.UID != facts.Native.PodUID || pod.Node != cp.Pods[0].Node || pod.NodeUID == "" || pod.ResourceVersion == "" || !executionHash.MatchString(pod.SpecSHA256) || !reflect.DeepEqual(pod.Containers, cp.Pods[0].Containers) {
		return ErrSourceRecoveryProofRequired
	}
	// All pre-capture platform PVCs remain pinned. This asserts storage identity
	// and preserved processes; it deliberately makes no raw live-AOF freeze claim.
	seen := map[string]bool{}
	for _, pin := range metadata.PlatformMounts {
		if pin.WriterID != writer.ID {
			continue
		}
		if pin.Namespace != cp.Namespace || pin.DeploymentUID != writer.Original.UID || pin.OriginalSpecSHA256 != cp.SpecSHA256 || pin.Claim == nil || seen[pin.Source.Name] {
			return ErrSourceRecoveryProofRequired
		}
		seen[pin.Source.Name] = true
		found := false
		for _, v := range pod.Volumes {
			if v.Name == pin.Source.Name && v.Kind == "PersistentVolumeClaim" && v.Claim == pin.Claim.Name && v.ClaimUID == pin.Claim.UID && v.PV == pin.Claim.PVName && v.PVUID == pin.Claim.PVUID && v.PVSpecSHA256 == pin.Claim.SHA256 {
				found = true
			}
		}
		if !found {
			return ErrSourceRecoveryProofRequired
		}
	}
	if len(seen) == 0 {
		return ErrSourceRecoveryProofRequired
	}
	return nil
}

// StageTx invokes this only for a NEW root, inside the existing final SQL
// transaction. It performs local opaque checks only. Exact already-registered
// durable replay follows the existing SQL evidence-family checks instead.
func (p *PreparedSourceRecovery) checkRedisReadServiceNative(ctx context.Context) error {
	for _, entry := range p.entries[1:] {
		var leaf sourceRecoveryLeaf
		if json.Unmarshal(entry.Payload, &leaf) != nil {
			return ErrSourceRecoveryProofRequired
		}
		if leaf.SourceRecoveryObservation.Scope != RedisReadServiceRecoveryScope {
			continue
		}
		facts, e := redisReadServiceFacts(leaf.SourceRecoveryObservation)
		proof := p.redisNative[leaf.WriterID]
		if e != nil || proof == nil || !sourceRecoveryEqual(proof.Data(), facts.Native) || proof.Recheck(ctx, facts.Native.Operation, facts.InventorySHA256, "recovered", time.Now()) != nil {
			return ErrSourceRecoveryProofRequired
		}
	}
	return nil
}
