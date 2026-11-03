package systembackupexecution

import (
	"reflect"
	"regexp"

	root "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
)

const bootstrapSourcePartsVersion = "system-backup-original-source-parts.v2"
const bootstrapSourceWritersVersion = "system-backup-original-source-writers.v2"

type bootstrapSourceRegistryPart struct{ Module, Part, Operation string }
type bootstrapSourcePartsRegistry struct {
	SchemaVersion, Installation, Version string
	Parts                                []bootstrapSourceRegistryPart
	Source                               b.SourceInventory
	SQL                                  productionSQLSourceMetadata
	Redis                                []root.RedisSourceMetadataEntry
	Skills                               worker.SkillObjectCaptureSpec
	Deployment, Secrets                  worker.ResourceCaptureSpec
}
type bootstrapSourceNativeWriter struct {
	InstanceID, UserID, Generation, RuntimePodID, PID, Port                  int
	Namespace, Pod, PodUID, Deployment, Gateway, Endpoint, AgentEpoch, State string
	DeploymentUID, ReplicaSetUID, ServiceAccount, ServiceAccountUID, NodeUID string
}
type bootstrapSourceWritersRegistry struct {
	SchemaVersion, Installation, Version, ApplicationScope string
	Participants                                           []string
	API                                                    []observedWriterAPIObject
	Bindings                                               []observedSourceRuntimeBinding
	Pods                                                   []observedSourceRuntimePod
	Native                                                 []bootstrapSourceNativeWriter
}

// Registry codecs are original COMPARISON data only. Native observations below
// are private reader state, never constructor arguments or a readiness DTO.
// No registry hash/existence alone may populate a terminal fresh deadline.
type bootstrapSourceRegistryFacts struct {
	firstSQL, lastSQL   *bootstrapSourceSQLFacts
	firstAPI, lastAPI   *observedWriterAPI
	participants        []string
	native              []bootstrapSourceNativeWriter
	parts               []bootstrapSourceRegistryPart
	redis               []root.RedisSourceMetadataEntry
	skills              worker.SkillObjectCaptureSpec
	deployment, secrets worker.ResourceCaptureSpec
}

func (x *bootstrapSourceRegistryReader) matchSourceRegistries(f *bootstrapSourceRegistryFacts) error {
	if f == nil || !sameBootstrapSourceSQL(f.firstSQL, f.lastSQL) || f.firstAPI == nil || f.lastAPI == nil || !reflect.DeepEqual(f.firstAPI.objects, f.lastAPI.objects) || f.participants == nil || f.native == nil || f.parts == nil || x.access.Check(x.ctx) != nil {
		return install.ErrInstall
	}
	partsRaw, err := x.access.Read(x.ctx, x.association.Source.PartsRegistry)
	if err != nil {
		return install.ErrInstall
	}
	writersRaw, err := x.access.Read(x.ctx, x.association.Source.SourceWritersRegistry)
	if err != nil {
		return install.ErrInstall
	}
	var parts bootstrapSourcePartsRegistry
	var writers bootstrapSourceWritersRegistry
	if strictBootstrapSourceJSON(partsRaw, &parts) != nil || strictBootstrapSourceJSON(writersRaw, &writers) != nil || parts.SchemaVersion != bootstrapSourcePartsVersion || writers.SchemaVersion != bootstrapSourceWritersVersion || parts.Installation != x.association.Target.InstallationID || writers.Installation != parts.Installation || parts.Version != x.association.Parts.Version || writers.Version != x.association.SourceWriters.Version || writers.ApplicationScope != x.association.Source.ApplicationScope {
		return install.ErrInstall
	}
	if len(parts.Parts) == 0 || len(parts.Parts) > 10000 || len(writers.API) > 10000 || len(writers.Bindings) > 10000 || len(writers.Pods) > 10000 || len(writers.Native) > 10000 || len(writers.Participants) > 10000 {
		return install.ErrInstall
	}
	token := regexp.MustCompile(`^[a-z][a-z0-9_-]{0,127}$`)
	previous := ""
	for _, part := range parts.Parts {
		key := part.Module + "/" + part.Part
		if !token.MatchString(part.Module) || !token.MatchString(part.Part) || !token.MatchString(part.Operation) || key <= previous {
			return install.ErrInstall
		}
		previous = key
	}
	// Compare EVERY native row/identity field, not a digest or caller-set bit.
	if !reflect.DeepEqual(parts.Parts, f.parts) || !reflect.DeepEqual(parts.Source, f.lastSQL.inventory) || !reflect.DeepEqual(parts.SQL, f.lastSQL.metadata) || !reflect.DeepEqual(parts.Redis, f.redis) || !reflect.DeepEqual(parts.Skills, f.skills) || !reflect.DeepEqual(parts.Deployment, f.deployment) || !reflect.DeepEqual(parts.Secrets, f.secrets) || !reflect.DeepEqual(writers.Participants, f.participants) || !reflect.DeepEqual(writers.API, f.lastAPI.objects) || !reflect.DeepEqual(writers.Bindings, f.lastSQL.bindings) || !reflect.DeepEqual(writers.Pods, f.lastSQL.pods) || !reflect.DeepEqual(writers.Native, f.native) {
		return install.ErrInstall
	}
	if len(f.native) > 0 && x.association.Source.RuntimeAgent == nil {
		return install.ErrInstall
	}
	return x.access.Check(x.ctx)
}
