package systembackupexecution

import (
	"reflect"
	"sort"
	"strconv"
	"time"

	root "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Returns only after TWO complete real observations agree and all signed
// registry entries correspond. Time values remain private in the caller check;
// no observation/freshness DTO can be supplied to this consumer.
func (x *bootstrapSourceRegistryReader) observeRegistries() (time.Time, time.Time, error) {
	f, err := x.collectBootstrapSourceFacts()
	if err != nil || x.matchSourceRegistries(f) != nil {
		return time.Time{}, time.Time{}, install.ErrInstall
	}
	return x.access.Bounds(x.ctx)
}

// Shared real collection only. The Installer producer exports the resulting
// DATA before final config/grant signing; the enrolled consumer independently
// repeats this collection and compares exact signed file pins afterwards.
func (x *bootstrapSourceRegistryReader) collectBootstrapSourceFacts() (*bootstrapSourceRegistryFacts, error) {
	if p, ok := x.access.(*install.BootstrapSourceRegistryAuthoring); ok && p.RecheckAuthority(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	f := &bootstrapSourceRegistryFacts{}
	var err error
	f.firstSQL, err = x.readSourceSQL()
	if err != nil {
		return nil, err
	}
	clients, err := x.openMetadataClients()
	if err != nil {
		return nil, err
	}
	defer clients.Close()
	skills, err := x.readSkillObjectMetadata(x.physical, clients, f.firstSQL.inventory.Skills)
	if err != nil {
		return nil, err
	}
	deployment, secrets, err := x.readResourceMetadata(x.physical, clients)
	if err != nil {
		return nil, err
	}
	redisBinding, err := x.connection("source_redis")
	if err != nil {
		return nil, err
	}
	redis, err := root.ObserveSourceRedisMetadata(x.physical, clients.Redis, x.materials.Discovery.Redis, redisBinding.Account, x.checkPhysical)
	if err != nil {
		return nil, err
	}
	f.firstAPI, err = x.readWriterAPI(x.physical, clients)
	if err != nil {
		return nil, err
	}
	native, err := x.readNativeWriters(f.firstSQL, f.firstAPI, clients)
	if err != nil {
		return nil, err
	}
	participants, err := x.readControlParticipants()
	if err != nil {
		return nil, err
	}
	if x.checkRuntimeWorkspace(x.physical, clients.API, f.firstSQL.inventory.Instances, native) != nil {
		return nil, install.ErrInstall
	}
	firstParts, err := x.deriveParts(f.firstSQL, clients)
	if err != nil {
		return nil, err
	}
	if p, ok := x.access.(*install.BootstrapSourceRegistryAuthoring); ok && p.RecheckAuthority(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	f.lastSQL, err = x.readSourceSQL()
	if err != nil || !sameBootstrapSourceSQL(f.firstSQL, f.lastSQL) {
		return nil, install.ErrInstall
	}
	lastSkills, err := x.readSkillObjectMetadata(x.physical, clients, f.lastSQL.inventory.Skills)
	if err != nil || !reflect.DeepEqual(skills, lastSkills) {
		return nil, install.ErrInstall
	}
	lastDeployment, lastSecrets, err := x.readResourceMetadata(x.physical, clients)
	if err != nil || !reflect.DeepEqual(deployment, lastDeployment) || !reflect.DeepEqual(secrets, lastSecrets) {
		return nil, install.ErrInstall
	}
	lastRedis, err := root.ObserveSourceRedisMetadata(x.physical, clients.Redis, x.materials.Discovery.Redis, redisBinding.Account, x.checkPhysical)
	if err != nil || !reflect.DeepEqual(redis, lastRedis) {
		return nil, install.ErrInstall
	}
	f.lastAPI, err = x.readWriterAPI(x.physical, clients)
	if err != nil || !reflect.DeepEqual(f.firstAPI.objects, f.lastAPI.objects) {
		return nil, install.ErrInstall
	}
	lastNative, err := x.readNativeWriters(f.lastSQL, f.lastAPI, clients)
	if err != nil || !reflect.DeepEqual(native, lastNative) {
		return nil, install.ErrInstall
	}
	lastParticipants, err := x.readControlParticipants()
	if err != nil || !reflect.DeepEqual(participants, lastParticipants) {
		return nil, install.ErrInstall
	}
	lastParts, err := x.deriveParts(f.lastSQL, clients)
	if err != nil || !reflect.DeepEqual(firstParts, lastParts) || x.checkRuntimeWorkspace(x.physical, clients.API, f.lastSQL.inventory.Instances, lastNative) != nil {
		return nil, install.ErrInstall
	}
	wantParticipants := append([]string{}, x.config.RuntimeSources.LeaseParticipants...)
	sort.Strings(wantParticipants)
	if !reflect.DeepEqual(lastParticipants, wantParticipants) {
		return nil, install.ErrInstall
	}
	f.parts, f.native, f.participants, f.redis, f.skills, f.deployment, f.secrets = lastParts, lastNative, lastParticipants, lastRedis, lastSkills, lastDeployment, lastSecrets
	if p, ok := x.access.(*install.BootstrapSourceRegistryAuthoring); ok && p.RecheckAuthority(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	return f, nil
}

func (x *bootstrapSourceRegistryReader) deriveParts(f *bootstrapSourceSQLFacts, clients *productionMetadataClients) ([]bootstrapSourceRegistryPart, error) {
	if f == nil || f.inventory.TeamFacts == nil || f.inventory.Skills == nil {
		return nil, install.ErrInstall
	}
	parts := []bootstrapSourceRegistryPart{{ce.Part, ce.Part, ce.Operation}, {ce.Part, ce.ProofPart, ce.Operation}, {"deployment_and_secrets", "deployment_resources", "capture-deployment-resources"}, {"deployment_and_secrets", "secret_bundle", "capture-secret-bundle"}, {"skill_hub", b.SkillObjectsPart, "capture-skill-objects"}, {b.SourceRedisPart, b.SourceRedisPart, "capture-source-redis"}, {"users_instances", b.UsersInstancesDatabasePart, "capture-database"}}
	if _, ok := x.materials.Operations[cd.Operation]; ok {
		parts = append(parts, bootstrapSourceRegistryPart{cd.Part, cd.Part, cd.Operation})
	}
	for _, instance := range f.inventory.Instances {
		parts = append(parts, bootstrapSourceRegistryPart{"users_instances", "instance_" + strconv.Itoa(instance.ID) + "_workspace", "capture-workspace"})
	}
	var scope *productionPersistentMountScope
	if x.materials.Discovery != nil {
		scope = x.materials.Discovery.PersistentMounts
	}
	additional, err := persistentMountsForInstances(scope, f.inventory.Instances)
	if err != nil {
		return nil, err
	}
	for _, mounts := range additional {
		for _, mount := range mounts {
			parts = append(parts, bootstrapSourceRegistryPart{"users_instances", "instance_" + strconv.Itoa(mount.InstanceID) + "_" + mount.MountID, "capture-workspace"})
		}
	}
	// Match the CURRENT concrete production consumer: SourceFacts identifies
	// actual Team PVC sources; freezeProductionSource:81 selects Objects=[] and
	// teams_module only selects teams_objects for an explicit ObjectRef inventory.
	// Do not infer provider-wide absence or borrow an optional worker template.
	// An explicit teams_objects entry in the signed registry will fail exact match.
	for _, team := range f.inventory.TeamFacts.Teams {
		if team.PVC == "" {
			continue
		}
		if team.Namespace != x.config.Namespace {
			return nil, install.ErrInstall
		}
		claim, err := clients.API.CoreV1().PersistentVolumeClaims(team.Namespace).Get(x.physical, team.PVC, metav1.GetOptions{})
		if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Spec.VolumeName == "" {
			return nil, install.ErrInstall
		}
		pv, err := clients.API.CoreV1().PersistentVolumes().Get(x.physical, claim.Spec.VolumeName, metav1.GetOptions{})
		if err != nil || pv.UID == "" || pv.DeletionTimestamp != nil || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Name != claim.Name || pv.Spec.ClaimRef.Namespace != team.Namespace || x.checkPhysical(x.physical) != nil {
			return nil, install.ErrInstall
		}
		parts = append(parts, bootstrapSourceRegistryPart{"teams", "team_" + strconv.Itoa(team.ID) + "_workspace", "capture-workspace"})
	}
	sort.Slice(parts, func(i, j int) bool {
		a, b := parts[i], parts[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		return a.Part < b.Part
	})
	for n, p := range parts {
		if _, ok := x.materials.Operations[p.Operation]; !ok || n > 0 && parts[n-1].Module == p.Module && parts[n-1].Part == p.Part {
			return nil, install.ErrInstall
		}
	}
	return parts, nil
}
