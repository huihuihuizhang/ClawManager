package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackupinstallationowner/install"
)

func producerScopeFixture(t *testing.T) (productionCaptureMaterials, productionCaptureMetadata) {
	t.Helper()
	_, source, _, _, operations := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("explicit declaration fixture")
	}
	metadata.Redis.Policy.Purpose = "functional_test"
	mapping := &worker.SourceTLSMapping{Address: "original.invalid:443", ServerName: "original.invalid", CAFile: "/original/ca.pem", CASHA256: strings.Repeat("a", 64)}
	m := productionCaptureMaterials{Operations: operations, Discovery: &productionSourceDiscovery{Redis: metadata.Redis}, SkillBucket: metadata.Skills.Bucket, SkillPrefix: metadata.Skills.Prefix, MaxObjects: metadata.Skills.MaxObjects, MaxObjectBytes: metadata.Skills.MaxObjectBytes, MaxObjectTotalBytes: metadata.Skills.MaxTotalBytes, Objects: worker.FormalSourceMount{Objects: mapping, ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: metadata.Skills.Bucket, Prefix: metadata.Skills.Prefix + "/"}}}, Redis: worker.FormalSourceMount{Redis: mapping, RedisScope: &worker.RedisSourceBoundary{ID: metadata.Redis.Policy.Source.ID, ServerID: metadata.Redis.ServerID, Database: metadata.Redis.Policy.DB}, RedisPrefixes: metadata.Redis.Policy.Prefixes}}
	return m, metadata
}

func TestProductionMaterialOriginalSourceScopeMatchesWorkerWire(t *testing.T) {
	m, metadata := producerScopeFixture(t)
	until := time.Now().Add(time.Minute)
	for _, operation := range []string{"capture-source-redis", "capture-skill-objects"} {
		request := m.Operations[operation].Request
		request.Version, request.Operation, request.Deadline, request.ArtifactName = worker.Version, operation, until, "original-scope-comparison.enc"
		mount := m.Redis
		if operation == "capture-source-redis" {
			request.SourceRedis = &metadata.Redis
		} else {
			mount, request.SkillObjects = m.Objects, &metadata.Skills
		}
		want, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: request}, mount)
		if err != nil {
			t.Fatal("actual worker original scope", err)
		}
		got, err := producerWorkerScope(m, operation)
		if err != nil || got != want {
			t.Fatal("producer/worker wire mismatch", operation, got, want, err)
		}
	}
	before, _ := json.Marshal(m)
	if _, err := producerWorkerScope(m, "capture-skill-objects"); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("producer mutated the original declaration")
	}
}

func TestProductionMaterialScopeRejectsWideningAndUnknownOperations(t *testing.T) {
	for _, name := range []string{"nil-discovery", "unknown-operation", "extra-root", "other-bucket", "parent-prefix", "wildcard-prefix", "mixed-provider", "redis-boundary"} {
		t.Run(name, func(t *testing.T) {
			m, _ := producerScopeFixture(t)
			operation := "capture-skill-objects"
			switch name {
			case "nil-discovery":
				m.Discovery = nil
			case "unknown-operation":
				operation = "capture-team-objects"
			case "extra-root":
				m.Objects.ObjectPrefixes = append(m.Objects.ObjectPrefixes, worker.ObjectSourcePrefix{Bucket: "other", Prefix: "packages/"})
			case "other-bucket":
				m.Objects.ObjectPrefixes[0].Bucket = "other"
			case "parent-prefix":
				m.SkillPrefix = "../packages"
				m.Objects.ObjectPrefixes[0].Prefix = m.SkillPrefix + "/"
			case "wildcard-prefix":
				m.SkillPrefix = "packages/*"
				m.Objects.ObjectPrefixes[0].Prefix = m.SkillPrefix + "/"
			case "mixed-provider":
				m.Objects.Redis = m.Redis.Redis
			case "redis-boundary":
				operation = "capture-source-redis"
				m.Redis.RedisScope.Database++
			}
			if _, err := producerWorkerScope(m, operation); err == nil {
				t.Fatal("accepted wider or different original provider root")
			}
		})
	}
}

func TestProductionMaterialWriteRequiresPrivateDistinctExactFiles(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux private-file mode contract")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, name := range []string{"redis.grant", "objects.grant", "metadata.grant", "materials.json"} {
		files[filepath.Join(dir, name)] = []byte(name)
	}
	if producerOutputPaths(dir, files) != nil {
		t.Fatal("private original output directory")
	}
	for file, raw := range files {
		if writeOriginalMaterialFile(file, raw) != nil || writeOriginalMaterialFile(file, raw) != nil || writeOriginalMaterialFile(file, []byte("different")) == nil {
			t.Fatal("exact retry or no-overwrite failed")
		}
		actual, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(actual, raw) {
			t.Fatal("changed original bytes", err)
		}
	}
	delete(files, filepath.Join(dir, "redis.grant"))
	if producerOutputPaths(dir, files) == nil {
		t.Fatal("accepted aliased/missing output")
	}
}

func TestProductionMaterialProducerRejectsMissingAuthenticatedOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := ProduceOriginalCaptureMaterials(ctx, nil, nil, install.EnrollmentPin{}, "", "", ""); err == nil {
		t.Fatal("accepted missing authenticated installation-owner source")
	}
}
