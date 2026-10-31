package systembackupexecution

import (
	"context"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

func TestModuleFactoryPreflightDiscoverUsesOnlySourceInventoryMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	_, _, source, _, a, _, _, _, _ := newConsumerMySQLFixture(t)
	for _, q := range []string{"CREATE TABLE users(id INT PRIMARY KEY)", "INSERT INTO users VALUES(1)", "CREATE TABLE instances(id INT PRIMARY KEY,user_id INT,instance_mode VARCHAR(32),type VARCHAR(32),runtime_type VARCHAR(32),runtime_variant VARCHAR(32),os_type VARCHAR(32),status VARCHAR(32),runtime_generation BIGINT,pod_name VARCHAR(128),pod_namespace VARCHAR(128),workspace_path VARCHAR(256))"} {
		if _, err := source.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var database, server string
	if source.QueryRow("SELECT DATABASE(),@@server_uuid").Scan(&database, &server) != nil {
		t.Fatal("local source pin unavailable")
	}
	factories, writers, providers, oldParts := 0, 0, 0, 0
	cfg := PublicCaptureConfig{Source: b.LinuxProfileConfig{Source: source, Database: database, ServerUUID: server, Supported: map[b.AgentKind]bool{{Type: "openclaw", Mode: "pro", Variant: "linux", OS: "linux"}: true}, HoldLimit: time.Second, BuildWriters: func(context.Context, d.Input, b.SourceInventory, []b.FrozenWriter) ([]flow.Writer, error) {
		writers++
		return nil, d.ErrNotReady
	}, BuildParts: func(d.Input, b.SourceInventory, time.Time) ([]b.JobPart, error) {
		oldParts++
		return nil, d.ErrNotReady
	}}, ModuleFactory: func(d.Input, b.SourceInventory, time.Time, []b.FrozenWriter) (*b.CaptureModules, error) {
		factories++
		return nil, d.ErrNotReady
	}, FormalKeys: func(context.Context, FormalCandidateReadScope) (FormalCandidateKeyUse, error) {
		providers++
		return nil, d.ErrNotReady
	}}
	configured, err := configuredPublicSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := b.NewLinuxProfile(configured)
	if err != nil {
		t.Fatal(err)
	}
	a.TaskType = "preflight"
	discovery, err := profile.Discover(context.Background(), d.Input{Authority: a})
	if err != nil || len(discovery.Parts) != 1 || discovery.Parts[0].Part != "source_inventory" || discovery.Parts[0].Category != "preflight" || len(discovery.Writers) != 0 || len(discovery.Parts[0].Intent.SpecJSON) != 0 || factories != 0 || writers != 0 || providers != 0 || oldParts != 0 {
		t.Fatal("preflight entered capture factory/writers/provider or dispatched job", err, factories, writers, providers, oldParts)
	}
}
