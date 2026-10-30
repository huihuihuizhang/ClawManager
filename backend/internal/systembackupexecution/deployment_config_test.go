package systembackupexecution

import (
	"clawreef/internal/systembackup/kube"
	c "clawreef/internal/systembackupcontroller"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDeploymentConfiguration(t *testing.T) DeploymentConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "deployment.json")
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg := DeploymentConfig{Version: "system-backup-public-deployment.v1", CaptureScope: "platform-workspace", InstallationID: "installation", ControllerOwner: "controller", ApplicationScope: "application", Namespace: "backup", NamespaceUID: "ns-uid", TrustDomain: "backup.invalid", ForwardGrant: GrantReference{path, key}, RecoveryGrant: GrantReference{path, key}, KeyDirectory: dir, ProfileFile: path, CapacityFile: path, SourceDSNFile: path, SourceUser: "source_reader", SourceDatabase: "source", SourceServerUUID: "server-uuid", StagingDirectory: dir, StagingClaim: "staging", WorkerImage: "example/worker@sha256:" + strings.Repeat("a", 64), Security: kube.WorkerSecurity{ServiceAccountName: "worker", ServiceAccountUID: "sa-uid", NodeUIDs: map[string]string{"node": "node-uid"}}, ControlURL: "https://control.invalid/worker/v1", Listen: ":8443", ServerCertificate: path, ServerKey: path, IssuerCertificate: path, IssuerKey: path, Writers: []PlatformDeployment{{"backup", "source", "dep-uid"}}, Workspace: WorkspaceCapture{Claim: "source", Node: "node", MaxFiles: 10, MaxFileBytes: 1024, MaxArchiveBytes: 4096, MaxCompressedBytes: 4096}, AcquireSeconds: 60, HoldSeconds: 120}
	cfg.SealCustodyMaxBytes = 1 << 30
	return cfg
}

func TestDeploymentConfigurationIsPinnedAndClosed(t *testing.T) {
	cfg := testDeploymentConfiguration(t)
	path := cfg.ProfileFile
	raw, _ := json.Marshal(cfg)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadDeploymentConfig(path, hash(raw)); e != nil {
		t.Fatal("valid pinned config", e)
	}
	if _, e := LoadDeploymentConfig(path, strings.Repeat("0", 64)); e == nil {
		t.Fatal("wrong pin accepted")
	}
	raw = append(raw, []byte(` {}`)...)
	os.WriteFile(path, raw, 0600)
	if _, e := LoadDeploymentConfig(path, hash(raw)); e == nil {
		t.Fatal("trailing config accepted")
	}
	cfg.CaptureScope = "all"
	if cfg.Validate() == nil {
		t.Fatal("unimplemented all-domain capability accepted")
	}
	cfg.CaptureScope = "platform-workspace"
	cfg.Writers = append(cfg.Writers, cfg.Writers[0])
	if cfg.Validate() == nil {
		t.Fatal("duplicate writer accepted")
	}
}

func TestNFSWorkspaceRequiresInstallationOwnedSubtree(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	cfg.Workspace.Claim = ""
	cfg.Workspace.NFS = &NFSWorkspace{Server: "10.107.165.245", Export: "/"}
	cfg.Workspace.SubPath = "installations/" + hash([]byte(cfg.InstallationID))
	if err := cfg.Validate(); err != nil {
		t.Fatal("installation-owned NFS subtree rejected", err)
	}
	platform := cfg
	platform.CaptureScope = "platform-workspace"
	platform.RuntimeSources = nil
	if platform.Validate() == nil {
		t.Fatal("NFS capture without runtime source verification admitted")
	}
	for _, fault := range []string{"root", "other-installation", "alias", "dual-source", "hostname", "relative-export"} {
		candidate := cfg
		copyNFS := *cfg.Workspace.NFS
		candidate.Workspace.NFS = &copyNFS
		switch fault {
		case "root":
			candidate.Workspace.SubPath = ""
		case "other-installation":
			candidate.Workspace.SubPath = "installations/" + hash([]byte("other"))
		case "alias":
			candidate.Workspace.SubPath += "/../other"
		case "dual-source":
			candidate.Workspace.Claim = "source"
		case "hostname":
			candidate.Workspace.NFS.Server = "workspace-store.other.svc"
		case "relative-export":
			candidate.Workspace.NFS.Export = "relative"
		}
		if candidate.Validate() == nil {
			t.Fatal("unsafe NFS source admitted", fault)
		}
	}
	access, err := RequiredCaptureAccess(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range access {
		if len(rule.Rule.Resources) == 1 && rule.Rule.Resources[0] == "persistentvolumeclaims" && len(rule.Rule.ResourceNames) > 0 {
			for _, name := range rule.Rule.ResourceNames {
				if name == "" || name == "source" {
					t.Fatal("NFS capture generated source PVC permission", rule.Rule.ResourceNames)
				}
			}
		}
	}
}

func TestForwardCaptureGrantCannotBorrowRecoveryAuthority(t *testing.T) {
	for _, tc := range []struct {
		actions []string
		ok      bool
	}{
		{[]string{"prepare", "capture", "issue_worker"}, true},
		{[]string{"recover"}, false},
		{[]string{"prepare", "capture"}, false},
		{[]string{"prepare", "capture", "recover"}, false},
		{[]string{"prepare", "capture", "issue_worker", "recover"}, false},
		{[]string{"prepare", "prepare", "issue_worker"}, false},
	} {
		if forwardCaptureActions(c.ExecutionGrant{Actions: tc.actions}) != tc.ok {
			t.Fatal("forward role accepted wrong authority set")
		}
	}
}

func TestSourceGrantParserDoesNotAcceptWritesOrOtherTables(t *testing.T) {
	for _, tc := range []struct {
		grant string
		ok    bool
	}{
		{"GRANT SELECT ON `source`.`users` TO 'reader'@'%'", true},
		{"GRANT SELECT ON `source`.`instances` TO 'reader'@'%'", true},
		{"GRANT SELECT ON `source`.`users` TO `reader`@`%`", true},
		{"GRANT SELECT ON `source`.`users` TO 'reader'@'%' WITH GRANT OPTION", false},
		{"GRANT SELECT, UPDATE ON `source`.`users` TO 'reader'@'%'", false},
		{"GRANT ALL PRIVILEGES ON `source`.* TO 'reader'@'%'", false},
		{"GRANT SELECT ON `source`.`secrets` TO 'reader'@'%'", false},
	} {
		if ok := sourceSelect.MatchString(tc.grant); ok != tc.ok {
			t.Fatal("read-only grant acceptance mismatch", strings.Fields(tc.grant)[1], ok)
		}
	}
}
