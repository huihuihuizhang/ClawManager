package services

import (
	"path/filepath"
	"testing"

	"clawreef/internal/models"
	"clawreef/internal/systembackup/scope"
	sh "clawreef/internal/systembackupskillhub"
)

func TestBackupWorkspaceSkillRootsMatchOriginalService(t *testing.T) {
	for _, kind := range []string{"openclaw", "hermes", "deepseek-harness", "opencode"} {
		for _, mode := range []string{"lite", "pro"} {
			t.Run(kind+"-"+mode, func(t *testing.T) {
				workspace := t.TempDir()
				backend := "gateway"
				if mode == "pro" {
					backend = "desktop"
				}
				instance := &models.Instance{Type: kind, InstanceMode: mode, RuntimeType: backend, WorkspacePath: &workspace}
				project := ""
				if kind == "opencode" && mode == "pro" {
					var err error
					instance.EnvironmentOverridesJSON, err = marshalEnvironmentOverrides(map[string]string{openCodeDefaultProjectEnv: "/config/workspace/nested/project"})
					if err != nil {
						t.Fatal(err)
					}
					project = openCodeProProjectRelativePath(instance)
				}
				relative, err := sh.WorkspaceSkillRoot(scope.Runtime{Type: kind, Mode: mode, Backend: backend, Variant: "linux", OS: "linux"}, project)
				if err != nil || filepath.Join(workspace, filepath.FromSlash(relative)) != runtimeSkillInstallRoot(instance) {
					t.Fatal("backup root drifted from original Runtime mapping", relative, err)
				}
			})
		}
	}
}

func TestBackupWorkspaceMD5GoldenMatchesOriginalService(t *testing.T) {
	files := map[string][]byte{"SKILL.md": []byte("# demo\n"), "src/main.py": []byte("print('demo')\n"), ".private": []byte("full archive must still retain this")}
	if hashDirectory(files) != "7c876ed8f2fc9206f8cc0914cb0a24f0" {
		t.Fatal("original MD5 semantics changed; review backup archive inspector golden")
	}
}
