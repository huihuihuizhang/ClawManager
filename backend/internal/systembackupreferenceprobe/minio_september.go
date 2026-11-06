package systembackupreferenceprobe

import (
	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

func (r *minioPermissionHTTP) serverSeptember(ctx context.Context) (string, error) {
	return r.serverBuiltinFlat(ctx, ma.SeptemberPermissionProfile)
}

func (r *minioPermissionHTTP) serverBuiltinFlat(ctx context.Context, permission string) (string, error) {
	if !ma.MatchesBuiltinFlatImage(permission, r.provider.ImageID) {
		return "", minioPermissionFailure("builtin-flat-provider-image")
	}
	raw, status, err := r.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	if err != nil || status != http.StatusOK || minioPermissionUniqueJSON(raw) != nil {
		return "", minioPermissionFailure("september-native-server-info")
	}
	var info struct {
		DeploymentID string `json:"deploymentID"`
		Region       string `json:"region"`
		Servers      []struct {
			State   string `json:"state"`
			Version string `json:"version"`
			Commit  string `json:"commitID"`
		} `json:"servers"`
	}
	if json.Unmarshal(raw, &info) != nil || info.DeploymentID != r.provider.DeploymentID || info.Region != r.provider.Region || len(info.Servers) != 1 {
		return "", minioPermissionFailure("september-native-server-identity")
	}
	s := info.Servers[0]
	if s.State != "online" || !ma.MatchesNativeServer(permission, s.Version, s.Commit) {
		return "", minioPermissionFailure("september-native-release-contract")
	}
	stable, err := ce.Canonical(info)
	if err != nil {
		return "", err
	}
	return hash(stable), nil
}

func (r *minioPermissionHTTP) serverOriginalBackupTarget(ctx context.Context) (string, error) {
	if ma.MatchesDeleteCompatImageID(r.provider.ImageID) {
		return r.serverBuiltinFlat(ctx, ma.DeleteCompatPermissionProfile)
	}
	return r.serverSeptember(ctx)
}
