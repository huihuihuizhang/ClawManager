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
	profile, _ := ma.NativeProfile(ma.SeptemberPermissionProfile)
	if json.Unmarshal(raw, &info) != nil || info.DeploymentID != r.provider.DeploymentID || info.Region != r.provider.Region || len(info.Servers) != 1 {
		return "", minioPermissionFailure("september-native-server-identity")
	}
	s := info.Servers[0]
	if s.State != "online" || s.Version != profile.ServerVersion || s.Commit != profile.ServerCommit {
		return "", minioPermissionFailure("september-native-release-contract")
	}
	stable, err := ce.Canonical(info)
	if err != nil {
		return "", err
	}
	return hash(stable), nil
}
