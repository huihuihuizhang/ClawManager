package systembackupexecution

import (
	"context"
	"net/url"
	"sort"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func collectOriginalWholeHistoryBuckets(ctx context.Context, n *minioPermissionHTTP, business []string) ([]string, error) {
	if n == nil || n.client == nil || n.client.Transport == nil {
		return nil, install.ErrInstall
	}
	u, e := url.Parse(n.provider.Endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, install.ErrInstall
	}
	// The actual original root credentials and exact native TLS CA+SPKI
	// transport were constructed by nativeInstallAdmin and verified against
	// the actual native server immediately before this complete read.
	client, e := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4(n.credential.AccessKey, n.credential.SecretKey, ""), Secure: true, Region: n.provider.Region, Transport: n.client.Transport})
	if e != nil {
		return nil, install.ErrInstall
	}
	buckets, e := client.ListBuckets(ctx)
	if e != nil || len(buckets) == 0 || len(buckets) > 64 {
		return nil, install.ErrInstall
	}
	names := make([]string, 0, len(buckets))
	seen := map[string]bool{}
	for _, bucket := range buckets {
		if bucket.Name == "" || bucket.CreationDate.IsZero() || seen[bucket.Name] {
			return nil, install.ErrInstall
		}
		seen[bucket.Name] = true
		names = append(names, bucket.Name)
	}
	for _, name := range business {
		if !seen[name] {
			return nil, install.ErrInstall
		}
	}
	sort.Strings(names)
	return names, nil
}
