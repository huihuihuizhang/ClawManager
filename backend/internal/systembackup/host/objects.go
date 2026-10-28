package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	"clawreef/internal/systembackup/assets"
	"clawreef/internal/systembackup/control"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type ObjectSource struct{ Endpoint, Bucket, Region, CA, Credentials string }

func objectReader(config ObjectSource) (func(context.Context, assets.ObjectRef) (io.ReadCloser, error), func(), error) {
	u, e := url.Parse(config.Endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || config.Bucket == "" {
		return nil, nil, control.ErrInvalid
	}
	ca, e := ReadFile(config.CA, 64<<10)
	if e != nil {
		return nil, nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, control.ErrInvalid
	}
	var key struct{ AccessKey, SecretKey, SessionToken string }
	if ReadJSON(config.Credentials, &key) != nil || key.AccessKey == "" || key.SecretKey == "" {
		return nil, nil, control.ErrInvalid
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	client, e := minio.New(u.Host, &minio.Options{Secure: true, Region: config.Region, Creds: credentials.NewStaticV4(key.AccessKey, key.SecretKey, key.SessionToken), Transport: transport})
	if e != nil {
		return nil, nil, control.ErrInvalid
	}
	return func(ctx context.Context, ref assets.ObjectRef) (io.ReadCloser, error) {
		return client.GetObject(ctx, config.Bucket, ref.Key, minio.GetObjectOptions{VersionID: ref.VersionID})
	}, transport.CloseIdleConnections, nil
}
