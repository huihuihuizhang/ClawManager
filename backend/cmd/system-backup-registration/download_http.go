package main

import (
	"io"
	"net/http"
	"strings"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

func mountDownloadHTTP(api sec.RegistrationAPI, download *loadedDownload) (http.Handler, error) {
	if download == nil {
		return api, nil
	}
	if download.application == nil || download.application.Runtime == nil || download.application.ProofTargets == nil || download.application.Runtime.CheckFailurePersistence() != nil {
		return nil, errDownloadDeployment
	}
	api.DownloadProofTargets = download.application.ProofTargets
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
			return
		}
		if download.application.Runtime.CheckFailurePersistence() != nil {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"code":"not_ready","message":"not_ready"}`)
			return
		}
		// This endpoint only inspects the existing journal. SQL/configuration
		// readiness stays in the trusted exec probe; anonymous HTTP cannot cause
		// a configuration transaction or open a second journal writer.
		if r.URL.Path == downloadReadinessPath {
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || !downloadDigest.MatchString(download.digest) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set(downloadReadinessHeader, download.digest)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasPrefix(r.URL.Path, ev.Path) {
			download.application.Runtime.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	}), nil
}
