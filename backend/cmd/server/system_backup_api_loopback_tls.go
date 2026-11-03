package main

import (
	"errors"
	"net/http"
	"time"
)

// Same actual router and login/session services, on a real private TLS socket.
// No forwarded header creates Request.TLS and the existing HTTP API stays up.
func newSystemBackupLoopbackTLS(handler http.Handler, getenv func(string) string) (*http.Server, error) {
	if getenv == nil {
		return nil, errors.New("backup loopback TLS unavailable")
	}
	address := getenv("SYSTEM_BACKUP_API_TLS_ADDRESS")
	if address == "" {
		return nil, nil
	}
	if address != "127.0.0.1:9002" || handler == nil {
		return nil, errors.New("backup loopback TLS unavailable")
	}
	config, e := loadSystemBackupAPITLS(getenv)
	if e != nil || config == nil {
		return nil, errors.New("backup loopback TLS unavailable")
	}
	return &http.Server{Addr: address, Handler: handler, TLSConfig: config, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}, nil
}
