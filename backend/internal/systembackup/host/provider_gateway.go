package host

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/recovery"
)

type ProviderGatewayConfig struct {
	Listen          string
	TLS             TLSFiles
	ControlDatabase string
	Server          recovery.GatewayServerConfig
	BackendModule   recovery.Reference
	BackendConfig   PinnedFile
}

func (c ProviderGatewayConfig) Validate() error {
	host, port, e := net.SplitHostPort(c.Listen)
	n, portErr := strconv.Atoi(port)
	if e != nil || net.ParseIP(host) == nil || portErr != nil || n < 1 || n > 65535 || !tlsPaths(c.TLS) || c.Server.Validate() != nil || c.BackendModule.Validate() != nil || !pinned(c.BackendConfig) || c.Server.AllowAppend && !absolute(c.ControlDatabase) {
		return control.ErrInvalid
	}
	if !c.Server.AllowAppend && c.ControlDatabase != "" {
		return control.ErrInvalid
	}
	return nil
}

// The factory receives authenticated configuration bytes, not request URLs or
// credentials. It must construct a native backend for precisely this binding.
// No default S3/disk backend pretends to provide the missing native semantics.
type ProviderGatewayFactory func(ProviderGatewayConfig, []byte) (recovery.NativeGatewayBackend, io.Closer, error)
type ProviderGatewayFactories map[string]ProviderGatewayFactory

func LoadProviderGateway(path string) (ProviderGatewayConfig, error) {
	var c ProviderGatewayConfig
	raw, e := ReadFile(path, recovery.MaxDocument)
	if e != nil {
		return c, e
	}
	defer clear(raw)
	if _, e = recovery.Canonical(raw); e != nil {
		return c, control.ErrInvalid
	}
	if decodeConfig(raw, &c) != nil || c.Validate() != nil {
		return c, control.ErrInvalid
	}
	return c, nil
}

func RunProviderGateway(ctx context.Context, c ProviderGatewayConfig, factories ProviderGatewayFactories) error {
	if c.Validate() != nil {
		return control.ErrInvalid
	}
	factory := factories[c.BackendModule.ID]
	// Reject missing adapters before reading credentials, connecting, or listening.
	if factory == nil {
		return control.ErrNotReady
	}
	raw, e := readPinnedBytes(c.BackendConfig)
	if e != nil {
		return e
	}
	defer clear(raw)
	backend, closer, e := factory(c, raw)
	if closer != nil {
		defer closer.Close()
	}
	if e != nil || backend == nil {
		return control.ErrNotReady
	}
	ca, e := ReadFile(c.TLS.CA, 64<<10)
	if e != nil {
		return e
	}
	cert, e := ReadFile(c.TLS.Certificate, 64<<10)
	if e != nil {
		return e
	}
	key, e := ReadFile(c.TLS.Key, 64<<10)
	if e != nil {
		return e
	}
	defer clear(key)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return control.ErrInvalid
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return control.ErrInvalid
	}
	var journal recovery.GatewayDispatchJournal
	if c.Server.AllowAppend {
		bounded, stop := context.WithTimeout(ctx, 10*time.Second)
		db, e := control.OpenControlDatabase(bounded, c.ControlDatabase)
		stop()
		if e != nil {
			return e
		}
		defer db.Close()
		bounded, stop = context.WithTimeout(ctx, 5*time.Second)
		var count int
		e = db.QueryRowContext(bounded, "SELECT COUNT(*) FROM system_backup_gateway_dispatch WHERE 1=0").Scan(&count)
		stop()
		if e != nil {
			return control.ErrNotReady
		}
		journal = control.GatewayDispatch{Store: control.SQLStore{DB: db}}
	}
	handler, e := recovery.NewGatewayServer(c.Server, backend, journal)
	if e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return control.ErrNotReady
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{pair}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if server.Shutdown(shutdown) != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	e = server.ServeTLS(listener, "", "")
	if errors.Is(e, http.ErrServerClosed) && ctx.Err() != nil {
		return ctx.Err()
	}
	return control.ErrNotReady
}
