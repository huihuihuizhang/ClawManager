package main

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// listen must serve this server. A caller may close owned runtime keys only
// when drained is true. A timeout closes connections and returns false: forced
// connection closure does not prove that every handler has stopped using keys.
func serveRegistrationHTTP(ctx context.Context, server *http.Server, listen func() error, drainTimeout time.Duration) (drained bool, err error) {
	if ctx == nil || server == nil || listen == nil || drainTimeout <= 0 {
		return false, errors.New("registration HTTPS lifecycle unavailable")
	}
	if ctx.Err() != nil {
		return true, nil
	}
	lifecycle, cancel := context.WithCancel(ctx)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		<-lifecycle.Done()
		drain, stop := context.WithTimeout(context.Background(), drainTimeout)
		defer stop()
		err := server.Shutdown(drain)
		if err != nil {
			_ = server.Close()
		}
		finished <- err
	}()
	listenErr := listen()
	cancel() // listener startup/fatal failure must also stop the shutdown watcher
	if shutdownErr := <-finished; shutdownErr != nil {
		return false, shutdownErr
	}
	if errors.Is(listenErr, http.ErrServerClosed) && ctx.Err() != nil {
		return true, nil
	}
	return true, listenErr
}
