package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type registrationServeOutcome struct {
	drained bool
	err     error
}

func registrationTestTLS(t *testing.T, handler http.Handler) (*http.Server, net.Listener, *http.Client, string) {
	t.Helper()
	certificate := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config, client := certificate.TLS.Clone(), certificate.Client()
	certificate.Close()
	client.Timeout = 5 * time.Second
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, TLSConfig: config, ReadHeaderTimeout: time.Second}
	t.Cleanup(func() { server.Close(); listener.Close(); client.CloseIdleConnections() })
	return server, listener, client, "https://" + listener.Addr().String()
}

func TestRegistrationHTTPSDrainsActiveHandlerBeforeReturn(t *testing.T) {
	entered, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseHandler()
	server, listener, client, url := registrationTestTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		close(entered)
		<-release
		_, _ = w.Write([]byte("complete"))
	}))
	shutdownStarted := make(chan struct{})
	server.RegisterOnShutdown(func() { close(shutdownStarted) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan registrationServeOutcome, 1)
	go func() {
		drained, err := serveRegistrationHTTP(ctx, server, func() error { return server.ServeTLS(listener, "", "") }, 3*time.Second)
		done <- registrationServeOutcome{drained, err}
	}()
	response := make(chan error, 1)
	go func() {
		res, err := client.Get(url)
		if err == nil {
			var raw []byte
			raw, err = io.ReadAll(res.Body)
			res.Body.Close()
			if err == nil && string(raw) != "complete" {
				err = errors.New("truncated TLS response")
			}
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS handler did not start")
	}
	cancel()
	select {
	case <-shutdownStarted:
	case <-time.After(time.Second):
		t.Fatal("shutdown watcher did not run")
	}
	select {
	case result := <-done:
		t.Fatalf("returned before active handler drained: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	releaseHandler()
	select {
	case err := <-response:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS response did not finish")
	}
	select {
	case result := <-done:
		if !result.drained || result.err != nil {
			t.Fatal("graceful result", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful lifecycle did not return")
	}
	select {
	case <-handlerDone:
	default:
		t.Fatal("dependencies could close before handler finished")
	}
}

func TestRegistrationHTTPSTimeoutIsNotDrained(t *testing.T) {
	entered, release, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		close(release)
		select {
		case <-entered:
			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Error("forced-close handler leaked after release")
			}
		default:
		}
	}()
	server, listener, client, url := registrationTestTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); defer close(handlerDone); <-release }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan registrationServeOutcome, 1)
	go func() {
		drained, err := serveRegistrationHTTP(ctx, server, func() error { return server.ServeTLS(listener, "", "") }, 50*time.Millisecond)
		done <- registrationServeOutcome{drained, err}
	}()
	response := make(chan error, 1)
	go func() {
		res, err := client.Get(url)
		if res != nil {
			res.Body.Close()
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS handler did not start")
	}
	cancel()
	select {
	case result := <-done:
		if result.drained || !errors.Is(result.err, context.DeadlineExceeded) {
			t.Fatal("forced close claimed graceful drain", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown exceeded budget")
	}
	select {
	case <-handlerDone:
		t.Fatal("test did not retain an active handler")
	default:
	}
	select {
	case err := <-response:
		if err == nil {
			t.Fatal("forced-close client saw success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forced close left TLS connection open")
	}
}

func TestRegistrationHTTPSListenerFailureStopsWatcher(t *testing.T) {
	server, listener, _, _ := registrationTestTLS(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	listener.Close()
	drained, err := serveRegistrationHTTP(context.Background(), server, func() error { return server.ServeTLS(listener, "", "") }, time.Second)
	if !drained || err == nil {
		t.Fatal("listener error hidden or watcher not drained", drained, err)
	}
}

func TestRegistrationHTTPSCanceledBeforeListen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	drained, err := serveRegistrationHTTP(ctx, &http.Server{}, func() error { called = true; return nil }, time.Second)
	if err != nil || !drained || called {
		t.Fatal("canceled startup opened listener", drained, err, called)
	}
}
