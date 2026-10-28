package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"clawreef/internal/services/k8s"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	prefix := strings.TrimSpace(os.Getenv("K8S_NAMESPACE"))
	if prefix == "" {
		prefix = "clawmanager"
	}
	systemNamespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	if systemNamespace == "" {
		systemNamespace = prefix + "-system"
	}
	port, err := k8s.SecretBrokerPort(os.Getenv("CLAWMANAGER_SECRET_BROKER_PORT"))
	if err != nil {
		log.Fatal(err)
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("initialize in-cluster Kubernetes configuration: %v", err)
	}
	restConfig.Timeout = 15 * time.Second
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Fatalf("initialize Kubernetes client: %v", err)
	}
	handler, err := k8s.NewSecretBrokerHandler(client, k8s.SecretBrokerConfig{
		NamespacePrefix:   prefix,
		SystemNamespace:   systemNamespace,
		AppNamespace:      systemNamespace,
		AppServiceAccount: envOrDefault("CLAWMANAGER_SECRET_BROKER_APP_SERVICE_ACCOUNT", "clawmanager-app"),
		Audience:          envOrDefault("CLAWMANAGER_SECRET_BROKER_AUDIENCE", "clawmanager-secret-broker"),
		ReadAllowlist:     k8s.ParseSecretBrokerReadAllowlist(os.Getenv("CLAWMANAGER_SECRET_BROKER_READ_ALLOWLIST")),
	})
	if err != nil {
		log.Fatalf("initialize Secret broker policy: %v", err)
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
	certFile := strings.TrimSpace(os.Getenv("CLAWMANAGER_SECRET_BROKER_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("CLAWMANAGER_SECRET_BROKER_TLS_KEY_FILE"))
	if (certFile == "") != (keyFile == "") {
		log.Fatal("CLAWMANAGER_SECRET_BROKER_TLS_CERT_FILE and CLAWMANAGER_SECRET_BROKER_TLS_KEY_FILE must be set together")
	}
	if certFile == "" && !k8s.SecretBrokerInsecureHTTPForTestsEnabled() {
		log.Fatal("Secret broker TLS certificate and key are required; insecure HTTP is test-only")
	}
	go func() {
		log.Printf("Secret broker listening on %s for app identity system:serviceaccount:%s:%s", server.Addr, systemNamespace, envOrDefault("CLAWMANAGER_SECRET_BROKER_APP_SERVICE_ACCOUNT", "clawmanager-app"))
		var serveErr error
		if certFile != "" {
			serveErr = server.ListenAndServeTLS(certFile, keyFile)
		} else {
			serveErr = server.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			log.Fatalf("Secret broker failed: %v", serveErr)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Secret broker shutdown failed: %v", err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
