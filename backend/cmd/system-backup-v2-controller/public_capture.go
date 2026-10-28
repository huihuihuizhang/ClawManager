package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"clawreef/internal/config"
	"clawreef/internal/db"
	"clawreef/internal/services/k8s"
	"clawreef/internal/services/leader"
	c "clawreef/internal/systembackupcontroller"
	execution "clawreef/internal/systembackupexecution"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Public and historical controller modes are exclusive. There is no shadow
// legacy task or second capture loop behind this production entry point.
func runConfiguredPublic(ctx context.Context, cfg *config.Config) error {
	if !cfg.LeaderElection.Enabled {
		return errors.New("public execution requires leader election")
	}
	if e := c.ValidateControllerDatabaseCredentials(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), cfg.Database.User); e != nil {
		return e
	}
	session, e := db.ConnectPublicBackupMetadata(cfg.Database, func(ctx context.Context, pool *sql.DB) error {
		return (c.SQLPublicCaptureGrantProbe{DB: pool, Schema: cfg.Database.Database, User: cfg.Database.User}).Check(ctx)
	})
	if e != nil {
		return errors.New("public control database unavailable")
	}
	defer session.Close()
	control, ok := session.Driver().(*sql.DB)
	if !ok || control == nil {
		return errors.New("public control SQL unavailable")
	}
	if e = k8s.Initialize(cfg); e != nil {
		return errors.New("public Kubernetes client unavailable")
	}
	kc := k8s.GetClient()
	if kc == nil || kc.Clientset == nil || kc.Config == nil {
		return errors.New("public Kubernetes client unavailable")
	}
	publicREST := rest.CopyConfig(kc.Config)
	publicREST.QPS = 50
	publicREST.Burst = 100
	publicREST.Timeout = 10 * time.Second
	publicClient, e := kubernetes.NewForConfig(publicREST)
	if e != nil {
		return errors.New("public bounded Kubernetes client unavailable")
	}
	watchREST := rest.CopyConfig(publicREST)
	watchREST.Timeout = 0 // Each witness supplies its own bounded stream context.
	watchClient, e := kubernetes.NewForConfig(watchREST)
	if e != nil {
		return errors.New("public bounded Kubernetes watch client unavailable")
	}
	dyn, e := dynamic.NewForConfig(publicREST)
	if e != nil {
		return errors.New("public Kubernetes dynamic client unavailable")
	}
	service, e := execution.NewDeploymentService(ctx, control, publicClient, dyn, os.Getenv("SYSTEM_BACKUP_PUBLIC_CONFIG_FILE"), os.Getenv("SYSTEM_BACKUP_PUBLIC_CONFIG_SHA256"), os.Getenv("SYSTEM_BACKUP_FORWARD_GRANT_SHA256"), os.Getenv("SYSTEM_BACKUP_RECOVERY_GRANT_SHA256"), os.Getenv("SYSTEM_BACKUP_ENABLED") == "true")
	if e != nil {
		return fmt.Errorf("public deployment unavailable: %w", e)
	}
	defer service.Close()
	service.Runtime.Owner.WatchClient = watchClient
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName, _ = os.Hostname()
	}
	pod, z := publicClient.CoreV1().Pods(service.Config.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if z != nil || pod.UID == "" || pod.DeletionTimestamp != nil {
		return errors.New("public controller Pod identity unavailable")
	}
	service.PublisherOwner = "public:" + string(pod.UID)
	active, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 1)
	status := &controllerStatus{}
	health := os.Getenv("SYSTEM_BACKUP_CONTROLLER_HEALTH_ADDRESS")
	if health == "" {
		health = defaultHealthAddress
	}
	status.setReady(c.BootstrapSnapshot{ConfigEnabled: true, EffectiveEnabled: true, ConfigVersion: service.Forward.DeploymentBinding().ConfigVersion})
	status.setDependencyFailure("standby")
	_ = startHealthServer(active, health, control, status)
	lease := leader.Config{Namespace: service.Config.Namespace, LeaseName: "clawmanager-public-backup-controller", Identity: service.PublisherOwner, LeaseDuration: time.Duration(cfg.LeaderElection.LeaseDuration) * time.Second, RenewDeadline: time.Duration(cfg.LeaderElection.RenewDeadline) * time.Second, RetryPeriod: time.Duration(cfg.LeaderElection.RetryPeriod) * time.Second}
	log.Printf("[system-backup-public] ready-for-election scope=%s protocol=public-v1", service.Config.CaptureScope)
	var lifecycle sync.Mutex
	var runningDone chan struct{}
	leader.Run(active, publicClient, lease, leader.Callbacks{
		OnStartedLeading: func(leaderCtx context.Context) {
			lifecycle.Lock()
			if leaderCtx.Err() != nil || runningDone != nil {
				lifecycle.Unlock()
				return
			}
			done := make(chan struct{})
			runningDone = done
			lifecycle.Unlock()
			status.leading.Store(true)
			status.setDependenciesReady()
			go func() {
				defer close(done)
				if z := service.Run(leaderCtx); z != nil {
					log.Printf("[system-backup-public] execution stopped with a protected journal")
					select {
					case failures <- z:
					default:
					}
					cancel()
				}
			}()
		},
		OnStoppedLeading: func() {
			status.leading.Store(false)
			status.setDependencyFailure("standby")
			lifecycle.Lock()
			done := runningDone
			lifecycle.Unlock()
			if done != nil {
				select {
				case <-done:
				case <-time.After(130 * time.Second):
					select {
					case failures <- c.ErrExecutionRecoveryRequired:
					default:
					}
					cancel()
				}
			}
			lifecycle.Lock()
			runningDone = nil
			lifecycle.Unlock()
		},
	})
	select {
	case <-failures:
		return errors.New("public execution stopped; original journals retained")
	default:
		return nil
	}
}
