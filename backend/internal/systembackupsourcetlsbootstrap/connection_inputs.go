package systembackupsourcetlsbootstrap

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"clawreef/internal/mysqltls"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The original existing root credential is read only after actual local-admin
// authentication and successful native SAN reload. It is never printed or
// placed in argv. A changed Secret which no longer matches the running server
// cannot produce a qualified connection receipt.
func (c *Client) emitConnectionInputs(ctx context.Context, plan BootstrapPlan, receipt *BootstrapReceipt) error {
	if c.identity(ctx, false) != nil {
		return ErrBootstrap
	}
	pod, e := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, plan.Pod.Name, metav1.GetOptions{})
	if e != nil || string(pod.UID) != plan.Pod.UID || objectSHA(pod.Spec) != plan.Pod.SpecSHA256 {
		return ErrBootstrap
	}
	password := []byte{}
	for _, container := range pod.Spec.Containers {
		if container.Name != plan.Container {
			continue
		}
		for _, env := range container.Env {
			if env.Name != "MYSQL_ROOT_PASSWORD" {
				continue
			}
			if env.ValueFrom == nil {
				password = []byte(env.Value)
			} else if ref := env.ValueFrom.SecretKeyRef; ref != nil {
				if c.access(ctx, "get", "", "secrets", "", ref.Name) != nil {
					return ErrBootstrap
				}
				secret, e := c.kube.CoreV1().Secrets(c.options.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
				if e != nil || secret.UID == "" || secret.DeletionTimestamp != nil {
					return ErrBootstrap
				}
				password = append([]byte{}, secret.Data[ref.Key]...)
			}
		}
	}
	defer clear(password)
	if len(password) == 0 {
		return ErrBootstrap
	}
	material := mysqltls.Material{CAFile: receipt.CAFile, CASHA256: receipt.CASHA256, ServerName: plan.DNSNames[0]}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = string(password)
	cfg.Net = "tcp"
	cfg.Addr = plan.DatabaseAddress
	cfg.DBName = plan.Database
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 10 * time.Second
	cfg.WriteTimeout = 10 * time.Second
	dsn := []byte(cfg.FormatDSN())
	defer clear(dsn)
	if material.Apply(cfg) != nil {
		return ErrBootstrap
	}
	connector, e := mysql.NewConnector(cfg)
	cfg.Passwd = ""
	if e != nil {
		return ErrBootstrap
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	var uuid, account, username, stored, role, provider string
	var active bool
	var id int64
	if db.QueryRowContext(ctx, "SELECT @@server_uuid,CURRENT_USER()").Scan(&uuid, &account) != nil || uuid != plan.Native.ServerUUID || !strings.HasPrefix(account, "root@") {
		return ErrBootstrap
	}
	if db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,is_active,auth_provider FROM users WHERE username=?`, plan.AdminUsername).Scan(&id, &username, &stored, &role, &active, &provider) != nil || id != plan.Native.AdminID || username != plan.AdminUsername || role != "admin" || !active || provider != "local" || bcrypt.CompareHashAndPassword([]byte(stored), c.password) != nil {
		return ErrBootstrap
	}
	if c.identity(ctx, false) != nil {
		return ErrBootstrap
	}
	file, e := writeOutput(c.options.OutputDirectory, "mysql-installer-original.dsn", dsn)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(material)
	if e != nil {
		return ErrBootstrap
	}
	tlsFile, e := writeOutput(c.options.OutputDirectory, "mysql-source-tls.json", raw)
	if e != nil {
		return e
	}
	receipt.DSNFile, receipt.DSNSHA256, receipt.SourceTLSFile, receipt.SourceTLSSHA256, receipt.SQLAccount, receipt.OperatorSQLTLSVerified = file, digest(dsn), tlsFile, digest(raw), account, true
	// Pin only the already exported CA path; no private MySQL/CA signing key
	// leaves the original container or appears in this installation receipt.
	if material.CAFile != filepath.Join(c.options.OutputDirectory, "mysql-source-ca.pem") {
		return ErrBootstrap
	}
	return c.identity(ctx, false)
}
