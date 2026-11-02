// Read-only original production MySQL input observation. It neither creates
// accounts/certificates/routines nor initializes/enables backup configuration.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

var errObserve = errors.New("original production SQL observation rejected")
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

type sourcePlan struct {
	Version, Purpose, InventorySHA256            string
	Namespace, NamespaceUID                      string
	OwnerSubject, OwnerUID, OwnerGroupsSHA256    string
	Service, ServiceUID, Address                 string
	Port                                         int
	Database, ServerUUID, Account, TLSServerName string
	CASHA256                                     string
	Census                                       domain.SchemaCensusSpec
}

type serviceIdentity struct {
	Name, UID, Namespace string
	ClusterIP            string `json:"cluster_ip"`
	Ports                []struct{ Port int }
}

type publicInventory struct {
	Version      string    `json:"schema_version"`
	Namespace    string    `json:"namespace"`
	NamespaceUID string    `json:"namespace_uid"`
	ObservedAt   time.Time `json:"observed_at"`
	Owner        struct {
		Subject      string `json:"subject"`
		UID          string `json:"uid"`
		GroupsSHA256 string `json:"groups_sha256"`
	} `json:"owner"`
	Objects map[string]struct{ Items []serviceIdentity } `json:"public_objects"`
}

type observation struct {
	Version, Status, Purpose, InventorySHA256, PlanSHA256 string
	Namespace, NamespaceUID, OwnerSubject, ServiceUID     string
	Database, ServerUUID, Account                         string
	TLSVersion, TLSCipher, PeerLeafSHA256                 string
	PeerDNSNames, PeerIPAddresses                         []string
	ObservedAt                                            time.Time
	FiniteBusinessGrantsChecked, SchemaCensusChecked      bool
	SourceScopeComplete, AcceptanceReady                  bool
}

func hash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func pinnedPublicFile(path, digest string, max int64) ([]byte, error) {
	// Reuse the bounded regular-file/symlink/identity checks. Public inputs are
	// kept in the same private delivery directory as their selected pins.
	raw, err := install.ReadSourceMaterialFile(path)
	if err != nil || int64(len(raw)) > max || !digestPattern.MatchString(digest) || hash(raw) != digest {
		return nil, errObserve
	}
	return raw, nil
}

func validatePlan(p sourcePlan, inventory publicInventory, now time.Time) error {
	if p.Version != "original-production-source-sql-plan.v1" || p.Purpose != "functional_test" || p.Namespace != "clawmanager-zhanghui08-system" || p.NamespaceUID != "337cfe30-2c17-4b8e-b32a-760778b8098e" || !digestPattern.MatchString(p.InventorySHA256) || !digestPattern.MatchString(p.CASHA256) || !digestPattern.MatchString(p.OwnerGroupsSHA256) || !namePattern.MatchString(p.Service) || p.ServiceUID == "" || p.Port < 1 || p.Port > 65535 || !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(p.Database) || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(p.ServerUUID) || !regexp.MustCompile(`^[A-Za-z0-9_]+@[A-Za-z0-9_.:%-]+$`).MatchString(p.Account) || strings.SplitN(p.Account, "@", 2)[0] == "root" || p.TLSServerName == "" || strings.ContainsAny(p.TLSServerName, "/\\@?#\r\n\x00 ") {
		return errObserve
	}
	if inventory.Version != "zhanghui08-original-first-install-public-inputs.v1" || inventory.Namespace != p.Namespace || inventory.NamespaceUID != p.NamespaceUID || inventory.Owner.Subject != p.OwnerSubject || inventory.Owner.UID != p.OwnerUID || inventory.Owner.GroupsSHA256 != p.OwnerGroupsSHA256 || p.OwnerSubject == "" || inventory.ObservedAt.IsZero() || now.Before(inventory.ObservedAt) || now.Sub(inventory.ObservedAt) > 15*time.Minute {
		return errObserve
	}
	found := false
	addressHost, addressPort, addressError := net.SplitHostPort(p.Address)
	if addressError != nil || addressPort != strconv.Itoa(p.Port) {
		return errObserve
	}
	for _, service := range inventory.Objects["services"].Items {
		if service.Name != p.Service || service.UID != p.ServiceUID || service.Namespace != p.Namespace {
			continue
		}
		allowedHost := p.Service + "." + p.Namespace + ".svc"
		if service.ClusterIP != "" && service.ClusterIP != "None" {
			ip := net.ParseIP(service.ClusterIP)
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				return errObserve
			}
			allowedHost = service.ClusterIP
		}
		for _, port := range service.Ports {
			found = found || port.Port == p.Port && addressHost == allowedHost
		}
	}
	if !found {
		return errObserve
	}
	return nil
}

func productionConnector(p sourcePlan, dsn, ca []byte, observed *observation) (mysql.Config, error) {
	zero := mysql.Config{}
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(dsn)))
	address := p.Address
	if err != nil || cfg.Net != "tcp" || cfg.Addr != address || cfg.DBName != p.Database || cfg.User != strings.SplitN(p.Account, "@", 2)[0] || cfg.User == "root" || cfg.MultiStatements || cfg.InterpolateParams || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowOldPasswords || cfg.AllowFallbackToPlaintext || len(cfg.Params) != 0 || cfg.TLSConfig != "" && cfg.TLSConfig != "true" {
		return zero, errObserve
	}
	remaining, certificates := ca, 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return zero, errObserve
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return zero, errObserve
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return zero, errObserve
		}
		remaining, certificates = rest, certificates+1
		if certificates > 128 {
			return zero, errObserve
		}
	}
	roots := x509.NewCertPool()
	if certificates == 0 || hash(ca) != p.CASHA256 || !roots.AppendCertsFromPEM(ca) {
		return zero, errObserve
	}
	cfg.TLSConfig = ""
	cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: p.TLSServerName,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.Version != tls.VersionTLS13 {
				return errObserve
			}
			leaf := state.PeerCertificates[0]
			observed.TLSVersion, observed.TLSCipher, observed.PeerLeafSHA256 = tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), hash(leaf.Raw)
			observed.PeerDNSNames = append([]string{}, leaf.DNSNames...)
			for _, ip := range leaf.IPAddresses {
				observed.PeerIPAddresses = append(observed.PeerIPAddresses, ip.String())
			}
			return nil
		}}
	cfg.ParseTime, cfg.Loc, cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = true, time.UTC, 5*time.Second, 10*time.Second, 10*time.Second
	return *cfg, nil
}

func run(ctx context.Context, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("system-backup-source-sql-observe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planFile := flags.String("plan-file", "", "selected original public production SQL plan")
	planSHA := flags.String("plan-sha256", "", "independently selected original plan SHA256")
	inventoryFile := flags.String("inventory-file", "", "original owner/namespace-pinned public inventory")
	dsnFile := flags.String("dsn-file", "", "private existing finite-account DSN file; never root")
	caFile := flags.String("ca-file", "", "original pinned public production MySQL CA")
	mode := flags.String("mode", "", "tls, source, or render-source-account; render only prints a review proposal without reading credentials or opening SQL")
	if ctx == nil || out == nil || flags.Parse(args) != nil || flags.NArg() != 0 || *planFile == "" || *planSHA == "" || *inventoryFile == "" || *mode != "tls" && *mode != "source" && *mode != "render-source-account" || *mode != "render-source-account" && (*dsnFile == "" || *caFile == "") || *mode == "render-source-account" && (*dsnFile != "" || *caFile != "") {
		return 2
	}
	raw, err := pinnedPublicFile(*planFile, *planSHA, 262144)
	var plan sourcePlan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&plan) != nil || decoder.Decode(new(any)) != io.EOF {
		return 1
	}
	inventoryRaw, err := pinnedPublicFile(*inventoryFile, plan.InventorySHA256, 8<<20)
	var inventory publicInventory
	if err != nil || json.Unmarshal(inventoryRaw, &inventory) != nil || validatePlan(plan, inventory, time.Now().UTC()) != nil || *mode == "source" && plan.Census.Validate() != nil {
		return 1
	}
	if *mode == "render-source-account" {
		return writeSourceProposal(plan, out)
	}
	dsn, err := install.ReadPrivateFile(*dsnFile, 16384)
	if err != nil {
		return 1
	}
	defer clear(dsn)
	ca, err := pinnedPublicFile(*caFile, plan.CASHA256, 1<<20)
	if err != nil {
		return 1
	}
	report := observation{Version: "original-production-source-sql-observation.v1", Purpose: plan.Purpose, InventorySHA256: plan.InventorySHA256, PlanSHA256: *planSHA, Namespace: plan.Namespace, NamespaceUID: plan.NamespaceUID, OwnerSubject: plan.OwnerSubject, ServiceUID: plan.ServiceUID}
	cfg, err := productionConnector(plan, dsn, ca, &report)
	if err != nil {
		return 1
	}
	connector, err := mysql.NewConnector(&cfg)
	if err != nil {
		return 1
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	active, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	conn, err := db.Conn(active)
	if err != nil {
		return 1
	}
	defer conn.Close()
	var previousClock time.Time
	identity := func() error {
		var role string
		if conn.QueryRowContext(active, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)").Scan(&report.Account, &role, &report.Database, &report.ServerUUID, &report.ObservedAt) != nil || role != "NONE" || report.Account != plan.Account || report.Database != plan.Database || report.ServerUUID != plan.ServerUUID || report.TLSVersion != "TLS 1.3" || report.PeerLeafSHA256 == "" || report.ObservedAt.IsZero() || report.ObservedAt.Before(previousClock) {
			return errObserve
		}
		previousClock = report.ObservedAt
		return nil
	}
	if identity() != nil {
		return 1
	}
	report.Status = "ACTUAL_PRODUCTION_TLS_SESSION_OBSERVED_NOT_SOURCE_COMPLETENESS"
	if *mode == "source" {
		rows, err := conn.QueryContext(active, "SHOW GRANTS")
		if err != nil {
			return 1
		}
		var grants []string
		for rows.Next() {
			var grant string
			if rows.Scan(&grant) != nil || len(grants) >= 1000 {
				rows.Close()
				return 1
			}
			grants = append(grants, grant)
		}
		rowErr, closeErr := rows.Err(), rows.Close()
		if rowErr != nil || closeErr != nil || domain.ValidateBusinessSourceGrants(plan.Database, grants) != nil || domain.CheckBusinessSchemaCensus(active, conn, plan.Census) != nil {
			return 1
		}
		report.FiniteBusinessGrantsChecked, report.SchemaCensusChecked = true, true
		report.Status = "ACTUAL_FINITE_BUSINESS_SOURCE_POLICY_OBSERVED_NOT_FULL_CAPTURE"
	}
	if identity() != nil {
		return 1
	}
	if _, err := pinnedPublicFile(*inventoryFile, plan.InventorySHA256, 8<<20); err != nil {
		return 1
	}
	if _, err := pinnedPublicFile(*planFile, *planSHA, 262144); err != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(report) != nil {
		return 1
	}
	return 0
}

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if code := run(ctx, os.Args[1:], os.Stdout); code != 0 {
		_, _ = io.WriteString(os.Stderr, "original production SQL observation unavailable\n")
		os.Exit(code)
	}
}
