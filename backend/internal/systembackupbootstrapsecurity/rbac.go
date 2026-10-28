// Package systembackupbootstrapsecurity supplies concrete A security validators
// to the offline bootstrap command. It grants no provider or write capability.
package systembackupbootstrapsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	sec "clawreef/internal/systembackupsecurity"
)

// RBAC validates the existing registration RBAC profile from deployment-owned
// content-addressed files. Its directory is trusted composition, never HTTP.
// Path validity is checked on the execution host during Prepare, so requirements
// can describe a Linux composition without reading its mounts on another OS.
type RBAC struct{ directory string }

func NewRBAC(registryDirectory string) *RBAC { return &RBAC{registryDirectory} }

var installationID = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var databaseID = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var serverID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var requestKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

func validGrant(g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) bool {
	matrix := g.MatrixKey == "k8s-cluster" || g.MatrixKey == "k3s-cluster" || g.MatrixKey == "k8s-single-node" || g.MatrixKey == "k3s-single-node"
	return installationID.MatchString(g.InstallationID) && serverID.MatchString(g.ServerUUID) && databaseID.MatchString(g.Database) &&
		g.UserID > 0 && g.UserID <= 2147483647 && g.Username != "" && len(g.Username) <= 128 &&
		matrix && len(c.CanonicalJSON()) > 0 && g.ConfigSHA256 == c.SHA256() && requestKey.MatchString(g.IdempotencyKey) &&
		strings.TrimSpace(g.ChangeReason) != "" && utf8.ValidString(g.ChangeReason) && utf8.RuneCountInString(g.ChangeReason) <= 512
}

func (v *RBAC) Prepare(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || !filepath.IsAbs(v.directory) || filepath.Clean(v.directory) != v.directory || !validGrant(g, c) {
		return nil, sec.ErrRegistrationUnavailable
	}
	var pin sec.BootstrapRegistryRef
	for _, p := range c.Registries() {
		if p.Kind == "rbac_bindings" {
			if pin.Kind != "" {
				return nil, sec.ErrRegistrationUnavailable
			}
			pin = p
		}
	}
	if pin.Kind == "" {
		return nil, sec.ErrRegistrationUnavailable
	}
	check := &rbacCheck{files: sec.RegistrationFiles{RegistryDirectory: v.directory}, grant: g, pin: pin}
	if err := check.authorize(ctx); err != nil {
		return nil, err
	}
	return check, nil
}

type rbacCheck struct {
	files sec.RegistrationFiles
	grant sec.OfflineBootstrapGrant
	pin   sec.BootstrapRegistryRef
}

func (*rbacCheck) MarshalJSON() ([]byte, error) { return nil, sec.ErrRegistrationUnavailable }
func (*rbacCheck) String() string               { return "BootstrapRBACCheck" }
func (*rbacCheck) GoString() string             { return "BootstrapRBACCheck" }

func (c *rbacCheck) authorize(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	raw, err := c.files.RegistryBytes(c.pin.Kind, c.pin.Version, c.pin.SHA256)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	// Use the existing closed JSON/profile/role validator. It checks every
	// binding, not only the requesting principal, and rejects hash/version drift.
	a := sec.PinnedRegistrationAuthority{InstallationID: c.grant.InstallationID,
		RegistryBytes: func(kind, version, digest string) ([]byte, error) {
			if kind != c.pin.Kind || version != c.pin.Version || digest != c.pin.SHA256 {
				return nil, sec.ErrRegistrationUnavailable
			}
			return append([]byte(nil), raw...), nil
		}}
	actor := sec.RegistrationActor{UserID: c.grant.UserID, Subject: "user:" + strconv.FormatInt(c.grant.UserID, 10)}
	config := sec.RegistrationConfig{RBACRegistryVersion: c.pin.Version, RBACRegistrySHA256: c.pin.SHA256}
	if err = a.AuthorizeRole(actor, config); err != nil {
		return err
	}
	var registry sec.RegistrationRBACRegistry
	if json.Unmarshal(raw, &registry) != nil {
		return sec.ErrRegistrationUnavailable
	}
	// A different user's binding cannot assert this user's subject either.
	for _, binding := range registry.Bindings {
		if binding.Subject != "user:"+binding.ActorID {
			return sec.ErrRegistrationUnavailable
		}
	}
	if ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

func (c *rbacCheck) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if c == nil || ctx == nil || ctx.Err() != nil || tx == nil || now.IsZero() {
		return sec.ErrRegistrationUnavailable
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != c.grant.ServerUUID || database != c.grant.Database {
		return sec.ErrRegistrationUnavailable
	}
	// The outer bootstrap transaction already locks and checks the local admin
	// row and live offline grant. This read adds no locks, writes or Commit.
	return c.authorize(ctx)
}
