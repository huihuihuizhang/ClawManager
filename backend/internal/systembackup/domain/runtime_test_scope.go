package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrRuntimeTestScope = errors.New("explicit runtime test scope missing, invalid or changed")

const RuntimeTestScopeVersion = "explicit-known-error-lite-runtime-test-scope.v1"
const RunningOnlyRuntimeTestScopeVersion = "explicit-running-only-runtime-test-scope.v2"
const RunningTenantRuntimeTestScopeVersion = "explicit-running-tenant-runtime-test-scope.v3"

// DATA, not authority. The original administrator must bind these exact bytes
// through the deployment core and existing signed source-writers registry/ref.
// SQL export always retains every original row. Only runtime capture is deferred.
type RuntimeTestScope struct {
	Version, InstallationID, ServerUUID, Database, NamespaceUID string
	OriginalInstancesSHA256                                     string
	Deferred                                                    []SourceInstance
}

func RuntimeInstancesSHA(instances []SourceInstance) (string, error) {
	raw, e := json.Marshal(instances)
	if e != nil {
		return "", ErrRuntimeTestScope
	}
	raw, e = jsoncanonicalizer.Transform(raw)
	if e != nil {
		return "", ErrRuntimeTestScope
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Called once by the real original owner, never on each task to reselect IDs.
// The returned scope is unsigned until the existing admin issuance binds it.
func NewKnownErrorLiteRuntimeTestScope(installation, server, database, namespaceUID string, instances []SourceInstance) (*RuntimeTestScope, error) {
	return newRuntimeTestScope(RuntimeTestScopeVersion, installation, server, database, namespaceUID, instances)
}

func NewRunningOnlyRuntimeTestScope(installation, server, database, namespaceUID string, instances []SourceInstance) (*RuntimeTestScope, error) {
	s, err := newRuntimeTestScope(RunningOnlyRuntimeTestScopeVersion, installation, server, database, namespaceUID, instances)
	if err == nil {
		return s, nil
	}
	return newRuntimeTestScope(RunningTenantRuntimeTestScopeVersion, installation, server, database, namespaceUID, instances)
}

func (s *RuntimeTestScope) RunningOnly() bool {
	return s != nil && (s.Version == RunningOnlyRuntimeTestScopeVersion || s.Version == RunningTenantRuntimeTestScopeVersion)
}

func (s *RuntimeTestScope) stoppedRuntimeTestRow(i SourceInstance) bool {
	if i.Type != "openclaw" || i.Status != "stopped" || i.OS != "linux" || i.Generation <= 0 {
		return false
	}
	return s.Version == RunningOnlyRuntimeTestScopeVersion && i.Mode == "pro" ||
		s.Version == RunningTenantRuntimeTestScopeVersion && i.Mode == "lite" && i.Backend == "gateway" && i.Pod == "" && i.Namespace == ""
}

func newRuntimeTestScope(version, installation, server, database, namespaceUID string, instances []SourceInstance) (*RuntimeTestScope, error) {
	s := &RuntimeTestScope{Version: version, InstallationID: installation, ServerUUID: server, Database: database, NamespaceUID: namespaceUID, Deferred: []SourceInstance{}}
	for _, i := range instances {
		if s.stoppedRuntimeTestRow(i) {
			s.Deferred = append(s.Deferred, i)
			continue
		}
		if i.Status != "error" {
			continue
		}
		if i.Mode != "lite" || (i.Type != "opencode" && i.Type != "deepseek-harness") {
			return nil, ErrRuntimeTestScope
		}
		s.Deferred = append(s.Deferred, i)
	}
	var e error
	s.OriginalInstancesSHA256, e = RuntimeInstancesSHA(instances)
	if e != nil || s.Validate(instances) != nil {
		return nil, ErrRuntimeTestScope
	}
	return s, nil
}

func (s *RuntimeTestScope) ShapeValid() bool {
	if s == nil || s.Version != RuntimeTestScopeVersion && !s.RunningOnly() || s.InstallationID == "" || s.ServerUUID == "" || s.Database == "" || s.NamespaceUID == "" || len(s.OriginalInstancesSHA256) != 64 || (s.Version == RuntimeTestScopeVersion && len(s.Deferred) != 2) || (s.RunningOnly() && len(s.Deferred) != 3) {
		return false
	}
	decoded, e := hex.DecodeString(s.OriginalInstancesSHA256)
	if e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != s.OriginalInstancesSHA256 {
		return false
	}
	kinds := map[string]bool{}
	stopped := 0
	for n, i := range s.Deferred {
		if i.ID <= 0 || i.UserID <= 0 || i.Generation < 0 || n > 0 && s.Deferred[n-1].ID >= i.ID {
			return false
		}
		if s.stoppedRuntimeTestRow(i) {
			stopped++
			continue
		}
		if i.Mode != "lite" || i.Status != "error" || (i.Type != "opencode" && i.Type != "deepseek-harness") || kinds[i.Type] || s.RunningOnly() && i.OS != "linux" ||
			s.Version == RunningTenantRuntimeTestScopeVersion && (i.Backend != "gateway" || i.Pod != "" || i.Namespace != "") {
			return false
		}
		kinds[i.Type] = true
	}
	return len(kinds) == 2 && (s.Version == RuntimeTestScopeVersion || stopped == 1)
}

func (s *RuntimeTestScope) Validate(instances []SourceInstance) error {
	if !s.ShapeValid() {
		return ErrRuntimeTestScope
	}
	sum, e := RuntimeInstancesSHA(instances)
	if e != nil || sum != s.OriginalInstancesSHA256 {
		return ErrRuntimeTestScope
	}
	found := 0
	for n, i := range instances {
		if i.ID <= 0 || i.UserID <= 0 || n > 0 && instances[n-1].ID >= i.ID {
			return ErrRuntimeTestScope
		}
		if s.IsDeferred(i) {
			found++
			continue
		}
		// No wildcard error rule. A new/changed error fails even if an upstream
		// caller incorrectly kept the same signed scope object.
		tenantPro := s.Version == RunningTenantRuntimeTestScopeVersion && i.Mode == "pro" && i.Backend == "desktop" && i.Pod != "" && i.Namespace != ""
		if i.Status == "error" || s.RunningOnly() && (i.Status != "running" || i.Mode != "lite" && !tenantPro || i.OS != "linux" || i.Generation <= 0) {
			return ErrRuntimeTestScope
		}
	}
	if found != len(s.Deferred) || s.Version == RunningOnlyRuntimeTestScopeVersion && len(instances) != 6 ||
		s.Version == RunningTenantRuntimeTestScopeVersion && len(instances) <= found {
		return ErrRuntimeTestScope
	}
	return nil
}

func (s *RuntimeTestScope) IsDeferred(i SourceInstance) bool {
	if !s.ShapeValid() {
		return false
	}
	for _, d := range s.Deferred {
		if reflect.DeepEqual(i, d) {
			return true
		}
	}
	return false
}

func (s *RuntimeTestScope) Clone() *RuntimeTestScope {
	if s == nil {
		return nil
	}
	copy := *s
	copy.Deferred = append([]SourceInstance{}, s.Deferred...)
	return &copy
}

func (s *RuntimeTestScope) RuntimeInstances(instances []SourceInstance) ([]SourceInstance, error) {
	if s == nil {
		return instances, nil
	}
	if s.Validate(instances) != nil {
		return nil, ErrRuntimeTestScope
	}
	out := []SourceInstance{}
	for _, i := range instances {
		if !s.IsDeferred(i) {
			out = append(out, i)
		}
	}
	return out, nil
}
