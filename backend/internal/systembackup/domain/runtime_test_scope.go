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
	s := &RuntimeTestScope{Version: RuntimeTestScopeVersion, InstallationID: installation, ServerUUID: server, Database: database, NamespaceUID: namespaceUID, Deferred: []SourceInstance{}}
	for _, i := range instances {
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
	if s == nil || s.Version != RuntimeTestScopeVersion || s.InstallationID == "" || s.ServerUUID == "" || s.Database == "" || s.NamespaceUID == "" || len(s.OriginalInstancesSHA256) != 64 || len(s.Deferred) != 2 {
		return false
	}
	decoded, e := hex.DecodeString(s.OriginalInstancesSHA256)
	if e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != s.OriginalInstancesSHA256 {
		return false
	}
	kinds := map[string]bool{}
	for n, i := range s.Deferred {
		if i.ID <= 0 || i.UserID <= 0 || i.Generation < 0 || i.Mode != "lite" || i.Status != "error" || (i.Type != "opencode" && i.Type != "deepseek-harness") || kinds[i.Type] || n > 0 && s.Deferred[n-1].ID >= i.ID {
			return false
		}
		kinds[i.Type] = true
	}
	return len(kinds) == 2
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
		if i.Status == "error" {
			return ErrRuntimeTestScope
		}
	}
	if found != 2 {
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
