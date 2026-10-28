package systembackupsecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// NewPinnedBootstrapCandidateAuthority adds the original offline grant and
// pinned RBAC sources to a mandatory independent deployment/resource authority.
// It does not authenticate a deployment mapping, replace any of the 27 resource
// requirements, reserve capacity, or turn comparison data into authorization.
// Every attempt, including a historical retry, prepares fresh original sources
// before transaction locks; locked methods use only that owned snapshot and SQL.
func NewPinnedBootstrapCandidateAuthority(s BootstrapAdmissionSources, original BootstrapCandidateAuthority) (BootstrapCandidateAuthority, error) {
	if s.ReadGrant == nil || s.RegistryBytes == nil || candidateAuthorityNil(original) {
		return nil, ErrRegistrationUnavailable
	}
	return &pinnedBootstrapCandidateAuthority{readGrant: s.ReadGrant, registryBytes: s.RegistryBytes, original: original, clock: time.Now}, nil
}

type pinnedBootstrapCandidateAuthority struct {
	readGrant     func() (OfflineBootstrapGrant, time.Time, time.Time, error)
	registryBytes func(string, string, string) ([]byte, error)
	original      BootstrapCandidateAuthority
	clock         func() time.Time
}

type pinnedBootstrapCandidateSession struct {
	grant              OfflineBootstrapGrant
	notBefore, expires time.Time
	deadline           pd.Timestamp
	rbac               BootstrapRegistryRef
	registries         map[BootstrapRegistryRef][]byte
	registriesComplete bool
	request            pd.BootstrapConsumptionRequest
	hash               pd.Hash
	original           BootstrapCandidateAuthoritySession
}

func (pinnedBootstrapCandidateAuthority) String() string { return "PinnedBootstrapCandidateAuthority" }
func (pinnedBootstrapCandidateAuthority) GoString() string {
	return "PinnedBootstrapCandidateAuthority"
}
func (pinnedBootstrapCandidateAuthority) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*pinnedBootstrapCandidateAuthority) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}
func (pinnedBootstrapCandidateSession) String() string   { return "PinnedBootstrapCandidateSession" }
func (pinnedBootstrapCandidateSession) GoString() string { return "PinnedBootstrapCandidateSession" }
func (pinnedBootstrapCandidateSession) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*pinnedBootstrapCandidateSession) UnmarshalJSON([]byte) error {
	return ErrRegistrationUnavailable
}

func pinnedCandidateContext(ctx context.Context) bool {
	return !candidateAuthorityNil(ctx) && ctx.Err() == nil
}

// These DTOs have no authority-bearing interfaces. Detach nested slices and
// pointers before each trusted callback as well as on input/output boundaries.
func pinnedCandidateCopy[T any](v T) (T, error) {
	var out T
	copy, err := pinnedCandidateValue(reflect.ValueOf(v))
	if err != nil || !copy.IsValid() {
		return out, ErrRegistrationUnavailable
	}
	return copy.Interface().(T), nil
}

// Copy observation DTOs without invoking their wire decoders. Zero-valued
// optional facts are legitimate during intermediate stages; copying them must
// not manufacture a new admission or run structural wire validation early.
func pinnedCandidateValue(v reflect.Value) (reflect.Value, error) {
	if !v.IsValid() {
		return reflect.Value{}, ErrRegistrationUnavailable
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		child, err := pinnedCandidateValue(v.Elem())
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(child)
		return out, nil
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		child, err := pinnedCandidateValue(v.Elem())
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(child)
		return out, nil
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		var out reflect.Value
		if v.Kind() == reflect.Slice {
			out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		} else {
			out = reflect.New(v.Type()).Elem()
		}
		for i := 0; i < v.Len(); i++ {
			child, err := pinnedCandidateValue(v.Index(i))
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(child)
		}
		return out, nil
	case reflect.Struct:
		// time.Time has private immutable representation; value copying is exact.
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return v, nil
		}
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath != "" {
				return reflect.Value{}, ErrRegistrationUnavailable
			}
			child, err := pinnedCandidateValue(v.Field(i))
			if err != nil {
				return reflect.Value{}, err
			}
			out.Field(i).Set(child)
		}
		return out, nil
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key, err := pinnedCandidateValue(iter.Key())
			if err != nil {
				return reflect.Value{}, err
			}
			value, err := pinnedCandidateValue(iter.Value())
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(key, value)
		}
		return out, nil
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.String:
		return v, nil
	default:
		return reflect.Value{}, ErrRegistrationUnavailable
	}
}

func pinnedCandidateError(err error) error {
	switch err {
	case nil, pd.ErrInvalid, pd.ErrUnavailable, pd.ErrExpired, pd.ErrConflict, pd.ErrGuardRequired, ErrRegistrationPermission, ErrRegistrationUnavailable:
		return err
	default:
		return ErrRegistrationUnavailable
	}
}

// A SQL UTC(6) sample must be strictly before the original raw expiry. Ceil,
// rather than floor, preserves the last legal SQL sample for fractional grants.
func pinnedCandidateDeadline(expires time.Time) (pd.Timestamp, error) {
	t := expires.UTC()
	if rem := t.Nanosecond() % 1000; rem != 0 {
		t = t.Add(time.Duration(1000-rem) * time.Nanosecond)
	}
	v := pd.Timestamp(t.Format("2006-01-02T15:04:05.000000Z"))
	if _, err := v.Time(); err != nil || expires.IsZero() {
		return "", ErrRegistrationPermission
	}
	return v, nil
}

func (a *pinnedBootstrapCandidateAuthority) PrepareBootstrapCandidates(ctx context.Context, g OfflineBootstrapGrant, c BootstrapConfig, r pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	var zero PreparedBootstrapCandidateAuthority
	if a == nil || !pinnedCandidateContext(ctx) || a.readGrant == nil || a.registryBytes == nil || a.clock == nil || candidateAuthorityNil(a.original) || !validBootstrapGrant(g) {
		return zero, ErrRegistrationUnavailable
	}
	ownedConfig, err := DecodeBootstrapConfig(c.CanonicalJSON())
	if err != nil || !bytes.Equal(ownedConfig.CanonicalJSON(), c.CanonicalJSON()) || g.ConfigSHA256 != ownedConfig.SHA256() {
		return zero, ErrRegistrationUnavailable
	}
	hash, err := pd.BootstrapConsumptionHash(r)
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	var fields map[string]json.RawMessage
	grantBytes, err := json.Marshal(g)
	if err != nil || json.Unmarshal(ownedConfig.CanonicalJSON(), &fields) != nil ||
		r.Scope != (pd.Scope{ServerUUID: pd.ServerUUID(g.ServerUUID), Database: pd.Database(g.Database), Installation: pd.Installation(g.InstallationID)}) ||
		r.OfflineGrantHash != pd.Hash(registrationHash(string(grantBytes))) || r.ConfigHash != pd.Hash(g.ConfigSHA256) ||
		r.RegistrySetHash != pd.Hash(registrationHash(string(fields["registries"]))) || r.RefSetHash != pd.Hash(registrationHash(string(fields["references"]))) ||
		r.ActorID != pd.Counter(strconv.FormatInt(g.UserID, 10)) || r.Username != g.Username || r.MatrixKey != g.MatrixKey || r.Endpoint != BootstrapConfigEndpoint || r.IdempotencyKey != g.IdempotencyKey {
		return zero, ErrRegistrationUnavailable
	}
	ownedRequest, err := pinnedCandidateCopy(r)
	if err != nil {
		return zero, err
	}
	sort.Slice(ownedRequest.Candidates, func(i, j int) bool { return ownedRequest.Candidates[i].Purpose < ownedRequest.Candidates[j].Purpose })
	current, notBefore, expires, err := a.readGrant()
	if err != nil || current != g || notBefore.IsZero() || !expires.After(notBefore) {
		return zero, ErrRegistrationPermission
	}
	deadline, err := pinnedCandidateDeadline(expires)
	if err != nil {
		return zero, err
	}
	s := &pinnedBootstrapCandidateSession{grant: g, notBefore: notBefore, expires: expires, deadline: deadline, request: ownedRequest, hash: hash, registries: make(map[BootstrapRegistryRef][]byte), registriesComplete: true}
	for _, ref := range ownedConfig.Registries() {
		if ref.Kind == "rbac_bindings" {
			s.rbac = ref
		}
		raw, readErr := a.registryBytes(ref.Kind, ref.Version, ref.SHA256)
		// The source may reuse its buffer on the next read. Copy immediately.
		if readErr != nil || len(raw) == 0 || len(raw) > 262144 {
			s.registriesComplete = false
			continue
		}
		owned := append([]byte(nil), raw...)
		if registrationHash(string(owned)) != ref.SHA256 {
			s.registriesComplete = false
			continue
		}
		s.registries[ref] = owned
	}
	// Original Authorize requires the current grant and RBAC. Original
	// ValidateAndReserve requires all nine resource registries. Preserve that
	// separation: capture non-RBAC errors now, deny new use after D's L3 branch,
	// but permit an authenticated exact historical result without resource work.
	if s.authorizeSnapshot(ctx, a.clock()) != nil {
		return zero, ErrRegistrationPermission
	}
	callbackConfig, err := DecodeBootstrapConfig(ownedConfig.CanonicalJSON())
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	callbackRequest, err := pinnedCandidateCopy(ownedRequest)
	if err != nil {
		return zero, err
	}
	prepared, err := a.original.PrepareBootstrapCandidates(ctx, g, callbackConfig, callbackRequest)
	if err != nil {
		return zero, pinnedCandidateError(err)
	}
	if candidateAuthorityNil(prepared.Session) || s.authorizeSnapshot(ctx, a.clock()) != nil {
		return zero, ErrRegistrationPermission
	}
	s.original = prepared.Session
	if prepared.CapacityObservedAt != nil {
		observed := *prepared.CapacityObservedAt
		prepared.CapacityObservedAt = &observed
	}
	prepared.Session = s
	return prepared, nil
}

func (s *pinnedBootstrapCandidateSession) authorizeSnapshot(ctx context.Context, now time.Time) error {
	if s == nil || !pinnedCandidateContext(ctx) || now.IsZero() || now.Before(s.notBefore) || !now.Before(s.expires) || s.rbac.Kind != "rbac_bindings" {
		return ErrRegistrationPermission
	}
	a := PinnedRegistrationAuthority{InstallationID: s.grant.InstallationID, RegistryBytes: func(kind, version, digest string) ([]byte, error) {
		raw, ok := s.registries[BootstrapRegistryRef{Kind: kind, Version: version, SHA256: digest}]
		if !ok {
			return nil, ErrRegistrationUnavailable
		}
		return append([]byte(nil), raw...), nil
	}}
	return pinnedCandidateError(a.AuthorizeRole(RegistrationActor{UserID: s.grant.UserID, Subject: "user:" + strconv.FormatInt(s.grant.UserID, 10)}, RegistrationConfig{RBACRegistryVersion: s.rbac.Version, RBACRegistrySHA256: s.rbac.SHA256}))
}

func (s *pinnedBootstrapCandidateSession) requestCopy(ctx context.Context, r pd.BootstrapConsumptionRequest) (pd.BootstrapConsumptionRequest, error) {
	if s == nil || !pinnedCandidateContext(ctx) || candidateAuthorityNil(s.original) {
		return pd.BootstrapConsumptionRequest{}, ErrRegistrationUnavailable
	}
	hash, err := pd.BootstrapConsumptionHash(r)
	if err != nil || hash != s.hash {
		return pd.BootstrapConsumptionRequest{}, ErrRegistrationPermission
	}
	return pinnedCandidateCopy(s.request)
}

func (s *pinnedBootstrapCandidateSession) sample(ctx context.Context, tx pd.BootstrapReadSQL, floor time.Time) (time.Time, error) {
	if candidateAuthorityNil(tx) || floor.IsZero() {
		return time.Time{}, ErrRegistrationUnavailable
	}
	now, err := tx.SampleTime(ctx)
	_, offset := now.Zone()
	if err != nil || now.Year() < 1000 || now.Year() > 9999 || offset != 0 || now.Nanosecond()%1000 != 0 || now.Before(floor) || s.authorizeSnapshot(ctx, now) != nil {
		return time.Time{}, ErrRegistrationPermission
	}
	return now, nil
}

func (s *pinnedBootstrapCandidateSession) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	var zero pd.BootstrapConsumptionAdmission
	request, err := s.requestCopy(ctx, r)
	if err != nil {
		return zero, err
	}
	start, err := s.sample(ctx, tx, now)
	if err != nil {
		return zero, err
	}
	domain, err := pinnedCandidateCopy(d)
	if err != nil {
		return zero, err
	}
	admission, err := s.original.Authorize(ctx, tx, request, domain, start)
	if err != nil {
		return zero, pinnedCandidateError(err)
	}
	end, err := s.sample(ctx, tx, start)
	if err != nil {
		return zero, err
	}
	identity, err := admission.IdentityExpiresAt.Time()
	if err != nil || admission.BindingHash != s.hash || !end.Before(identity) {
		return zero, ErrRegistrationPermission
	}
	limit, err := s.deadline.Time()
	if err != nil {
		return zero, ErrRegistrationPermission
	}
	if limit.Before(identity) {
		admission.IdentityExpiresAt = s.deadline
	}
	// Dependency/old observation freshness is decided only after D's L3 replay
	// branch. Do not reject a legal historical receipt here by that old deadline.
	return admission, nil
}

func (s *pinnedBootstrapCandidateSession) LockHosts(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	request, err := s.requestCopy(ctx, r)
	if err != nil {
		return err
	}
	if !s.registriesComplete {
		return ErrRegistrationUnavailable
	}
	if candidateAuthorityNil(tx) {
		return ErrRegistrationUnavailable
	}
	facts, err := pinnedCandidateCopy(f)
	if err != nil {
		return err
	}
	return pinnedCandidateError(s.original.LockHosts(ctx, tx, request, facts))
}
func (s *pinnedBootstrapCandidateSession) LockReferences(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	request, err := s.requestCopy(ctx, r)
	if err != nil {
		return err
	}
	if !s.registriesComplete {
		return ErrRegistrationUnavailable
	}
	if candidateAuthorityNil(tx) {
		return ErrRegistrationUnavailable
	}
	facts, err := pinnedCandidateCopy(f)
	if err != nil {
		return err
	}
	return pinnedCandidateError(s.original.LockReferences(ctx, tx, request, facts))
}
func (s *pinnedBootstrapCandidateSession) Reserve(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) error {
	request, err := s.requestCopy(ctx, r)
	if err != nil {
		return err
	}
	if !s.registriesComplete {
		return ErrRegistrationUnavailable
	}
	if candidateAuthorityNil(tx) {
		return ErrRegistrationUnavailable
	}
	facts, err := pinnedCandidateCopy(f)
	if err != nil {
		return err
	}
	return pinnedCandidateError(s.original.Reserve(ctx, tx, request, facts))
}
func (s *pinnedBootstrapCandidateSession) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	request, err := s.requestCopy(ctx, r)
	if err != nil {
		return nil, err
	}
	if !s.registriesComplete {
		return nil, ErrRegistrationUnavailable
	}
	if candidateAuthorityNil(tx) {
		return nil, ErrRegistrationUnavailable
	}
	facts, err := pinnedCandidateCopy(f)
	if err != nil {
		return nil, err
	}
	evidence, err := s.original.LockEvidence(ctx, tx, request, facts)
	if err != nil {
		return nil, pinnedCandidateError(err)
	}
	return pinnedCandidateCopy(evidence)
}
func (s *pinnedBootstrapCandidateSession) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, r pd.BootstrapConsumptionRequest, f pd.BootstrapConsumptionFacts, now time.Time) error {
	request, err := s.requestCopy(ctx, r)
	if err != nil {
		return err
	}
	if !f.Replayed && !s.registriesComplete {
		return ErrRegistrationUnavailable
	}
	start, err := s.sample(ctx, tx, now)
	if err != nil {
		return err
	}
	facts, err := pinnedCandidateCopy(f)
	if err != nil {
		return err
	}
	if err = s.original.Recheck(ctx, tx, request, facts, start); err != nil {
		return pinnedCandidateError(err)
	}
	_, err = s.sample(ctx, tx, start)
	return err
}
