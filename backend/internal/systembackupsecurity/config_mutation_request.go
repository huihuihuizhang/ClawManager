package systembackupsecurity

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const ConfigUpdateEndpoint = "updateSystemBackupConfig"
const ConfigRollbackEndpoint = "rollbackSystemBackupConfig"
const ConfigMutationRequestHashProfile = "a-config-mutation-request-hash.v1"

// ConfigMutationRequest contains only strict business input. Proof, session,
// request ID and idempotency key belong to separately bound trusted transport.
// Parsing/classification never grants permission or consumes a nonce/key.
type ConfigMutationRequest struct {
	endpoint                             string
	expectedVersion, rollbackFromVersion int64
	reason                               *string
	config                               ConfigValues
	canonical                            []byte
}

func (r ConfigMutationRequest) Endpoint() string           { return r.endpoint }
func (r ConfigMutationRequest) ExpectedVersion() int64     { return r.expectedVersion }
func (r ConfigMutationRequest) RollbackFromVersion() int64 { return r.rollbackFromVersion }
func (r ConfigMutationRequest) Config() ConfigValues       { return r.config }
func (r ConfigMutationRequest) ChangeReason() *string {
	if r.reason == nil {
		return nil
	}
	copy := *r.reason
	return &copy
}
func (r ConfigMutationRequest) CanonicalJSON() []byte { return append([]byte(nil), r.canonical...) }

func DecodeConfigMutationRequest(endpoint string, raw []byte) (ConfigMutationRequest, error) {
	fail := func() (ConfigMutationRequest, error) { return ConfigMutationRequest{}, ErrConfigMutation }
	if (endpoint != ConfigUpdateEndpoint && endpoint != ConfigRollbackEndpoint) || len(raw) < 2 || len(raw) > 262144 ||
		!json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 {
		return fail()
	}
	third := "config"
	if endpoint == ConfigRollbackEndpoint {
		third = "rollback_from_version"
	}
	for _, key := range []string{"expected_version", "change_reason", third} {
		if _, ok := fields[key]; !ok {
			return fail()
		}
	}
	decodeVersion := func(raw json.RawMessage) (int64, bool) {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var v any
		if d.Decode(&v) != nil {
			return 0, false
		}
		n, ok := v.(json.Number)
		if !ok {
			return 0, false
		}
		return bootstrapNumber(n, bootstrapNumberRule{Min: 1, Max: 9007199254740991, Scale: 1})
	}
	r := ConfigMutationRequest{endpoint: endpoint}
	var ok bool
	r.expectedVersion, ok = decodeVersion(fields["expected_version"])
	if !ok {
		return fail()
	}
	var reason *string
	if json.Unmarshal(fields["change_reason"], &reason) != nil || (reason != nil && len(*reason) > 512) {
		return fail()
	}
	r.reason = reason
	request := map[string]any{"expected_version": json.Number(fieldsVersion(r.expectedVersion)), "change_reason": nil}
	if reason != nil {
		request["change_reason"] = *reason
	}
	if endpoint == ConfigUpdateEndpoint {
		var err error
		r.config, err = DecodeConfigValues(fields["config"])
		if err != nil {
			return fail()
		}
		d := json.NewDecoder(bytes.NewReader(r.config.CanonicalJSON()))
		d.UseNumber()
		var config any
		if d.Decode(&config) != nil {
			return fail()
		}
		request["config"] = config
	} else {
		r.rollbackFromVersion, ok = decodeVersion(fields[third])
		if !ok {
			return fail()
		}
		request[third] = json.Number(fieldsVersion(r.rollbackFromVersion))
	}
	var canonical strings.Builder
	canonicalMutationJSON(&canonical, request)
	r.canonical = []byte(canonical.String())
	if len(r.canonical) > 262144 {
		return fail()
	}
	return r, nil
}

var configMutationInstallation = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var configMutationActor = regexp.MustCompile(`^[0-9]{1,128}$`)

// RequestHash implements A's reviewed JCS domain profile. Actor and installation
// must be independently authenticated by the writer, not trusted from an HTTP body.
func (r ConfigMutationRequest) RequestHash(installation, actorType, actorID string) (string, error) {
	validActor := (actorType == "admin" && configMutationActor.MatchString(actorID)) || (actorType == "system" && actorID == "system:controller")
	if !configMutationInstallation.MatchString(installation) || !validActor || len(r.canonical) < 2 {
		return "", ErrConfigMutation
	}
	method := "PUT"
	if r.endpoint == ConfigRollbackEndpoint {
		method = "POST"
	} else if r.endpoint != ConfigUpdateEndpoint {
		return "", ErrConfigMutation
	}
	d := json.NewDecoder(bytes.NewReader(r.canonical))
	d.UseNumber()
	var request any
	if d.Decode(&request) != nil {
		return "", ErrConfigMutation
	}
	input := map[string]any{"domain": "clawmanager.system-backup.config-mutation.v1", "origin_installation_id": installation,
		"actor_type": actorType, "actor_id": actorID, "endpoint": r.endpoint, "method": method, "request": request}
	var canonical strings.Builder
	canonicalMutationJSON(&canonical, input)
	return registrationHash(canonical.String()), nil
}

// Effective ConfigValues use only fixed ASCII object keys. Request wrappers
// also use fixed ASCII keys but permit a nullable reason, which bootstrap's
// canonicalizer deliberately does not need to encode.
func canonicalMutationJSON(out *strings.Builder, value any) {
	if value == nil {
		out.WriteString("null")
		return
	}
	// Add null support recursively without broadening accepted input types.
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			out.WriteString(jcsString(k))
			out.WriteByte(':')
			canonicalMutationJSON(out, v[k])
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, x := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			canonicalMutationJSON(out, x)
		}
		out.WriteByte(']')
	default:
		bootstrapCanonical(out, value)
	}
}

func fieldsVersion(version int64) string { return strconv.FormatInt(version, 10) }
