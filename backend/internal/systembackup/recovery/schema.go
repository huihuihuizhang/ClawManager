package recovery

import (
	"encoding/json"
	"reflect"
	"strings"
)

// SchemaBytes emits the reviewable closed JSON schemas for the public recovery
// documents. contracts.schema.json is checked in; tests reject unreviewed drift.
// Semantic cross-document/identity/cryptographic constraints remain in Validate.
func SchemaBytes() ([]byte, error) {
	defs := map[string]any{}
	var schema func(reflect.Type) map[string]any
	schema = func(t reflect.Type) map[string]any {
		if t == reflect.TypeOf(json.RawMessage{}) {
			return map[string]any{}
		}
		if t.Kind() == reflect.Pointer {
			return schema(t.Elem())
		}
		switch t.Kind() {
		case reflect.Struct:
			name := t.Name()
			if _, ok := defs[name]; !ok {
				defs[name] = map[string]any{}
				props := map[string]any{}
				required := []string{}
				for i := 0; i < t.NumField(); i++ {
					f := t.Field(i)
					tag := strings.Split(f.Tag.Get("json"), ",")
					key := tag[0]
					if key == "" {
						key = f.Name
					}
					if key == "-" {
						continue
					}
					props[key] = schema(f.Type)
					if len(tag) < 2 || tag[1] != "omitempty" {
						required = append(required, key)
					}
				}
				defs[name] = map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": required}
			}
			return map[string]any{"$ref": "#/$defs/" + name}
		case reflect.Map:
			return map[string]any{"type": "object", "additionalProperties": schema(t.Elem())}
		case reflect.Slice:
			if t.Elem().Kind() == reflect.Uint8 {
				return map[string]any{"type": "string", "contentEncoding": "base64"}
			}
			return map[string]any{"type": "array", "items": schema(t.Elem())}
		case reflect.Bool:
			return map[string]any{"type": "boolean"}
		case reflect.Int, reflect.Int64:
			return map[string]any{"type": "integer", "minimum": -9007199254740991, "maximum": 9007199254740991}
		case reflect.Uint32:
			return map[string]any{"type": "integer", "minimum": 0, "maximum": 4294967295}
		default:
			return map[string]any{"type": "string"}
		}
	}
	for _, v := range []any{Manifest{}, Index{}, Marker{}, Acceptance{}, Record{}, Header{}, Signature{}, Request{}, ProviderConfig{}, Capability{}, CaptureRequest{}, PartResult{}, RedisPolicy{}, RedisItem{}, Snapshot{}, Page{}, ScanState{}, ScanPage{}, PrunePlan{}, DeletionProof{}, GatewayConfig{}, GatewayServerConfig{}, GatewayRequest{}, GatewayResponse{}, CodecDescriptor{}} {
		schema(reflect.TypeOf(v))
	}
	for _, name := range []string{"Manifest", "Index", "Marker", "Acceptance", "Record", "Header"} {
		d := defs[name].(map[string]any)
		props := d["properties"].(map[string]any)
		props["schema_version"] = map[string]any{"const": Version}
	}
	props := defs["Manifest"].(map[string]any)["properties"].(map[string]any)
	for _, v := range []struct {
		name string
		keys []string
		def  string
	}{{"parts", RequiredParts(), "PartSummary"}, {"business_domains", SixDomains(), "Summary"}} {
		fields := map[string]any{}
		for _, k := range v.keys {
			fields[k] = map[string]any{"$ref": "#/$defs/" + v.def}
		}
		props[v.name] = map[string]any{"type": "object", "additionalProperties": false, "properties": fields, "required": v.keys}
	}
	props["purpose"] = map[string]any{"enum": []string{"acceptance", "functional_test"}}
	props["consistency_class"] = map[string]any{"enum": []string{"strong", "bounded"}}
	h := defs["Header"].(map[string]any)["properties"].(map[string]any)
	h["algorithm"] = map[string]any{"const": "Ed25519"}
	h["purpose"] = map[string]any{"enum": []string{string(ManifestPurpose), string(AcceptancePurpose), string(CatalogPurpose)}}
	defs["Record"].(map[string]any)["oneOf"] = []any{map[string]any{"required": []string{"registration"}, "properties": map[string]any{"record_type": map[string]any{"const": "artifact_registered"}}, "not": map[string]any{"required": []string{"deletion"}}}, map[string]any{"required": []string{"deletion"}, "properties": map[string]any{"record_type": map[string]any{"const": "artifact_deleted"}}, "not": map[string]any{"required": []string{"registration"}}}}
	for _, v := range []struct{ name, payload, purpose string }{{"SignedManifest", "Manifest", string(ManifestPurpose)}, {"SignedAcceptance", "Acceptance", string(AcceptancePurpose)}, {"SignedCatalogRecord", "Record", string(CatalogPurpose)}} {
		defs[v.name] = map[string]any{"type": "object", "additionalProperties": false, "required": []string{"payload", "signature"}, "properties": map[string]any{"payload": map[string]any{"$ref": "#/$defs/" + v.payload}, "signature": map[string]any{"allOf": []any{map[string]any{"$ref": "#/$defs/Signature"}, map[string]any{"properties": map[string]any{"protected": map[string]any{"properties": map[string]any{"purpose": map[string]any{"const": v.purpose}}}}}}}}}
	}
	return json.MarshalIndent(map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:clawmanager:system-backup.v1:recovery", "title": "Six-domain artifact and recovery catalog contract", "$defs": defs}, "", "  ")
}
