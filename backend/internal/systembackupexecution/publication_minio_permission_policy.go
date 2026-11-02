package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// No general IAM interpreter is invented. This version profile accepts only
// a closed positive subset: exact actions/resources, no Deny, Principal,
// NotAction/NotResource, conditions, inheritance or policy variables. A Deny or
// unknown form refuses the whole observation, never drops a statement.
type minioPermissionRule struct{ Actions, Resources []string }

func minioPermissionUniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return minioPermissionFailure("native-json-limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return minioPermissionFailure("native-json-shape")
		}
		seen := map[string]bool{}
		n := 0
		for d.More() {
			n++
			if n > 256 {
				return minioPermissionFailure("native-json-limit")
			}
			if delim == '{' {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return minioPermissionFailure("native-json-duplicate")
				}
				seen[s] = true
			}
			if err := visit(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := visit(0); err != nil {
		return minioPermissionFailure("native-json-shape")
	}
	if _, err := d.Token(); err != io.EOF {
		return minioPermissionFailure("native-json-trailing")
	}
	return nil
}

func minioPermissionStrings(raw json.RawMessage) ([]string, error) {
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		var single string
		if json.Unmarshal(raw, &single) != nil {
			return nil, minioPermissionFailure("policy-set")
		}
		list = []string{single}
	}
	if len(list) == 0 || len(list) > 16 {
		return nil, minioPermissionFailure("policy-set")
	}
	seen := map[string]bool{}
	for _, s := range list {
		if s == "" || len(s) > 512 || seen[s] || strings.ContainsAny(s, "\x00\r\n${?") {
			return nil, minioPermissionFailure("policy-set")
		}
		seen[s] = true
	}
	return list, nil
}

func minioPermissionPolicy(raw []byte, expectedSHA string, expected []minioPermissionRule) error {
	if minioPermissionUniqueJSON(raw) != nil {
		return minioPermissionFailure("policy-json")
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || hash(canonical) != expectedSHA {
		return minioPermissionFailure("original-policy-hash")
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(raw, &document) != nil || len(document) < 2 || len(document) > 3 {
		return minioPermissionFailure("policy-profile")
	}
	for key := range document {
		if key != "Version" && key != "Statement" && key != "Id" {
			return minioPermissionFailure("policy-profile")
		}
	}
	var version string
	var statements []map[string]json.RawMessage
	if json.Unmarshal(document["Version"], &version) != nil || version != "2012-10-17" || json.Unmarshal(document["Statement"], &statements) != nil || len(statements) == 0 || len(statements) > 8 {
		return minioPermissionFailure("policy-profile")
	}
	allowed := map[string]bool{}
	have := map[string]bool{}
	for _, rule := range expected {
		for _, action := range rule.Actions {
			for _, resource := range rule.Resources {
				allowed[action+"\x00"+resource] = true
			}
		}
	}
	for _, statement := range statements {
		for key := range statement {
			if key != "Effect" && key != "Action" && key != "Resource" && key != "Sid" {
				return minioPermissionFailure("policy-profile")
			}
		}
		var effect string
		if json.Unmarshal(statement["Effect"], &effect) != nil || effect != "Allow" {
			return minioPermissionFailure("policy-deny-or-unknown-effect")
		}
		actions, err := minioPermissionStrings(statement["Action"])
		if err != nil {
			return err
		}
		resources, err := minioPermissionStrings(statement["Resource"])
		if err != nil {
			return err
		}
		for _, action := range actions {
			for _, resource := range resources {
				key := action + "\x00" + resource
				if !allowed[key] {
					return minioPermissionFailure("policy-broader-or-unsupported")
				}
				have[key] = true
			}
		}
	}
	for key := range allowed {
		if !have[key] {
			return minioPermissionFailure("policy-required-action-missing")
		}
	}
	return nil
}

func minioPermissionObjectRules(purpose, bucket, root, staging string) ([]minioPermissionRule, error) {
	for _, prefix := range []string{root, staging} {
		if prefix != "" && (!strings.HasSuffix(prefix, "/") || strings.ContainsAny(prefix, "*?[]\\\x00\r\n") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "../")) {
			return nil, minioPermissionFailure("original-prefix")
		}
	}
	if bucket == "" || root == "" {
		return nil, minioPermissionFailure("original-prefix")
	}
	resources := []string{"arn:aws:s3:::" + bucket + "/" + root + "*"}
	if strings.HasPrefix(purpose, "artifact_") && staging != "" {
		resources = append(resources, "arn:aws:s3:::"+bucket+"/"+staging+"*")
	}
	actions := []string{}
	switch purpose {
	case "artifact_read", "catalog_read":
		actions = []string{"s3:GetObject", "s3:GetObjectVersion"}
	case "artifact_write", "catalog_append":
		actions = []string{"s3:PutObject"}
	case "artifact_delete":
		if staging == "" {
			return nil, minioPermissionFailure("original-delete-prefix")
		}
		actions = []string{"s3:DeleteObjectVersion"}
		resources = []string{"arn:aws:s3:::" + bucket + "/" + staging + "*"}
	default:
		return nil, minioPermissionFailure("original-purpose")
	}
	sort.Strings(resources)
	return []minioPermissionRule{{actions, resources}}, nil
}
