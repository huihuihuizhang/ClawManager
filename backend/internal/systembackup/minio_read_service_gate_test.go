package systembackup

import (
	"context"
	"strings"
	"testing"

	mn "clawreef/internal/systembackup/minionative"
)

func TestMinIOReadGateRetiredOPARequiresExplicitCompatNull(t *testing.T) {
	const observed = `{"status":"success","config":[{"subSystem":"policy_opa","kv":null}]}`
	if _, err := decodeMinioGateConfig([]byte(observed), "policy_opa", mn.DeleteCompatManifest); err != nil {
		t.Fatal("pinned MinIO retired OPA response refused", err)
	}
	for _, tc := range []struct{ raw, subsystem, image string }{
		{observed, "policy_opa", ""},
		{strings.Replace(observed, `,"kv":null`, "", 1), "policy_opa", mn.DeleteCompatManifest},
		{strings.Replace(observed, "null", "[]", 1), "policy_opa", mn.DeleteCompatManifest},
		{strings.Replace(observed, "policy_opa", "policy_plugin", 1), "policy_plugin", mn.DeleteCompatManifest},
		{strings.Replace(observed, `"kv":null`, `"target":"other","kv":null`, 1), "policy_opa", mn.DeleteCompatManifest},
	} {
		if _, err := decodeMinioGateConfig([]byte(tc.raw), tc.subsystem, tc.image); err == nil {
			t.Fatalf("unqualified empty native config allowed: %s", tc.raw)
		}
	}
}

func TestMinIOReadServiceNativeGlobalResourceReadback(t *testing.T) {
	keeper, _, err := MinIOReadGatePolicies([]string{"business"})
	if err != nil {
		t.Fatal(err)
	}
	native := []byte(strings.ReplaceAll(string(keeper), `["*"]`, `["**"]`))
	if !OriginalMinIOReadGatePoliciesMatch(keeper, native) {
		t.Fatal("native global resources changed the policy comparison")
	}
	widened := []byte(strings.Replace(string(native), `"arn:aws:s3:::business"`, `"**"`, 1))
	if OriginalMinIOReadGatePoliciesMatch(keeper, widened) {
		t.Fatal("native comparison accepted a widened bucket scope")
	}
}

func TestMinIOReadServicePolicyProtectsActualBusinessScope(t *testing.T) {
	k, r, e := MinIOReadGatePolicies([]string{"business"})
	if e != nil || !minioGateSamePolicy(k, k) || !minioGateSamePolicy(r, r) || minioGateSamePolicy(k, r) {
		t.Fatal("finite keeper/reader policy data failed")
	}
	for _, x := range []struct {
		name, raw string
		ok        bool
	}{
		{"other-output", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::backups/installation/*"]}]}`, true},
		{"business-write", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::business/*"]}]}`, false},
		{"wildcard-bucket", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::*/*"]}]}`, false},
		{"admin-mutation", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"],"Resource":["*"]}]}`, false},
		{"unknown-condition", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"],"Condition":{}}]}`, false},
	} {
		t.Run(x.name, func(t *testing.T) {
			if minioGateOutputPolicy([]byte(x.raw), []string{"business"}) != x.ok {
				t.Fatal("source mutation escaped exact actual policy check")
			}
		})
	}
}
func TestMinIOReadServiceDrainRequiresCompleteNativeMetricFrame(t *testing.T) {
	base := "minio_api_requests_total{name=\"ListBuckets\",type=\"s3\"} 2\n"
	zero, e := minioGateDrainedMetrics([]byte(base))
	if e != nil || !zero {
		t.Fatal("pinned zero-omission contract failed")
	}
	zero, e = minioGateDrainedMetrics([]byte(base + "minio_api_requests_inflight_total{name=\"PutObject\",type=\"s3\"} 1\n"))
	if e != nil || zero {
		t.Fatal("accepted source write was considered drained")
	}
	for _, raw := range []string{"", strings.TrimSuffix(base, "\n"), base + base, "minio_api_requests_waiting_total{type=\"s3\"} 0\n", base + "minio_api_requests_inflight_total{type=\"s3\"} NaN\n", base + "broken\n"} {
		if _, e := minioGateDrainedMetrics([]byte(raw)); e == nil {
			t.Fatal("partial/unknown metrics became zero")
		}
	}
}
func TestMinIOReadServiceRejectsUnboundAndUnknownInputs(t *testing.T) {
	if _, e := PrepareMinIOReadServiceGate(context.Background(), nil, MinIOReadGateInput{}, MinIOGateCredential{}, MinIOGateCredential{}, MinIOGateCredential{}, nil, nil); e == nil {
		t.Fatal("unbound original source became gate")
	}
	for _, raw := range []string{`{"k":1,"k":2}`, `{} {}`, `{"status":"success","unknown":1}`} {
		var x struct{ Status string }
		if minioGateDecode([]byte(raw), &x) == nil {
			t.Fatal("unknown native format accepted")
		}
	}
	v := &VerifiedMinIOReadServiceObservation{}
	if v.Data().Version != "" {
		t.Fatal("zero observation became native result")
	}
}

func TestMinIOGatePolicyReadbackSortsOnlyPolicySets(t *testing.T) {
	current := []byte(`{"Version":"2012-10-17","Statement":[{"Sid":"fixed","Effect":"Deny","Action":["s3:PutObject","s3:DeleteObject"],"Resource":["arn:aws:s3:::b/*","arn:aws:s3:::a/*"],"Condition":{"StringEquals":{"s3:prefix":["private","staff"]}}}]}`)
	reordered := []byte(`{"Statement":[{"Effect":"Deny","Sid":"fixed","Action":["s3:DeleteObject","s3:PutObject"],"Resource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"],"Condition":{"StringEquals":{"s3:prefix":["private","staff"]}}}],"Version":"2012-10-17"}`)
	if !minioGatePolicyReadbackEqual(current, reordered) {
		t.Fatal("equivalent MinIO readbacks differ")
	}
	for _, changed := range [][]byte{
		[]byte(`{"Statement":[{"Effect":"Deny","Sid":"fixed","Action":["s3:DeleteObject","s3:PutObject"],"Resource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"],"Condition":{"StringEquals":{"s3:prefix":["private","other"]}}}],"Version":"2012-10-17"}`),
		[]byte(`{"Statement":[{"Effect":"Allow","Sid":"fixed","Action":["s3:DeleteObject","s3:PutObject"],"Resource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"],"Condition":{"StringEquals":{"s3:prefix":["private","staff"]}}}],"Version":"2012-10-17"}`),
	} {
		if minioGatePolicyReadbackEqual(current, changed) {
			t.Fatal("different MinIO policy accepted as equivalent")
		}
	}
}
