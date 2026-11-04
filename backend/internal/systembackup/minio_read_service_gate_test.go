package systembackup

import (
	"context"
	"strings"
	"testing"
)

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
