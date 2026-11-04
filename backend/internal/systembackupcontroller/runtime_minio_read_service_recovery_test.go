package systembackupcontroller

import (
	"context"
	"encoding/json"
	"testing"

	sb "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

func TestMinIORecoveryCannotComeFromPublicFacts(t *testing.T) {
	if _, e := minioReadServiceFacts(SourceRecoveryObservation{Scope: MinIOReadServiceRecoveryScope, Facts: json.RawMessage(`{"Version":"source-recovery-minio-native-iam.v1","Kind":"minio_read_service"}`)}); e == nil {
		t.Fatal("empty public facts accepted")
	}
	if _, e := NewMinIOReadServiceRecoveryObservation(context.Background(), d.Authority{}, b.FrozenWriter{}, MinIOReadServiceRecoveryFacts{}, &sb.VerifiedMinIOReadServiceObservation{}); e == nil {
		t.Fatal("zero native handle became source recovery")
	}
}
