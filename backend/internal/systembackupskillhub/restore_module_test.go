package systembackupskillhub

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func restoreRequestFixture() RestoreRequest {
	source, mapping := fixture()
	return RestoreRequest{
		Binding: RestoreBinding{RegistrySHA256: strings.Repeat("1", 64), SchemaSHA256: strings.Repeat("2", 64), CheckpointSHA256: strings.Repeat("3", 64), CaptureContextSHA256: strings.Repeat("4", 64), ArtifactSHA256: strings.Repeat("5", 64), TargetIdentitySHA256: strings.Repeat("6", 64), EvidenceRef: "sev_skillhub_restore"},
		Source:  source, Mapping: mapping,
		Limits: ReadLimits{MaxRows: 1000, MaxPayloadBytes: 1 << 20, MaxMappingEntries: 1000, MaxMappingBytes: 1 << 20},
	}
}

type normalizationAuthorityStub struct {
	verify, recheck func(context.Context, RestoreRequest) error
	starts, ends    int
}

func (a *normalizationAuthorityStub) VerifyNormalization(ctx context.Context, r RestoreRequest) error {
	a.starts++
	if a.verify != nil {
		return a.verify(ctx, r)
	}
	return nil
}
func (a *normalizationAuthorityStub) RecheckNormalization(ctx context.Context, r RestoreRequest) error {
	a.ends++
	if a.recheck != nil {
		return a.recheck(ctx, r)
	}
	return nil
}

func TestNormalizerAuthenticatesAndFreezesSourceAndMapping(t *testing.T) {
	request := restoreRequestFixture()
	original := cloneRestoreRequest(request)
	authority := &normalizationAuthorityStub{
		verify: func(_ context.Context, r RestoreRequest) error {
			if !reflect.DeepEqual(r, original) {
				t.Error("initial proof input mismatch")
			}
			// Both direct adapter arguments and the caller's original variables mutate.
			r.Source.Skills[0].Name = "MUTATED-COPY"
			r.Mapping.IDs["skills"][10] = 999
			*r.Mapping.BindingPaths[500].InstallPath = "mutated/path"
			request.Source.Skills[0].Name = "MUTATED-ORIGINAL"
			request.Mapping.IDs["skills"][10] = 888
			*request.Mapping.BindingPaths[500].InstallPath = "changed/parent"
			return nil
		},
		recheck: func(_ context.Context, r RestoreRequest) error {
			if !reflect.DeepEqual(r, original) {
				t.Error("final proof observed modified expectation")
			}
			r.Source.Versions[0].ManifestJSON = ptr("modified")
			return nil
		},
	}
	rows, err := (Normalizer{Authority: authority}).Normalize(context.Background(), request)
	if err != nil || !reflect.DeepEqual(rows, goldenRows(original.Source)) {
		t.Fatalf("normalization changed with proof input mutation: %v", err)
	}
	if authority.starts != 1 || authority.ends != 1 {
		t.Fatal("missing before/after proof")
	}
}
func TestNormalizerFailsClosed(t *testing.T) {
	for _, name := range []string{"nil", "typed_nil", "initial_proof", "final_proof", "canceled_initial", "canceled_final", "bad_binding", "bad_evidence", "row_capacity", "payload_capacity", "mapping_capacity", "mapping_bytes", "candidate_capacity"} {
		t.Run(name, func(t *testing.T) {
			request := restoreRequestFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stub := &normalizationAuthorityStub{}
			var authority NormalizationAuthority = stub
			want := ErrRestoreAuthority
			switch name {
			case "nil":
				authority = nil
			case "typed_nil":
				authority = (*normalizationAuthorityStub)(nil)
			case "initial_proof":
				stub.verify = func(context.Context, RestoreRequest) error { return errors.New("SECRET source credential") }
			case "final_proof":
				stub.recheck = func(context.Context, RestoreRequest) error { return errors.New("SECRET target credential") }
			case "canceled_initial":
				stub.verify = func(context.Context, RestoreRequest) error { cancel(); return nil }
				want = context.Canceled
			case "canceled_final":
				stub.recheck = func(context.Context, RestoreRequest) error { cancel(); return nil }
				want = context.Canceled
			case "bad_binding":
				request.Binding.CheckpointSHA256 = "unbound"
			case "bad_evidence":
				request.Binding.EvidenceRef = "invalid"
			case "row_capacity":
				request.Limits.MaxRows = 1
				want = ErrCapacity
			case "payload_capacity":
				request.Limits.MaxPayloadBytes = 1
				want = ErrCapacity
			case "mapping_capacity":
				request.Limits.MaxMappingEntries = 1
				want = ErrCapacity
			case "mapping_bytes":
				request.Limits.MaxMappingBytes = 1
				want = ErrCapacity
			case "candidate_capacity":
				request.Mapping.ObjectKeys["shared/demo.zip"] = strings.Repeat("x", 2000)
				request.Limits.MaxPayloadBytes = 1500
				want = ErrCapacity
			}
			rows, err := (Normalizer{Authority: authority}).Normalize(ctx, request)
			if !errors.Is(err, want) || !reflect.DeepEqual(rows, Rows{}) {
				t.Fatalf("partial result or wrong error: %v", err)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("proof error leaked")
			}
			if name == "initial_proof" || name == "canceled_initial" {
				if stub.ends != 0 {
					t.Fatal("advanced after failed initial proof")
				}
			}
		})
	}
}
