package systembackupskillhub

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
)

type verificationAuthorityStub struct {
	verify, recheck func(context.Context, VersionReader, RestoreVerificationRequest) error
}

func (a *verificationAuthorityStub) VerifyRestoreVerification(ctx context.Context, reader VersionReader, r RestoreVerificationRequest) error {
	return a.verify(ctx, reader, r)
}
func (a *verificationAuthorityStub) RecheckRestoreVerification(ctx context.Context, reader VersionReader, r RestoreVerificationRequest) error {
	return a.recheck(ctx, reader, r)
}

type workspaceVerifierFunc func(context.Context, WorkspaceVerificationRequest) error

func (f workspaceVerifierFunc) VerifySkillHubWorkspace(ctx context.Context, r WorkspaceVerificationRequest) error {
	return f(ctx, r)
}

func verificationFixture(t *testing.T) (RestoreVerificationRequest, RestoreVerifier, *restoreSQLState, *[]string) {
	t.Helper()
	r := RestoreVerificationRequest{Restore: restoreRequestFixture(), ObjectLimits: ObjectCaptureLimits{MaxObjects: 3, MaxObjectBytes: 7, MaxTotalBytes: 12, MaxIndexBytes: 8192},
		Targets: map[string]RestoredObjectLocation{}, WorkspaceEvidenceRefs: []string{"sev_workspace_fixture"}}
	bodies := map[string]string{}
	versions := map[string]string{}
	for i, item := range []struct{ source, target, body string }{{"shared/demo.zip", "restored/shared.zip", "hello"}, {"archive/v2.zip", "restored/v2.zip", "hello!!"}, {"orphan.zip", "restored/orphan.zip", ""}} {
		entry := FrozenObject{Key: item.source, VersionID: "source-v" + strconv.Itoa(i), Size: int64(len(item.body))}
		r.Inventory = append(r.Inventory, entry)
		r.Captured = append(r.Captured, CapturedObject{Object: entry, Digest: ObjectDigest{Size: entry.Size, SHA256: hashText(item.body), Properties: &ObjectProperties{
			ETag: "source-etag", LastModified: "2026-10-22T04:05:06Z", Metadata: ObjectMetadata{ContentType: "application/zip"},
		}}})
		version := "target-v" + strconv.Itoa(i)
		r.Targets[item.source] = RestoredObjectLocation{Key: item.target, VersionID: version}
		bodies["/fixture-bucket/isolated/"+item.target] = item.body
		versions["/fixture-bucket/isolated/"+item.target] = version
	}
	r.Captured[0].Digest.Properties.OmittedUserMetadata = 1
	events := []string{}
	client, err := minio.New("s3.example.invalid", &minio.Options{Region: "us-east-1", Secure: true, BucketLookup: minio.BucketLookupPath, Transport: s3Transport(func(req *http.Request) (*http.Response, error) {
		events = append(events, "object")
		body, ok := bodies[req.URL.Path]
		if !ok || req.Method != "GET" || req.URL.Query().Get("versionId") != versions[req.URL.Path] {
			t.Error("wrong isolated target or immutable version")
		}
		h := http.Header{"Content-Length": {strconv.Itoa(len(body))}, "Content-Type": {"application/zip"}, "Etag": {`"new-target-etag"`}, "Last-Modified": {"Mon, 26 Oct 2026 04:05:06 GMT"}, "X-Amz-Version-Id": {versions[req.URL.Path]}}
		return &http.Response{StatusCode: 200, Header: h, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewS3VersionReader(client, "fixture-bucket", "isolated")
	if err != nil {
		t.Fatal(err)
	}
	state := &restoreSQLState{target: goldenRows(r.Restore.Source)}
	original := cloneVerificationRequest(r)
	verifier := RestoreVerifier{
		SQL: SQLRestoreVerifier{DB: restoreSQLDB(t, state), Authority: &targetReadAuthorityStub{verify: func(context.Context, ReadOnlyQueries, RestoreRequest) error {
			events = append(events, "sql")
			return nil
		}}},
		Objects: reader,
		Workspace: workspaceVerifierFunc(func(_ context.Context, request WorkspaceVerificationRequest) error {
			events = append(events, "workspace")
			if !reflect.DeepEqual(request.Restore, original.Restore) || !reflect.DeepEqual(request.UnpackagedBlobIDs, []int{1002}) || !reflect.DeepEqual(request.EvidenceRefs, []string{"sev_workspace_fixture"}) {
				t.Error("workspace proof lost binding or coverage")
			}
			return nil
		}),
		Authority: &verificationAuthorityStub{
			verify: func(_ context.Context, reader VersionReader, request RestoreVerificationRequest) error {
				events = append(events, "authority")
				if nilObjectAdapter(reader) || !reflect.DeepEqual(request, original) {
					t.Error("initial authority lost complete request/reader")
				}
				return nil
			},
			recheck: func(_ context.Context, reader VersionReader, request RestoreVerificationRequest) error {
				events = append(events, "recheck")
				if nilObjectAdapter(reader) || !reflect.DeepEqual(request, original) {
					t.Error("final authority lost complete request/reader")
				}
				return nil
			},
		},
	}
	return r, verifier, state, &events
}

func TestRestoreVerifierRunsSQLObjectsWorkspaceAndPreservesWarnings(t *testing.T) {
	r, v, _, events := verificationFixture(t)
	// Execute the real SQLRestorer over the database/sql fixture first, then read
	// its committed target via an independent read pool and the combined verifier.
	state := &writeSQLState{}
	if err := (SQLRestorer{DB: writeSQLDB(t, state), Authority: &writeAuthorityStub{}}).Restore(context.Background(), r.Restore); err != nil {
		t.Fatal(err)
	}
	writes := state.base.observed().writes
	v.SQL.DB = restoreSQLDB(t, &state.base)
	got, err := v.Verify(context.Background(), r)
	want := RestoreVerificationSummary{SQLRows: 24, Objects: 3, WorkspaceBindings: 3, UnpackagedBlobs: 1, ObjectsWithOmittedMetadata: 1}
	if err != nil || got != want {
		t.Fatalf("summary=%+v error=%v", got, err)
	}
	if !reflect.DeepEqual(*events, []string{"authority", "sql", "object", "object", "object", "workspace", "recheck"}) {
		t.Fatalf("stage order=%v", *events)
	}
	audit := state.base.observed()
	if writes != 29 || audit.writes != writes || !audit.options.ReadOnly {
		t.Fatal("verification performed writes or shared writer credentials")
	}
}

func TestRestoreVerifierFreezesInputsAcrossCallbacks(t *testing.T) {
	r, v, _, _ := verificationFixture(t)
	proof := v.Authority.(*verificationAuthorityStub)
	initial := proof.verify
	proof.verify = func(ctx context.Context, reader VersionReader, copy RestoreVerificationRequest) error {
		if err := initial(ctx, reader, copy); err != nil {
			return err
		}
		copy.Restore.Source.Skills[0].Name = "SECRET callback mutation"
		copy.Captured[0].Digest.Properties.Metadata.ContentType = "wrong"
		copy.Targets["shared/demo.zip"] = RestoredObjectLocation{Key: "wrong"}
		copy.WorkspaceEvidenceRefs[0] = "wrong"
		r.Restore.Source.Skills[0].Name = "SECRET caller mutation"
		r.Captured[1].Digest.Properties.Metadata.ContentType = "wrong"
		r.Inventory[0].VersionID = "wrong"
		r.WorkspaceEvidenceRefs[0] = "wrong"
		return nil
	}
	workspace := v.Workspace
	v.Workspace = workspaceVerifierFunc(func(ctx context.Context, copy WorkspaceVerificationRequest) error {
		if err := workspace.VerifySkillHubWorkspace(ctx, copy); err != nil {
			return err
		}
		copy.Restore.Mapping.ObjectKeys["shared/demo.zip"] = "wrong"
		copy.UnpackagedBlobIDs[0] = 999
		copy.EvidenceRefs[0] = "wrong"
		return nil
	})
	if got, err := v.Verify(context.Background(), r); err != nil || got.SQLRows != 24 {
		t.Fatalf("callback changed expected data: %+v %v", got, err)
	}
}

func TestRestoreVerifierRejectsMissingCapabilitiesAndBadPreflightBeforeIO(t *testing.T) {
	for _, mode := range []string{"authority", "typed_authority", "workspace", "typed_workspace", "objects", "typed_objects", "SQL", "SQL_authority", "missing_evidence", "duplicate_evidence", "bad_evidence", "evidence_capacity", "object_mapping", "late_metadata", "captured_selector_metadata"} {
		t.Run(mode, func(t *testing.T) {
			r, v, state, events := verificationFixture(t)
			switch mode {
			case "authority":
				v.Authority = nil
			case "typed_authority":
				var p *verificationAuthorityStub
				v.Authority = p
			case "workspace":
				v.Workspace = nil
			case "typed_workspace":
				var f workspaceVerifierFunc
				v.Workspace = f
			case "objects":
				v.Objects = nil
			case "typed_objects":
				var f objectReaderFunc
				v.Objects = f
			case "SQL":
				v.SQL.DB = nil
			case "SQL_authority":
				v.SQL.Authority = nil
			case "missing_evidence":
				r.WorkspaceEvidenceRefs = nil
			case "duplicate_evidence":
				r.WorkspaceEvidenceRefs = append(r.WorkspaceEvidenceRefs, r.WorkspaceEvidenceRefs[0])
			case "bad_evidence":
				r.WorkspaceEvidenceRefs[0] = "SECRET invalid"
			case "evidence_capacity":
				r.WorkspaceEvidenceRefs = []string{strings.Repeat("s", int(r.Restore.Limits.MaxMappingBytes)+1)}
			case "object_mapping":
				r.Targets["shared/demo.zip"] = RestoredObjectLocation{Key: "wrong", VersionID: "v"}
			case "late_metadata":
				r.Captured[2].Digest.Properties = nil
			case "captured_selector_metadata":
				r.Captured[2].Object.Metadata = &ObjectMetadata{ContentType: strings.Repeat("x", MaxObjectMetadataBytes)}
			}
			got, err := v.Verify(context.Background(), r)
			if err == nil || got != (RestoreVerificationSummary{}) || strings.Contains(err.Error(), "SECRET") || len(*events) != 0 || state.observed().begins != 0 {
				t.Fatalf("preflight escaped: %+v %v stages=%v", got, err, *events)
			}
		})
	}
}

func TestRestoreVerifierStopsOnFailureWithoutPartialSuccess(t *testing.T) {
	for _, mode := range []string{"initial", "sql", "sql_rows", "object", "workspace", "final", "cancel_initial", "cancel_object", "cancel_workspace", "cancel_final"} {
		t.Run(mode, func(t *testing.T) {
			r, v, state, events := verificationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proof := v.Authority.(*verificationAuthorityStub)
			failure := errors.New("SECRET proof or provider error")
			want := ErrRestoreAuthority
			switch mode {
			case "initial":
				proof.verify = func(context.Context, VersionReader, RestoreVerificationRequest) error { return failure }
			case "sql":
				v.SQL.Authority = &targetReadAuthorityStub{verify: func(context.Context, ReadOnlyQueries, RestoreRequest) error { return failure }}
			case "sql_rows":
				state.target.Skills[0].Name = "target drift"
				want = ErrMismatch
			case "object":
				v.Objects = objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) { return ObjectVersion{}, failure })
				want = ErrObjectIO
			case "workspace":
				v.Workspace = workspaceVerifierFunc(func(context.Context, WorkspaceVerificationRequest) error { return failure })
				want = ErrWorkspaceProof
			case "final":
				proof.recheck = func(context.Context, VersionReader, RestoreVerificationRequest) error { return failure }
			case "cancel_initial":
				proof.verify = func(context.Context, VersionReader, RestoreVerificationRequest) error { cancel(); return nil }
			case "cancel_object":
				v.Objects = objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
					cancel()
					return ObjectVersion{}, ctx.Err()
				})
			case "cancel_workspace":
				v.Workspace = workspaceVerifierFunc(func(context.Context, WorkspaceVerificationRequest) error { cancel(); return nil })
			case "cancel_final":
				proof.recheck = func(context.Context, VersionReader, RestoreVerificationRequest) error { cancel(); return nil }
			}
			if strings.HasPrefix(mode, "cancel_") {
				want = context.Canceled
			}
			got, err := v.Verify(ctx, r)
			if !errors.Is(err, want) || got != (RestoreVerificationSummary{}) || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("partial/leaking result=%+v err=%v", got, err)
			}
			for _, event := range *events {
				if event == "recheck" {
					t.Fatal("advanced past failed stage")
				}
			}
		})
	}
}

func TestRestoreVerifierChecksEmptyDomainWithoutSkippingAuthority(t *testing.T) {
	r, v, state, events := verificationFixture(t)
	r.Restore.Source = Rows{}
	r.Restore.Mapping = RestoreMapping{IDs: map[string]map[int]int{"users": {}, "instances": {}}}
	for _, table := range tables(Rows{}) {
		r.Restore.Mapping.IDs[table.name] = map[int]int{}
	}
	r.Inventory, r.Captured, r.Targets, r.WorkspaceEvidenceRefs = nil, nil, nil, nil
	r.ObjectLimits = ObjectCaptureLimits{MaxIndexBytes: 2}
	state.target = Rows{}
	v.Objects = objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
		t.Fatal("empty prefix attempted an object read")
		return ObjectVersion{}, nil
	})
	v.Authority = &verificationAuthorityStub{
		verify: func(context.Context, VersionReader, RestoreVerificationRequest) error {
			*events = append(*events, "authority")
			return nil
		},
		recheck: func(context.Context, VersionReader, RestoreVerificationRequest) error {
			*events = append(*events, "recheck")
			return nil
		},
	}
	v.Workspace = workspaceVerifierFunc(func(_ context.Context, r WorkspaceVerificationRequest) error {
		*events = append(*events, "workspace")
		if len(r.UnpackagedBlobIDs) != 0 || len(r.EvidenceRefs) != 0 || len(r.Restore.Source.Bindings) != 0 {
			t.Fatal("invented workspace coverage")
		}
		return nil
	})
	got, err := v.Verify(context.Background(), r)
	if err != nil || got != (RestoreVerificationSummary{}) || !reflect.DeepEqual(*events, []string{"authority", "sql", "workspace", "recheck"}) {
		t.Fatalf("empty verification=%+v error=%v events=%v", got, err, *events)
	}
	if audit := state.observed(); audit.commits != 1 || len(audit.queries) != 24 {
		t.Fatal("skipped empty SQL tables")
	}
}
