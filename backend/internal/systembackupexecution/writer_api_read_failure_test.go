package systembackupexecution

import (
	"context"
	"errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"strings"
	"testing"
)

func TestWriterAPIReadFailureClassificationAndPrivacy(t *testing.T) {
	for _, tc := range []struct {
		observed error
		reason   string
	}{
		{nil, "validation"}, {context.DeadlineExceeded, "deadline"},
		{apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "private-name", errors.New("secret-token")), "forbidden"},
		{errors.New("secret-token"), "read_error"},
	} {
		err := writerAPIReadFailure(ErrSourceWriterObservationIncomplete, context.Background(), "system_list", "Pod", tc.observed)
		var failure *WriterAPIReadFailure
		if !errors.As(err, &failure) || failure.Reason != tc.reason || !errors.Is(err, ErrSourceWriterObservationIncomplete) || strings.Contains(err.Error(), "secret") {
			t.Fatal("classification changed semantics or exposed upstream error")
		}
		if writerAPIReadFailure(err, context.Background(), "outer", "", nil) != err {
			t.Fatal("nested diagnostic lost")
		}
	}
	if writerAPIReadFailure(nil, context.Background(), "unused", "", nil) != nil {
		t.Fatal("success changed")
	}
}

// The native author classifies before closing its read authority. The outer
// phase wrapper must retain that reason after Close cancels the child context.
func TestWriterFailureClassificationBeforeAuthorityCleanup(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		observed := errors.New("private failure")
		expected := "read_error"
		if deadline {
			observed = context.DeadlineExceeded
			expected = "deadline"
		}
		run := func() (result error) {
			defer func() { result = writerAPIReadFailure(result, ctx, "outer", "MountMaterials", result) }()
			defer cancel()
			defer func() { result = writerAPIReadFailure(result, ctx, "longhorn_sources", "MountMaterials", result) }()
			return observed
		}
		err := run()
		var failure *WriterAPIReadFailure
		if ctx.Err() != context.Canceled || !errors.As(err, &failure) || failure.Reason != expected || failure.Step != "longhorn_sources" || !errors.Is(err, observed) {
			t.Fatalf("cleanup hid original refusal: %v", err)
		}
	}
}
