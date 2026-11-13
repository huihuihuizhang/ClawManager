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
