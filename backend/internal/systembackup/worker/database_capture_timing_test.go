package worker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
)

func TestDatabaseCaptureTimingFailureUsesOriginalChecksAndNoPrivateValues(t *testing.T) {
	for _, refusal := range []int{1, 2, 0} {
		i, env, key := formalInvocationFixture(t)
		i.Request.Operation, i.WorkspacePath = "capture-database", ""
		i.Request.Database = databaseRequestFixture(t).Request.Database
		i.Request.MaxFiles, i.Request.MaxFileBytes, i.Request.Files = 0, 0, nil
		connector := &databaseDiagnosticNoConnect{}
		env.Database = sql.OpenDB(connector)
		defer env.Database.Close()
		const secret = "PRIVATE_SOURCE_PASSWORD_TOKEN_ERROR_BODY"
		sourceChecks := 0
		env.SourceAuthorize = func(context.Context, Invocation) error {
			sourceChecks++
			if sourceChecks == refusal {
				return errors.New(secret)
			}
			return nil
		}
		var output bytes.Buffer
		previous := log.Writer()
		log.SetOutput(&output)
		result, err := runFormalCapture(context.Background(), i, key, env)
		log.SetOutput(previous)
		if err == nil || !reflect.DeepEqual(result, FormalCaptureResult{}) || strings.Contains(output.String(), secret) {
			t.Fatal("rejection leaked private data or returned a candidate")
		}
		const prefix = "[system-backup-database-timing] "
		var reports int
		for _, line := range strings.Split(output.String(), "\n") {
			_, raw, ok := strings.Cut(line, prefix)
			if !ok {
				continue
			}
			reports++
			var report struct {
				Version           string                       `json:"schema_version"`
				InvocationSHA256  string                       `json:"invocation_sha256"`
				CandidateReturned bool                         `json:"candidate_returned"`
				Samples           []domain.CaptureTimingSample `json:"samples"`
			}
			digest, _ := i.Hash()
			if json.Unmarshal([]byte(raw), &report) != nil || report.Version != "database-capture-timing.v1" || report.InvocationSHA256 != digest || report.CandidateReturned {
				t.Fatal("diagnostic substituted request identity or claimed success")
			}
			counts := map[string]uint64{}
			for _, sample := range report.Samples {
				counts[sample.Stage] = sample.Calls
			}
			if counts["key_check"] != uint64(key.checks) || counts["source_authorize"] != uint64(sourceChecks) || counts["worker_total"] != 1 {
				t.Fatal("lost original checks in summary", counts, key.checks, sourceChecks)
			}
		}
		if reports != 1 {
			t.Fatal("expected one bounded rejection report", reports)
		}
	}
}

func TestMeasuredCaptureKeyCheckPreservesErrorAndDoesNotSkipCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	refusal := errors.New("private authority error")
	calls := 0
	err := measuredCaptureKeyCheck(ctx, func(got context.Context) error {
		calls++
		if got != ctx {
			t.Fatal("replaced original context")
		}
		return refusal
	})
	if err != refusal || calls != 1 {
		t.Fatal("diagnostics suppressed/repeated original operation or changed error")
	}
}

func TestDatabaseCaptureTimingDoesNotCertifyPanickingCallback(t *testing.T) {
	i, env, key := formalInvocationFixture(t)
	i.Request.Operation, i.WorkspacePath = "capture-database", ""
	i.Request.Database = databaseRequestFixture(t).Request.Database
	i.Request.MaxFiles, i.Request.MaxFileBytes, i.Request.Files = 0, 0, nil
	connector := &databaseDiagnosticNoConnect{}
	env.Database = sql.OpenDB(connector)
	defer env.Database.Close()
	const secret = "PRIVATE_PANIC_VALUE"
	env.SourceAuthorize = func(context.Context, Invocation) error { panic(secret) }
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	func() {
		defer func() {
			if recover() != secret {
				t.Fatal("original panic changed or suppressed")
			}
		}()
		_, _ = runFormalCapture(context.Background(), i, key, env)
		t.Fatal("panic unexpectedly swallowed")
	}()
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), `"candidate_returned":false`) || !strings.Contains(output.String(), `"stage":"worker_total","calls":1,"failures":1`) {
		t.Fatal("panic leaked or was reported as a candidate", output.String())
	}
}

func TestDatabaseCaptureTimingKeepsUnknownAndExpiredBoundsDistinct(t *testing.T) {
	unknown := captureDeadlineSample(time.Time{})
	unknown.finish(time.Time{})
	if unknown != (captureDeadlineTiming{}) {
		t.Fatal("inferred a missing key/source bound")
	}
	expired := time.Now().Add(-time.Second)
	window := captureDeadlineSample(expired)
	window.finish(expired)
	if !window.Known || window.StartRemainingUS >= 0 || window.EndRemainingUS > window.StartRemainingUS {
		t.Fatal("expired original bound clamped or extended", window)
	}
}
