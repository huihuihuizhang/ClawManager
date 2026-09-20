package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupcontract"
)

type fakeQueueBudgetCollector struct {
	collect func(context.Context, string) ([]QueueBudgetMetricSample, error)
}

func (f fakeQueueBudgetCollector) Collect(ctx context.Context, installationID string) ([]QueueBudgetMetricSample, error) {
	return f.collect(ctx, installationID)
}

func completeQueueBudgetSamples() []QueueBudgetMetricSample {
	samples := make([]QueueBudgetMetricSample, 0, 25)
	for _, taskType := range []string{"backup", "drill"} {
		for _, purpose := range []string{"acceptance", "functional_test"} {
			samples = append(samples, QueueBudgetMetricSample{
				MetricName: "clawmanager_system_backup_task_queue_deadline_utilization_ratio", TaskType: taskType, TaskPurpose: purpose,
			})
		}
	}
	for _, mode := range []string{"production_readonly", "functional_test"} {
		samples = append(samples, QueueBudgetMetricSample{
			MetricName: "clawmanager_system_backup_preflight_queue_deadline_utilization_ratio", PreflightMode: mode,
		})
	}
	for _, scope := range []string{"health", "full"} {
		samples = append(samples, QueueBudgetMetricSample{
			MetricName: "clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio", VerificationScope: scope,
		})
	}
	for _, operationType := range systembackupcontract.OperationTypes {
		samples = append(samples, QueueBudgetMetricSample{
			MetricName: "clawmanager_system_backup_operation_queue_deadline_utilization_ratio", OperationType: operationType,
		})
	}
	return samples
}

func requestQueueMetrics(t *testing.T, handler http.Handler) (int, string) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.Code, string(body)
}

func TestQueueBudgetMetricsRenderCompleteClosedPrometheusSampleSet(t *testing.T) {
	samples := completeQueueBudgetSamples()
	samples[0].Value = 1.25
	body, err := renderQueueBudgetMetrics(samples)
	if err != nil {
		t.Fatal(err)
	}
	output := string(body)
	if strings.Count(output, "# HELP ") != 4 || strings.Count(output, "# TYPE ") != 4 ||
		strings.Count(output, "_queue_deadline_utilization_ratio{") != 25 ||
		!strings.Contains(output, "task_type=\"backup\",task_purpose=\"acceptance\"} 1.25\n") ||
		!strings.Contains(output, "preflight_mode=\"production_readonly\"} 0\n") ||
		!strings.Contains(output, "verification_scope=\"full\"} 0\n") {
		t.Fatalf("unexpected queue budget exposition: %s", output)
	}
	for _, mutate := range []func([]QueueBudgetMetricSample) []QueueBudgetMetricSample{
		func(items []QueueBudgetMetricSample) []QueueBudgetMetricSample { return items[:len(items)-1] },
		func(items []QueueBudgetMetricSample) []QueueBudgetMetricSample { items[0] = items[1]; return items },
		func(items []QueueBudgetMetricSample) []QueueBudgetMetricSample {
			items[0].TaskPurpose = "injected\"\n"
			return items
		},
		func(items []QueueBudgetMetricSample) []QueueBudgetMetricSample {
			items[0].Value = math.NaN()
			return items
		},
		func(items []QueueBudgetMetricSample) []QueueBudgetMetricSample {
			items[0].OperationType = "cleanup"
			return items
		},
	} {
		if rendered, err := renderQueueBudgetMetrics(mutate(completeQueueBudgetSamples())); err == nil || rendered != nil {
			t.Fatalf("invalid sample set was rendered: %q, %v", rendered, err)
		}
	}
}

func TestQueueBudgetMetricsHandlerLeaderOnlyAndFailsWithoutPartialData(t *testing.T) {
	leading, ready, called := false, false, 0
	collector := fakeQueueBudgetCollector{collect: func(_ context.Context, installationID string) ([]QueueBudgetMetricSample, error) {
		called++
		if installationID != "installation_test" {
			t.Fatalf("installation ID = %q", installationID)
		}
		return completeQueueBudgetSamples(), nil
	}}
	handler := QueueBudgetMetricsHandler{
		Collector: collector, InstallationID: "installation_test",
		Leader: func() bool { return leading }, Ready: func() bool { return ready },
	}
	if code, body := requestQueueMetrics(t, handler); code != http.StatusOK || body != "" || called != 0 {
		t.Fatalf("standby metrics = %d %q, calls=%d", code, body, called)
	}
	leading = true
	if code, body := requestQueueMetrics(t, handler); code != http.StatusServiceUnavailable || strings.Contains(body, "queue_deadline") || called != 0 {
		t.Fatalf("unready metrics = %d %q, calls=%d", code, body, called)
	}
	ready = true
	if code, body := requestQueueMetrics(t, handler); code != http.StatusOK || !strings.Contains(body, "# TYPE clawmanager_system_backup_task_queue_deadline_utilization_ratio gauge") || called != 1 {
		t.Fatalf("leader metrics = %d %q, calls=%d", code, body, called)
	}
	failed := handler
	failed.Collector = fakeQueueBudgetCollector{collect: func(context.Context, string) ([]QueueBudgetMetricSample, error) {
		return completeQueueBudgetSamples()[:1], errors.New("database unavailable")
	}}
	if code, body := requestQueueMetrics(t, failed); code != http.StatusServiceUnavailable || strings.Contains(body, "queue_deadline") {
		t.Fatalf("failed metrics leaked partial data: %d %q", code, body)
	}
	leading = false
	if code, body := requestQueueMetrics(t, handler); code != http.StatusOK || body != "" || called != 1 {
		t.Fatalf("leader loss metrics = %d %q, calls=%d", code, body, called)
	}
}

func TestQueueBudgetMetricsHandlerSuppressesSamplesWhenReadinessChangesDuringCollection(t *testing.T) {
	ready := true
	handler := QueueBudgetMetricsHandler{
		Collector: fakeQueueBudgetCollector{collect: func(context.Context, string) ([]QueueBudgetMetricSample, error) {
			ready = false
			return completeQueueBudgetSamples(), nil
		}},
		InstallationID: "installation_test",
		Leader:         func() bool { return true },
		Ready:          func() bool { return ready },
	}
	code, body := requestQueueMetrics(t, handler)
	if code != http.StatusServiceUnavailable || strings.Contains(body, "queue_deadline") {
		t.Fatalf("readiness loss leaked queue metrics: %d %q", code, body)
	}
}

func TestQueueBudgetMetricsHandlerReadsSQLSnapshotEndToEnd(t *testing.T) {
	created := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	state := &queueBudgetDBState{
		now:       created.Add(time.Minute),
		backup:    [][]driver.Value{{"acceptance", created, created.Add(2 * time.Minute)}},
		preflight: [][]driver.Value{{"production_readonly", created, created.Add(30 * time.Second)}},
		verify:    [][]driver.Value{{"full", created, created.Add(time.Minute)}},
	}
	db := sql.OpenDB(queueBudgetConnector{state: state})
	defer db.Close()
	handler := QueueBudgetMetricsHandler{
		Collector: SQLQueueBudgetReader{DB: db}, InstallationID: "installation_test",
		Leader: func() bool { return true }, Ready: func() bool { return true },
	}
	code, body := requestQueueMetrics(t, handler)
	if code != http.StatusOK || !state.committed || len(state.queries) != 6 ||
		!strings.Contains(body, "task_type=\"backup\",task_purpose=\"acceptance\"} 0.5\n") ||
		!strings.Contains(body, "preflight_mode=\"production_readonly\"} 2\n") ||
		!strings.Contains(body, "verification_scope=\"full\"} 1\n") {
		t.Fatalf("SQL-backed metrics = %d committed=%t queries=%d body=%q", code, state.committed, len(state.queries), body)
	}
}
