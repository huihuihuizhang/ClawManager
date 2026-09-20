package systembackupcontroller

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"clawreef/internal/systembackupcontract"
)

const queueBudgetScrapeTimeout = 5 * time.Second

type QueueBudgetCollector interface {
	Collect(context.Context, string) ([]QueueBudgetMetricSample, error)
}

type QueueBudgetMetricsHandler struct {
	Collector      QueueBudgetCollector
	InstallationID string
	Leader         func() bool
	Ready          func() bool
	Controller     *ControllerTelemetry
}

type queueBudgetMetricDescriptor struct {
	help string
}

var queueBudgetMetricDescriptors = map[string]queueBudgetMetricDescriptor{
	"clawmanager_system_backup_task_queue_deadline_utilization_ratio": {
		help: "Maximum pending task queue age divided by its immutable creation-time deadline window; values above one are not clipped.",
	},
	"clawmanager_system_backup_operation_queue_deadline_utilization_ratio": {
		help: "Maximum pending operation queue age divided by its immutable creation-time deadline window; values above one are not clipped.",
	},
	"clawmanager_system_backup_preflight_queue_deadline_utilization_ratio": {
		help: "Maximum pending preflight queue age divided by its immutable creation-time deadline window; values above one are not clipped.",
	},
	"clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio": {
		help: "Maximum pending artifact verify queue age divided by its immutable creation-time deadline window; values above one are not clipped.",
	},
}

func expectedQueueBudgetSamples() map[string]struct{} {
	expected := make(map[string]struct{}, 25)
	for _, taskType := range []string{"backup", "drill"} {
		for _, purpose := range []string{"acceptance", "functional_test"} {
			expected["task:"+taskType+":"+purpose] = struct{}{}
		}
	}
	for _, mode := range []string{"production_readonly", "functional_test"} {
		expected["preflight:"+mode] = struct{}{}
	}
	for _, scope := range []string{"health", "full"} {
		expected["artifact_verify:"+scope] = struct{}{}
	}
	for _, operationType := range systembackupcontract.OperationTypes {
		expected["operation:"+operationType] = struct{}{}
	}
	return expected
}

func queueBudgetSampleIdentity(sample QueueBudgetMetricSample) (string, string, error) {
	switch sample.MetricName {
	case "clawmanager_system_backup_task_queue_deadline_utilization_ratio":
		if sample.PreflightMode != "" || sample.VerificationScope != "" || sample.OperationType != "" {
			return "", "", fmt.Errorf("unexpected labels on task queue budget sample")
		}
		return "task:" + sample.TaskType + ":" + sample.TaskPurpose,
			fmt.Sprintf(`task_type=%q,task_purpose=%q`, sample.TaskType, sample.TaskPurpose), nil
	case "clawmanager_system_backup_preflight_queue_deadline_utilization_ratio":
		if sample.TaskType != "" || sample.TaskPurpose != "" || sample.VerificationScope != "" || sample.OperationType != "" {
			return "", "", fmt.Errorf("unexpected labels on preflight queue budget sample")
		}
		return "preflight:" + sample.PreflightMode,
			fmt.Sprintf(`preflight_mode=%q`, sample.PreflightMode), nil
	case "clawmanager_system_backup_artifact_verify_queue_deadline_utilization_ratio":
		if sample.TaskType != "" || sample.TaskPurpose != "" || sample.PreflightMode != "" || sample.OperationType != "" {
			return "", "", fmt.Errorf("unexpected labels on artifact verification queue budget sample")
		}
		return "artifact_verify:" + sample.VerificationScope,
			fmt.Sprintf(`verification_scope=%q`, sample.VerificationScope), nil
	case "clawmanager_system_backup_operation_queue_deadline_utilization_ratio":
		if sample.TaskType != "" || sample.TaskPurpose != "" || sample.PreflightMode != "" || sample.VerificationScope != "" {
			return "", "", fmt.Errorf("unexpected labels on operation queue budget sample")
		}
		return "operation:" + sample.OperationType,
			fmt.Sprintf(`operation_type=%q`, sample.OperationType), nil
	default:
		return "", "", fmt.Errorf("unregistered queue budget metric")
	}
}

func renderQueueBudgetMetrics(samples []QueueBudgetMetricSample) ([]byte, error) {
	expected := expectedQueueBudgetSamples()
	if len(samples) != len(expected) {
		return nil, fmt.Errorf("incomplete queue budget metric set")
	}
	var body bytes.Buffer
	declared := make(map[string]struct{}, len(queueBudgetMetricDescriptors))
	for _, sample := range samples {
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 {
			return nil, fmt.Errorf("invalid queue budget metric value")
		}
		identity, labels, err := queueBudgetSampleIdentity(sample)
		if err != nil {
			return nil, err
		}
		if _, ok := expected[identity]; !ok {
			return nil, fmt.Errorf("unknown or duplicate queue budget label group")
		}
		delete(expected, identity)
		if _, ok := declared[sample.MetricName]; !ok {
			descriptor := queueBudgetMetricDescriptors[sample.MetricName]
			_, _ = fmt.Fprintf(&body, "# HELP %s %s\n# TYPE %s gauge\n", sample.MetricName, descriptor.help, sample.MetricName)
			declared[sample.MetricName] = struct{}{}
		}
		_, _ = fmt.Fprintf(&body, "%s{%s} %s\n", sample.MetricName, labels, strconv.FormatFloat(sample.Value, 'g', -1, 64))
	}
	if len(expected) != 0 {
		return nil, fmt.Errorf("missing queue budget label groups")
	}
	return body.Bytes(), nil
}

func (h QueueBudgetMetricsHandler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.Leader == nil || h.Ready == nil || h.Collector == nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if !h.Leader() {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !h.Ready() {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), queueBudgetScrapeTimeout)
	defer cancel()
	samples, err := h.Collector.Collect(ctx, h.InstallationID)
	if err != nil {
		http.Error(w, "queue budget collection failed", http.StatusServiceUnavailable)
		return
	}
	body, err := renderQueueBudgetMetrics(samples)
	if err != nil {
		http.Error(w, "queue budget metrics invalid", http.StatusServiceUnavailable)
		return
	}
	if !h.Leader() {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !h.Ready() {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	if h.Controller != nil {
		body = append(body, h.Controller.Render()...)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
