package systembackupcontroller

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// ControllerTelemetry is process-local Prometheus state. Only the elected
// leader publishes it; counters start anew when that process restarts.
type ControllerTelemetry struct {
	mu              sync.Mutex
	leaderChanges   uint64
	successes       uint64
	failures        uint64
	lastSuccessUnix float64
	successDuration durationHistogram
	failureDuration durationHistogram
}

type durationHistogram struct {
	count   uint64
	sum     float64
	buckets [12]uint64
}

var controllerDurationBuckets = [...]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300}

func (h *durationHistogram) observe(seconds float64) {
	h.count++
	h.sum += seconds
	for index, upperBound := range controllerDurationBuckets {
		if seconds <= upperBound {
			h.buckets[index]++
		}
	}
}

func (m *ControllerTelemetry) LeaderStarted() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.leaderChanges++
	m.mu.Unlock()
}

func (m *ControllerTelemetry) ObserveReconcile(result ControlLoopResult, observedAt time.Time) {
	if m == nil {
		return
	}
	seconds := result.Duration.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if result.Err != nil {
		m.failures++
		m.failureDuration.observe(seconds)
		return
	}
	m.successes++
	m.successDuration.observe(seconds)
	m.lastSuccessUnix = float64(observedAt.UnixNano()) / 1e9
}

func (m *ControllerTelemetry) Render() []byte {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	leaderChanges, successes, failures := m.leaderChanges, m.successes, m.failures
	lastSuccess := m.lastSuccessUnix
	successDuration, failureDuration := m.successDuration, m.failureDuration
	m.mu.Unlock()

	var body bytes.Buffer
	fmt.Fprintln(&body, "# HELP clawmanager_system_backup_controller_leader_changes_total Total number of system backup controller leader changes observations.")
	fmt.Fprintln(&body, "# TYPE clawmanager_system_backup_controller_leader_changes_total counter")
	fmt.Fprintf(&body, "clawmanager_system_backup_controller_leader_changes_total %d\n", leaderChanges)
	fmt.Fprintln(&body, "# HELP clawmanager_system_backup_controller_reconcile_total Total number of system backup controller reconcile observations.")
	fmt.Fprintln(&body, "# TYPE clawmanager_system_backup_controller_reconcile_total counter")
	fmt.Fprintf(&body, "clawmanager_system_backup_controller_reconcile_total{metric_result=\"success\"} %d\n", successes)
	fmt.Fprintf(&body, "clawmanager_system_backup_controller_reconcile_total{metric_result=\"failure\"} %d\n", failures)
	fmt.Fprintln(&body, "# HELP clawmanager_system_backup_controller_reconcile_seconds Observed system backup controller reconcile in seconds.")
	fmt.Fprintln(&body, "# TYPE clawmanager_system_backup_controller_reconcile_seconds histogram")
	for _, item := range []struct {
		label string
		value durationHistogram
	}{{"success", successDuration}, {"failure", failureDuration}} {
		if item.value.count == 0 {
			continue
		}
		for index, upperBound := range controllerDurationBuckets {
			fmt.Fprintf(&body, "clawmanager_system_backup_controller_reconcile_seconds_bucket{metric_result=%q,le=%q} %d\n", item.label, strconv.FormatFloat(upperBound, 'g', -1, 64), item.value.buckets[index])
		}
		fmt.Fprintf(&body, "clawmanager_system_backup_controller_reconcile_seconds_bucket{metric_result=%q,le=\"+Inf\"} %d\n", item.label, item.value.count)
		fmt.Fprintf(&body, "clawmanager_system_backup_controller_reconcile_seconds_sum{metric_result=%q} %s\n", item.label, strconv.FormatFloat(item.value.sum, 'g', -1, 64))
		fmt.Fprintf(&body, "clawmanager_system_backup_controller_reconcile_seconds_count{metric_result=%q} %d\n", item.label, item.value.count)
	}
	fmt.Fprintln(&body, "# HELP clawmanager_system_backup_controller_last_success_timestamp_seconds Unix timestamp for the system backup controller last success timestamp value; zero means never successful.")
	fmt.Fprintln(&body, "# TYPE clawmanager_system_backup_controller_last_success_timestamp_seconds gauge")
	fmt.Fprintf(&body, "clawmanager_system_backup_controller_last_success_timestamp_seconds %s\n", strconv.FormatFloat(lastSuccess, 'g', -1, 64))
	return body.Bytes()
}
