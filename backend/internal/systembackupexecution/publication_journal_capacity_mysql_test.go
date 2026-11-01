package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	security "clawreef/internal/systembackupsecurity"
)

// Native SQL clock and reservation; the capacity report is explicitly modeled
// fixture DATA, not an observation of the production database filesystem.
func TestPublicationJournalRejectsStaleCapacityBeforeDispatchMySQL(t *testing.T) {
	x, store, state := newAOriginalPublicationService(t)
	h, ctx := x.history, context.Background()
	raw, err := os.ReadFile(h.service.Config.CapacityFile)
	if err != nil {
		t.Fatal(err)
	}
	report, err := security.ParseCapacityReport(raw)
	var now time.Time
	if err != nil || h.admin.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		t.Fatal("original capacity report/clock", err)
	}
	report.ObservedAt = now.Add(-6 * time.Second)
	raw, err = json.Marshal(report)
	if err != nil || os.WriteFile(h.service.Config.CapacityFile, raw, 0600) != nil {
		t.Fatal("named stale capacity report DATA", err)
	}
	intent := publicationJSONIntent{Kind: "manifest_put", Key: store.config.Root + h.original.TaskPublicID + "/3/manifest.json", Payload: []byte(`{"local":"capacity boundary protocol DATA"}`), Deadline: time.Now().Add(8 * time.Second)}
	_, send, err := h.service.beginPublicationAction(ctx, h.token, h.original.AttemptNo, store.config, intent)
	if send || !errors.Is(err, errPublicationUnavailable) || !strings.Contains(err.Error(), "capacity reservation rejected") {
		t.Fatal("stale report admitted a send", send, err)
	}
	var count int
	var status string
	var version uint64
	if h.admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_external_actions WHERE target_public_id=?", h.original.TaskPublicID).Scan(&count) != nil || count != 0 || h.admin.QueryRow("SELECT status,row_version FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&status, &version) != nil || status != "validating" || version != h.token.RowVersion || state.puts != 0 {
		t.Fatal("stale capacity altered original task or sent bytes", count, status, version, state.puts)
	}
	aRefreshPublicationPayloadCapacity(t, x)
	if _, err := h.service.publishOriginalJSON(ctx, h.token, h.original.AttemptNo, store, intent); err != nil || state.puts != 1 {
		t.Fatal("fresh capacity sample did not retain original task/claim", err, state.puts)
	}
}
