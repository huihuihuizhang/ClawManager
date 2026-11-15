package systembackupcontroller

import (
	"context"
	"database/sql"
	"testing"
	"time"

	q "clawreef/internal/systembackup/quiesce"
)

func TestOriginalLonghornClaimRequiresCurrentSQLAndMatchingReservation(t *testing.T) {
	for _, fault := range []string{"none", "owner", "epoch", "reservation", "inventory", "generation", "expired-transaction"} {
		t.Run(fault, func(t *testing.T) {
			r := originalReservationFixture()
			r.ControlKind = "platform-quiesce"
			state := &originalReservationModel{claim: r, now: time.Now().UTC().Truncate(time.Microsecond), owner: r.GateOwner, epoch: r.AcquisitionEpoch + 1}
			db := sql.OpenDB(reservationConnector{state})
			defer db.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			p, err := LockOriginalAdoptionReservation(ctx, tx, OriginalAdoptionDatabasePin{ServerUUID: r.ServerUUID, Database: r.Database, Account: "installer@localhost"}, r)
			if err != nil {
				t.Fatal(err)
			}
			b := q.ObservationBinding{Kind: q.LonghornExt4Protocol, InstallationID: r.InstallationID, OperationID: r.OperationID, ReservationID: r.ReservationID, Generation: r.GateGeneration, FenceEpoch: r.AcquisitionEpoch, InventorySHA256: r.SourceWritersSHA256, ExpiresAt: r.ExpiresAt, Namespace: "tenant", NamespaceUID: "ns-uid", Node: "node1", NodeUID: "node-uid"}
			switch fault {
			case "owner":
				state.owner = "other"
			case "epoch":
				state.epoch++
			case "reservation":
				b.ReservationID = r.OperationID
			case "inventory":
				b.InventorySHA256 = "other"
			case "generation":
				b.Generation++
			case "expired-transaction":
				_ = tx.Rollback()
			}
			got, err := p.LonghornClaim(ctx, tx, b)
			if (err == nil) != (fault == "none") {
				t.Fatalf("fault %s: %v", fault, err)
			}
			if err == nil && (got.TaskPublicID != "" || got.OriginalReservationID != r.ReservationID || got.EntryRowVersion != r.AcquisitionRowVersion || !got.LeaseObservedAt.Equal(state.now) || got.LeaseExpiresAt.After(p.ValidUntil())) {
				t.Fatal("claim lost SQL binding")
			}
		})
	}
}
