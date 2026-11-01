package domain

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Explicit current050/051/052/055 metadata projection for pure tests. Native
// coverage separately reads the actual migration schema, not this projection.
func gatewayRestoreFixture() (Snapshot, []Table, Policy) {
	s, _, p := fixture()
	key := Row{"id": Text("9223372036854775806"), "key_id": Text("gk_original_1"), "key_prefix": Text("cmk_live...aaaa"), "token_hash": Text(strings.Repeat("a", 64)), "key_type": Text("user_created"), "name": Text("原始 key"), "description": Text(""), "owner_user_id": Text("4"), "instance_id": {Null: true}, "allowed_model_groups": Text(`["original-model-group"]`), "status": Text("active"), "expires_at": Text("2020-01-01 00:00:00"), "last_used_at": {Null: true}, "created_by_user_id": Text("2147483647"), "revoked_at": {Null: true}, "revoked_by_user_id": {Null: true}, "revocation_reason": {Null: true}, "created_at": Text("2019-01-01 00:00:00"), "updated_at": Text("2020-01-01 00:00:00"), "rpm_limit": Text("0"), "tpm_limit": Text("2147483647"), "concurrent_requests_limit": Text("1"), "budget_limit": Text("0.00000000"), "budget_period": Text("daily"), "budget_spent": Text("9999999999.99999999"), "budget_reset_at": Text("2020-01-02 00:00:00"), "budget_currency_review_required": Text("1"), "budget_currency_reviewed_at": {Null: true}}
	orphan := cloneRow(key)
	orphan["id"], orphan["key_id"], orphan["token_hash"] = Text("105"), Text("legacy-instance-7"), Text(strings.Repeat("b", 64))
	orphan["key_type"], orphan["instance_id"], orphan["owner_user_id"] = Text("managed_instance"), Text("7"), Cell{Null: true}
	orphan["status"], orphan["revoked_by_user_id"], orphan["revocation_reason"] = Text("revoked"), Text("2147483646"), Text("original deleted actor history")
	orphan["allowed_model_groups"], orphan["budget_reset_at"], orphan["budget_spent"] = Cell{Null: true}, Cell{Null: true}, Text("0.00000001")
	keys := Table{Name: "gateway_keys", Engine: "InnoDB", PrimaryKey: []string{"id"}, ForeignKeys: []ForeignKey{{"instance_id", "instances", "id"}, {"owner_user_id", "users", "id"}}, UniqueKeys: []UniqueKey{{"uk_gateway_keys_key_id", []string{"key_id"}}, {"uk_gateway_keys_token_hash", []string{"token_hash"}}, {"uk_gateway_keys_managed_instance", []string{"instance_id", "key_type"}}}, Rows: []Row{key, orphan}}
	// This independent schema literal must not grow when a production field is
	// accidentally added. Unknown columns must still fail before first write.
	types := map[string]string{"id": "bigint", "key_id": "varchar(96)", "key_prefix": "varchar(128)", "token_hash": "char(64)", "key_type": "varchar(32)", "name": "varchar(160)", "description": "text", "owner_user_id": "int", "instance_id": "int", "allowed_model_groups": "json", "status": "varchar(24)", "expires_at": "timestamp", "last_used_at": "timestamp", "created_by_user_id": "int", "revoked_at": "timestamp", "revoked_by_user_id": "int", "revocation_reason": "varchar(255)", "created_at": "timestamp", "updated_at": "timestamp", "rpm_limit": "int", "tpm_limit": "int", "concurrent_requests_limit": "int", "budget_limit": "decimal(18,8)", "budget_period": "varchar(16)", "budget_spent": "decimal(18,8)", "budget_reset_at": "timestamp", "budget_currency_review_required": "tinyint(1)", "budget_currency_reviewed_at": "timestamp"}
	nullable := strings.Fields("description owner_user_id instance_id allowed_model_groups expires_at last_used_at created_by_user_id revoked_at revoked_by_user_id revocation_reason budget_reset_at budget_currency_reviewed_at")
	for _, name := range sortedKeys(key) {
		c := Column{Name: name, Type: types[name]}
		for _, n := range nullable {
			if n == name {
				c.Nullable = true
			}
		}
		keys.Columns = append(keys.Columns, c)
	}
	reservation := Row{"reservation_id": Text("reserved-expired"), "gateway_key_id": key["id"], "reserved_cost": Text("9999999999.99999999"), "actual_cost": {Null: true}, "settlement_status": Text("reserved"), "expires_at": Text("2020-01-01 00:00:00"), "created_at": Text("2019-01-01 00:00:00")}
	pending := cloneRow(reservation)
	pending["reservation_id"], pending["settlement_status"], pending["actual_cost"] = Text("pending-original"), Text("pending"), Text("0.00000001")
	reservations := Table{Name: "gateway_key_budget_reservations", Engine: "InnoDB", PrimaryKey: []string{"reservation_id"}, ForeignKeys: []ForeignKey{{"gateway_key_id", "gateway_keys", "id"}}, Rows: []Row{reservation, pending}}
	ledger := Table{Name: "gateway_key_budget_ledger", Engine: "InnoDB", PrimaryKey: []string{"reservation_id"}, ForeignKeys: []ForeignKey{{"gateway_key_id", "gateway_keys", "id"}}, Rows: []Row{{"reservation_id": Text("ledger-only"), "gateway_key_id": orphan["id"], "actual_cost": Text("9999999999.99999999"), "recorded_at": Text("2019-01-01 00:00:00")}, {"reservation_id": pending["reservation_id"], "gateway_key_id": pending["gateway_key_id"], "actual_cost": pending["actual_cost"], "recorded_at": Text("2019-01-01 00:00:00")}}}
	for _, t := range []*Table{&reservations, &ledger} {
		for _, name := range sortedKeys(t.Rows[0]) {
			kind := "timestamp"
			switch name {
			case "reservation_id":
				kind = "varchar(64)"
			case "gateway_key_id":
				kind = "bigint"
			case "reserved_cost", "actual_cost":
				kind = "decimal(18,8)"
			case "settlement_status":
				kind = "varchar(16)"
			}
			t.Columns = append(t.Columns, Column{Name: name, Type: kind, Nullable: name == "actual_cost" && t.Name == "gateway_key_budget_reservations"})
		}
	}
	s.Tables = append(s.Tables, keys, reservations, ledger)
	p.Dependencies = map[string]TableAdapter{}
	for _, table := range []Table{keys, reservations, ledger} {
		a := TableAdapter{SchemaSHA256: SchemaDigest(table), Normalizer: GatewayBudget055Normalizer, InterruptedAt: "2026-11-01T00:00:00Z", Columns: map[string]string{}}
		for _, c := range table.Columns {
			a.Columns[c.Name] = "preserve"
		}
		p.Dependencies[table.Name] = a
	}
	return s, copyTables(s.Tables), p
}

func TestGatewayBudgetWholeGroupPreservesUnsettledPrecisionAndDeletedHistory(t *testing.T) {
	s, target, p := gatewayRestoreFixture()
	before, _ := Digest(s)
	plan, err := Normalize(context.Background(), s, target, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gateway_key_budget_reservations", "gateway_key_budget_ledger"} {
		if !reflect.DeepEqual(find(s, name).Rows, find(plan.Data, name).Rows) {
			t.Fatal("reservation/ledger history changed", name)
		}
	}
	for n, row := range find(plan.Data, "gateway_keys").Rows {
		original := find(s, "gateway_keys").Rows[n]
		if row["status"].String() != "revoked" {
			t.Fatal("usable key")
		}
		for name, value := range original {
			if n == 0 && (name == "status" || name == "revoked_at" || name == "revoked_by_user_id" || name == "revocation_reason" || name == "updated_at") {
				continue
			}
			if value.Null != row[name].Null || !bytes.Equal(value.Bytes, row[name].Bytes) {
				t.Fatal("key definition/actor/HMAC/precision/NULL/window changed", name)
			}
		}
	}
	if find(plan.Data, "gateway_keys").Rows[0]["revoked_at"].String() != "2026-11-01 00:00:00" || !find(plan.Data, "gateway_keys").Rows[0]["revoked_by_user_id"].Null {
		t.Fatal("invented revocation actor/time")
	}
	if VerifyGatewayBudgetQuarantine(context.Background(), plan.Data) != nil {
		t.Fatal("independent semantic check")
	}
	if after, _ := Digest(s); after != before {
		t.Fatal("source mutated")
	}
}

func TestGatewayBudgetClosedGroupRejectsBeforeAnySQLWrite(t *testing.T) {
	for _, mode := range []string{"missing-adapter", "plain-preserve", "different-time", "unknown-column", "missing-fk", "wrong-unique-order", "changed-key-type", "overflow-id", "overprecise-money", "pending-null", "reserved-actual", "different-ledger-key", "different-ledger-cost", "unknown-state", "image-pending-without-owner-proof", "missing-key", "duplicate-hmac", "group-json-null", "historical-actor-zero"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := gatewayRestoreFixture()
			keys, reservations, ledger := find(s, "gateway_keys"), find(s, "gateway_key_budget_reservations"), find(s, "gateway_key_budget_ledger")
			switch mode {
			case "missing-adapter":
				delete(p.Dependencies, "gateway_key_budget_ledger")
			case "plain-preserve":
				a := p.Dependencies["gateway_keys"]
				a.Normalizer = ""
				p.Dependencies["gateway_keys"] = a
			case "different-time":
				a := p.Dependencies["gateway_key_budget_ledger"]
				a.InterruptedAt = "2026-11-01T00:00:01Z"
				p.Dependencies["gateway_key_budget_ledger"] = a
			case "unknown-column":
				for n := range s.Tables {
					if s.Tables[n].Name == "gateway_keys" {
						s.Tables[n].Columns = append(s.Tables[n].Columns, Column{Name: "future_enabled", Type: "int"})
						for _, r := range s.Tables[n].Rows {
							r["future_enabled"] = Text("1")
						}
					}
				}
			case "missing-fk":
				for n := range s.Tables {
					if s.Tables[n].Name == "gateway_keys" {
						s.Tables[n].ForeignKeys = nil
					}
				}
			case "wrong-unique-order":
				for n := range s.Tables {
					if s.Tables[n].Name == "gateway_keys" {
						s.Tables[n].UniqueKeys[2].Columns = []string{"key_type", "instance_id"}
					}
				}
			case "changed-key-type":
				keys.Rows[0]["key_type"] = Text("future_external")
			case "overflow-id":
				keys.Rows[0]["id"] = Text("9223372036854775808")
			case "overprecise-money":
				keys.Rows[0]["budget_spent"] = Text("0.000000001")
			case "pending-null":
				reservations.Rows[1]["actual_cost"] = Cell{Null: true}
			case "reserved-actual":
				reservations.Rows[0]["actual_cost"] = Text("0.00000000")
			case "different-ledger-key":
				ledger.Rows[1]["gateway_key_id"] = keys.Rows[1]["id"]
			case "different-ledger-cost":
				ledger.Rows[1]["actual_cost"] = Text("0.00000002")
			case "unknown-state":
				reservations.Rows[0]["settlement_status"] = Text("settled")
			case "image-pending-without-owner-proof":
				reservations.Rows[0]["settlement_status"] = Text("image_pending")
			case "missing-key":
				reservations.Rows[0]["gateway_key_id"] = Text("99")
			case "duplicate-hmac":
				keys.Rows[1]["token_hash"] = keys.Rows[0]["token_hash"]
			case "group-json-null":
				keys.Rows[0]["allowed_model_groups"] = Text(" null ")
			case "historical-actor-zero":
				keys.Rows[0]["created_by_user_id"] = Text("0")
			}
			state := isolatedTarget(target)
			db := database(state)
			defer db.Close()
			observer := database(state)
			defer observer.Close()
			checks := 0
			_, err := RestoreDrillWithEvidence(context.Background(), db, DrillTarget{Database: state.name, ServerUUID: state.uuid, CheckIsolation: func(ctx context.Context) error {
				checks++
				var name, uuid string
				if observer.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&name, &uuid) != nil || name != state.name || uuid != state.uuid {
					return ErrIsolation
				}
				return ctx.Err()
			}}, s, p, func(context.Context, RestorePlan) error { return errors.New("evidence must not run") })
			// This named SQL-driver fixture independently observes its own target
			// identity. It is not production network/credential isolation proof.
			if _, pureErr := Normalize(context.Background(), s, target, p); pureErr == nil {
				t.Fatal("unsupported state accepted")
			}
			if err == nil || errors.Is(err, ErrIsolation) || checks < 1 || state.writes != 0 || state.commits != 0 {
				t.Fatal("rejected input wrote SQL")
			}
		})
	}
}

func TestGatewayBudgetEmptyRequiredTableAndCanceledContext(t *testing.T) {
	s, target, p := gatewayRestoreFixture()
	for n := range s.Tables {
		if s.Tables[n].Name == "gateway_key_budget_reservations" {
			s.Tables[n].Rows = nil
		}
	}
	plan, err := Normalize(context.Background(), s, target, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(find(plan.Data, "gateway_key_budget_reservations").Columns) != 7 {
		t.Fatal("empty mandatory group metadata vanished")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Normalize(ctx, s, target, p); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled normalization", err)
	}
	find(plan.Data, "gateway_keys").Rows[0]["status"] = Text("active")
	if VerifyGatewayBudgetQuarantine(context.Background(), plan.Data) == nil {
		t.Fatal("readback accepted reactivated credential")
	}
}

func TestGatewayAttributionPreservesDeletedKeyAndNullWithoutInventingLinks(t *testing.T) {
	s, target, p := gatewayRestoreFixture()
	for _, name := range []string{"model_invocations", "audit_events", "cost_records"} {
		table := Table{Name: name, Engine: "InnoDB", PrimaryKey: []string{"id"}, Columns: []Column{{Name: "id", Type: "int"}, {Name: "gateway_key_id", Type: "bigint", Nullable: true}}, Rows: []Row{{"id": Text("11"), "gateway_key_id": Text("9223372036854775807")}, {"id": Text("12"), "gateway_key_id": {Null: true}}}}
		s.Tables = append(s.Tables, table)
		target = append(target, table)
	}
	plan, err := Normalize(context.Background(), s, target, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"model_invocations", "audit_events", "cost_records"} {
		if !reflect.DeepEqual(find(s, name).Rows, find(plan.Data, name).Rows) {
			t.Fatal("deleted key attribution or NULL changed", name)
		}
	}
	find(s, "cost_records").Rows[0]["gateway_key_id"] = Text("9223372036854775808")
	if _, err := Normalize(context.Background(), s, target, p); err == nil {
		t.Fatal("unsigned value accepted as current signed BIGINT")
	}
}
