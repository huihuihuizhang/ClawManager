package main

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func TestMySQLFixtureSchemaCommentsAndClosedLayout(t *testing.T) {
	for _, schema := range []string{mysqlAuditSchema, strings.ReplaceAll(mysqlAuditSchema, "\n", "\r\n"), "-- another comment; with SQL-looking text;\n" + mysqlAuditSchema} {
		steps, err := mysqlFixtureSchemaSteps(schema)
		if err != nil || len(steps) != 5 {
			t.Fatal("actual five-table fixture was split at a comment semicolon")
		}
		for _, step := range steps {
			if !strings.HasPrefix(step.query, "CREATE TABLE ") || strings.Contains(step.query, ";") || strings.Contains(step.query, "-- ") {
				t.Fatal("comment or multiple statements reached the fixture executor")
			}
		}
	}
	for _, schema := range []string{"", mysqlAuditSchema + "\nDROP TABLE audit_logs;", mysqlAuditSchema + "\nCREATE TABLE audit_logs (id BIGINT);", strings.Replace(mysqlAuditSchema, "CREATE TABLE audit_logs", "CREATE TABLE unexpected", 1), strings.Replace(mysqlAuditSchema, "CREATE TABLE audit_logs (", "CREATE TABLE audit_logs (\n", 1)} {
		if steps, err := mysqlFixtureSchemaSteps(schema); err == nil || steps != nil {
			t.Fatal("unsupported or incomplete fixture produced executable SQL")
		}
	}
}

// Compare the actual shared seed statements with columns independently parsed
// from the real DDL. This is a shape check, not an in-memory MySQL substitute.
func mysqlFixtureShapeError(schema []mysqlFixtureStep, seed []mysqlFixtureStep) error {
	tables := map[string][]string{}
	create := regexp.MustCompile(`^CREATE TABLE ([a-z][a-z0-9_]*) \((.+)\)$`)
	insert := regexp.MustCompile(`^INSERT INTO ([a-z][a-z0-9_]*) \(([^)]+)\) VALUES \(([?,]+)\)$`)
	for _, step := range schema {
		match := create.FindStringSubmatch(step.query)
		if match == nil {
			return errors.New("unsupported DDL shape")
		}
		for _, column := range strings.Split(match[2], ",") {
			tables[match[1]] = append(tables[match[1]], strings.Fields(column)[0])
		}
	}
	for _, step := range seed {
		match := insert.FindStringSubmatch(step.query)
		if match == nil {
			return errors.New("INSERT must name its columns")
		}
		columns := strings.Split(match[2], ",")
		if strings.Join(columns, ",") != strings.Join(tables[match[1]], ",") || len(columns) != len(step.args) || strings.Count(match[3], "?") != len(step.args) {
			return errors.New("fixture column, placeholder and argument counts differ")
		}
		for i, arg := range step.args {
			if arg == nil && !(match[1] == "audit_logs" && columns[i] == "resource_id") {
				return errors.New("unexpected NULL fixture argument")
			}
			if _, err := driver.DefaultParameterConverter.ConvertValue(arg); err != nil {
				return errors.New("fixture argument is not a SQL scalar")
			}
		}
	}
	return nil
}

func TestMySQLFixtureSeedMatchesActualSchema(t *testing.T) {
	schema, err := mysqlFixtureSchemaSteps(mysqlAuditSchema)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := mysqlFixtureSeedSteps(mysqlAuditFixture)
	if err != nil || len(seed) != 6 {
		t.Fatal("six original fixture rows required")
	}
	if err := mysqlFixtureShapeError(schema, seed); err != nil {
		t.Fatal(err)
	}
	if len(seed[0].args) != 10 {
		t.Fatal("operation fixture must have ten columns")
	}
	broken := append([]mysqlFixtureStep(nil), seed...)
	broken[0].query = strings.Replace(broken[0].query, "VALUES (?,?,?,?,?,?,?,?,?,?)", "VALUES (?,?,?,?,?,?,?,?,?,?,?)", 1)
	if mysqlFixtureShapeError(schema, broken) == nil {
		t.Fatal("original eleven-placeholder/ten-argument defect was not detected")
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"operation":null}`)} {
		if steps, err := mysqlFixtureSeedSteps(raw); err == nil || steps != nil {
			t.Fatal("invalid fixture produced seed statements")
		}
	}
}

func TestMySQLFixtureFailureDoesNotExposeSQLOrCredentials(t *testing.T) {
	secret := "PRIVATE_PASSWORD_AND_SQL_BODY"
	for _, tc := range []struct {
		name, stage, class, state string
		code                      uint16
		err                       error
	}{
		{"mysql", "schema_1", "mysql", "42000", 1064, fmt.Errorf("%s: %w", secret, &mysql.MySQLError{Number: 1064, SQLState: [5]byte{'4', '2', '0', '0', '0'}, Message: secret})},
		{"unsafe_sqlstate", "seed_operation", "mysql", "unknown", 1136, &mysql.MySQLError{Number: 1136, SQLState: [5]byte{'4', '\n', '0', '0', '0'}, Message: secret}},
		{"deadline", "seed_nonce", "deadline", "unknown", 0, fmt.Errorf("%s: %w", secret, context.DeadlineExceeded)},
		{"canceled", "fixture", "canceled", "unknown", 0, context.Canceled},
		{"other", secret, "unclassified", "unknown", 0, errors.New(secret)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stage := tc.stage
			if stage == secret {
				stage = "unknown"
			}
			got := mysqlFixtureFailure(tc.stage, tc.err)
			want := fmt.Sprintf("isolated SQL fixture step failed stage=%s class=%s code=%d sqlstate=%s", stage, tc.class, tc.code, tc.state)
			if got != want || strings.Contains(got, secret) || strings.ContainsAny(got, "\r\n") {
				t.Fatal("fixture diagnostics leaked untrusted error text")
			}
		})
	}
}
