package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Reuse the real JWT + SQLLoginSessions + pinned authority composition, with
// an independent observer of the INSERT actually sent to the model driver.
// This proves application binding; it does not prove real MySQL constraints.
type operationBindingObservation struct {
	session *mutationASessionState
	row     map[string]any
}

func (o *operationBindingObservation) Driver() driver.Driver { return registrationTestDriver{} }
func (o *operationBindingObservation) Connect(context.Context) (driver.Conn, error) {
	return &operationBindingConn{mutationASessionConn{mutationTestConn{o.session.base}, o.session}, o}, nil
}

type operationBindingConn struct {
	mutationASessionConn
	observation *operationBindingObservation
}

func operationBindingSQLRow(query string, args []driver.NamedValue) (map[string]any, error) {
	left := strings.Index(query, "(")
	separator := strings.Index(query, ") VALUES (")
	if left < 0 || separator < left || !strings.HasSuffix(query, ")") {
		return nil, errors.New("unexpected operation INSERT shape")
	}
	columns := strings.Split(query[left+1:separator], ",")
	values := strings.Split(query[separator+len(") VALUES ("):len(query)-1], ",")
	if len(columns) != len(values) {
		return nil, errors.New("operation INSERT column/value mismatch")
	}
	row, index := map[string]any{}, 0
	for n, token := range values {
		token = strings.TrimSpace(token)
		var value any
		switch {
		case token == "?":
			if index >= len(args) {
				return nil, errors.New("operation INSERT argument underflow")
			}
			value = args[index].Value
			index++
		case token == "NULL":
		case token == "FALSE":
			value = false
		case token == "TRUE":
			value = true
		case strings.HasPrefix(token, "'") && strings.HasSuffix(token, "'"):
			value = strings.ReplaceAll(token[1:len(token)-1], "''", "'")
		default:
			integer, err := strconv.ParseInt(token, 10, 64)
			if err != nil {
				return nil, errors.New("unobserved operation SQL default/expression")
			}
			value = integer
		}
		row[strings.TrimSpace(columns[n])] = value
	}
	if index != len(args) {
		return nil, errors.New("operation INSERT argument overflow")
	}
	return row, nil
}

func (c *operationBindingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, "INSERT INTO system_backup_v2_operations") {
		row, err := operationBindingSQLRow(query, args)
		if err != nil {
			return nil, err
		}
		c.observation.row = row
	}
	result, err := c.mutationTestConn.ExecContext(ctx, query, args)
	if err == nil && strings.HasPrefix(query, "UPDATE system_backup_v2_installation_state SET active_config_version=") {
		// Force a distinct completion timestamp only AFTER the config/CAS work.
		c.observation.session.base.now = c.observation.session.base.now.Add(2 * time.Second)
	}
	return result, err
}

func operationBindingFixture(t *testing.T, endpoint string) (ConfigMutationService, RegistrationActor, []byte, *operationBindingObservation) {
	t.Helper()
	svc, actor, raw, session := mutationASessionIntegrationFixture(t)
	observation := &operationBindingObservation{session: session}
	db := sql.OpenDB(observation)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	svc.DB = db
	if endpoint == ConfigRollbackEndpoint {
		raw = []byte(`{"expected_version":1,"change_reason":"synthetic rollback","rollback_from_version":1}`)
	}
	return svc, actor, raw, observation
}

func TestConfigOperationAResponseMatchesActualSQLFacts(t *testing.T) {
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		t.Run(endpoint, func(t *testing.T) {
			svc, actor, raw, observation := operationBindingFixture(t, endpoint)
			created := observation.session.base.now
			result, err := svc.Mutate(context.Background(), actor, endpoint, "mutation_key_0123456789", "a-operation-sql-facts", raw, nil)
			if err != nil {
				t.Fatal("actual JWT/session mutation failed", err)
			}
			policy, err := DecodeCanonicalConfigOperationResponse(result.Response)
			row := observation.row
			if err != nil || row == nil || policy.ActorID != actor.UserID || policy.Version != result.Version || policy.OperationPublicID != result.OperationPublicID || !policy.CreatedAt.Equal(created) || !policy.StartedAt.Equal(created) || !policy.FinishedAt.Equal(created.Add(2*time.Second)) || !policy.UpdatedAt.Equal(policy.FinishedAt) {
				t.Fatal("public Operation lacks final transaction time/identity binding", err)
			}
			var body map[string]any
			d := json.NewDecoder(bytes.NewReader(result.Response))
			d.UseNumber()
			if d.Decode(&body) != nil {
				t.Fatal("invalid successful Operation")
			}
			for key, value := range body {
				if key == "schema_version" { // This is the unchanged SQL default.
					continue
				}
				stored, present := row[key]
				if !present {
					t.Fatal("public Operation fact missing from exact SQL INSERT", key)
				}
				if timestamp, ok := stored.(time.Time); ok {
					if value != timestamp.UTC().Format(time.RFC3339Nano) {
						t.Fatal("public and SQL time differ", key)
					}
					continue
				}
				if number, ok := value.(json.Number); ok {
					if stored != mustOperationBindingInteger(t, number) {
						t.Fatal("public and SQL integer differ", key)
					}
					continue
				}
				if stored != value {
					t.Fatal("public Operation and SQL fact differ", key)
				}
			}
			state := observation.session.base
			if !bytes.Equal(result.Response, state.data.response) || row["redacted_response_sha256"] != registrationHash(string(result.Response)) || state.data.evidenceHash != registrationHash(string(result.Response)) || state.commits != 1 || state.data.active != 2 {
				t.Fatal("response/evidence/operation receipt bytes diverged")
			}
		})
	}
}

func mustOperationBindingInteger(t *testing.T, number json.Number) int64 {
	t.Helper()
	v, err := number.Int64()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

type operationAliasResponses struct {
	ConfigMutationResponses
	mode    string
	changed bool
}

func (s *operationAliasResponses) Prepare(ctx context.Context, p ConfigMutationOperationPreparation) (PreparedConfigMutationOperationResponse, error) {
	parent, err := s.ConfigMutationResponses.Prepare(ctx, p)
	if err != nil {
		return nil, err
	}
	return &operationAliasPrepared{PreparedConfigMutationOperationResponse: parent, observer: s}, nil
}

type operationAliasPrepared struct {
	PreparedConfigMutationOperationResponse
	observer *operationAliasResponses
	raw      []byte
}

func (p *operationAliasPrepared) mutate() error {
	changed := bytes.Replace(p.raw, []byte(`"actor_id":"42"`), []byte(`"actor_id":"43"`), 1)
	if bytes.Equal(changed, p.raw) || len(changed) != len(p.raw) {
		return errors.New("Operation actor mutation did not occur")
	}
	copy(p.raw, changed)
	p.observer.changed = true
	return nil
}
func (p *operationAliasPrepared) Stage(ctx context.Context, tx *sql.Tx, policy ConfigOperationResponsePolicy, raw []byte, retain time.Time) (int64, error) {
	p.raw = raw
	if p.observer.mode == "stage" {
		if err := p.mutate(); err != nil {
			return 0, err
		}
	}
	return p.PreparedConfigMutationOperationResponse.Stage(ctx, tx, policy, raw, retain)
}
func (p *operationAliasPrepared) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if err := p.PreparedConfigMutationOperationResponse.Recheck(ctx, tx, now); err != nil {
		return err
	}
	if p.observer.mode == "recheck" {
		return p.mutate()
	}
	return nil
}

func TestConfigOperationACallbackCannotRewriteOriginalResponse(t *testing.T) {
	for _, endpoint := range []string{ConfigUpdateEndpoint, ConfigRollbackEndpoint} {
		for _, mode := range []string{"stage", "recheck"} {
			t.Run(endpoint+"/"+mode, func(t *testing.T) {
				svc, actor, raw, observation := operationBindingFixture(t, endpoint)
				wrapper := &operationAliasResponses{ConfigMutationResponses: svc.Responses, mode: mode}
				svc.Responses = wrapper
				result, err := svc.Mutate(context.Background(), actor, endpoint, "mutation_key_0123456789", "a-operation-alias", raw, nil)
				state := observation.session.base
				if !wrapper.changed {
					t.Fatal("required callback byte mutation was not exercised", err)
				}
				if mode == "stage" {
					if err == nil || state.commits != 0 || state.data.active != 1 || len(state.data.rows) != 1 || len(state.data.writes) != 0 || len(result.Response) != 0 {
						t.Fatal("Stage substituted and committed an unauthorized Operation")
					}
					return
				}
				policy, decode := DecodeCanonicalConfigOperationResponse(result.Response)
				if err != nil || decode != nil || policy.ActorID != actor.UserID || !bytes.Equal(result.Response, state.data.response) || registrationHash(string(result.Response)) != state.data.evidenceHash || state.commits != 1 {
					t.Fatal("Recheck rewrote the writer's private response bytes", err, decode)
				}
			})
		}
	}
}
