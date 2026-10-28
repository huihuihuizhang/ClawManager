// Package systembackupgcmetadata reads privileged program metadata. An
// Observation is a sequential read, NOT an atomic catalog, DDL freeze, GC
// authorization or proof that a collector may commit. A separate reviewed
// freeze must span observation, mutation and commit in the eventual GC policy.
package systembackupgcmetadata

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("invalid_program_metadata_configuration")
	ErrUnavailable = errors.New("program_metadata_unavailable")
	namePattern    = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	accountPattern = regexp.MustCompile(`^([A-Za-z0-9_]{1,32})@([A-Za-z0-9_.:%-]{1,255})$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	serverPattern  = regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	versionPattern = regexp.MustCompile(`^8\.4\.[0-9]+(?:[-.A-Za-z0-9_]*)$`)
)

const (
	maxRows       = 10000
	maxFieldBytes = 16384
	maxTotalBytes = 16 << 20
	maxReadTime   = 5 * time.Second
)

// This is a SEPARATE privileged observer connection pool, never the GC worker
// connection or its credential. TRIGGER/EVENT metadata privileges themselves
// carry powers beyond reading. This package issues no grants and approves no
// account; the exact account/grants pin must come from deployment review.
type Config struct {
	DB                                                   *sql.DB
	ServerUUID, Database, Account, Version, GrantsSHA256 string
}
type Source struct{ c Config }

func New(c Config) (*Source, error) {
	a := accountPattern.FindStringSubmatch(c.Account)
	if c.DB == nil || !serverPattern.MatchString(c.ServerUUID) || !namePattern.MatchString(c.Database) || len(a) != 3 || strings.EqualFold(a[1], "root") || !versionPattern.MatchString(c.Version) || !digestPattern.MatchString(c.GrantsSHA256) {
		return nil, ErrInvalid
	}
	return &Source{c}, nil
}

type Digest struct {
	SHA256 string
	Rows   uint64
}
type Digests struct {
	Triggers, Routines, Parameters, Events, Views Digest
	ViewCreates                                   Digest
	Combined                                      string
}
type Observation struct {
	pins              Digests
	started, finished time.Time
}

func (o Observation) Digests() Digests                 { return o.pins }
func (o Observation) Interval() (time.Time, time.Time) { return o.started, o.finished }
func (Observation) MarshalJSON() ([]byte, error)       { return nil, ErrInvalid }
func (Observation) String() string                     { return "ProgramMetadataObservation" }
func (Observation) GoString() string                   { return "ProgramMetadataObservation" }

// Framing: domain+NUL; each row is R,u64(field count), then N or
// S,u64(UTF-8 byte length),bytes for each cell; end is C,u64(row count).
// No SQL NULL/empty coercion, JSON number convention or body normalization.
func number(h hash.Hash, n uint64) { var b [8]byte; binary.BigEndian.PutUint64(b[:], n); h.Write(b[:]) }
func frame(h hash.Hash, cells []sql.NullString) {
	h.Write([]byte{'R'})
	number(h, uint64(len(cells)))
	for _, c := range cells {
		if !c.Valid {
			h.Write([]byte{'N'})
			continue
		}
		h.Write([]byte{'S'})
		number(h, uint64(len(c.String)))
		h.Write([]byte(c.String))
	}
}
func beginDigest(domain string) hash.Hash {
	h := sha256.New()
	h.Write([]byte("clawmanager.gc-program-catalog.v1/" + domain + "\x00"))
	return h
}
func finishDigest(h hash.Hash, n uint64) Digest {
	h.Write([]byte{'C'})
	number(h, n)
	return Digest{hex.EncodeToString(h.Sum(nil)), n}
}

// GrantsDigest is an offline pin helper, not a privilege or completeness proof.
func GrantsDigest(statements []string) (string, error) {
	if len(statements) < 1 || len(statements) > 128 {
		return "", ErrInvalid
	}
	ss := append([]string(nil), statements...)
	sort.Strings(ss)
	h := beginDigest("grants")
	for n, s := range ss {
		if len(s) == 0 || len(s) > 2048 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) || n > 0 && ss[n-1] == s {
			return "", ErrInvalid
		}
		frame(h, []sql.NullString{{String: s, Valid: true}})
	}
	return finishDigest(h, uint64(len(ss))).SHA256, nil
}

// Global metadata coverage is deliberately explicit. A matching hash with only
// EXECUTE/REFERENCES or a schema-limited privilege is not complete visibility.
// No write/DDL privilege is added here, including those inherent in EVENT and
// TRIGGER; this merely checks the independently approved observer profile.
func (s *Source) grants(statements []string) error {
	a := accountPattern.FindStringSubmatch(s.c.Account)
	to := []string{"'" + a[1] + "'@'" + a[2] + "'", "`" + a[1] + "`@`" + a[2] + "`"}
	required := map[string]bool{"SELECT": false, "SHOW VIEW": false, "SHOW_ROUTINE": false, "TRIGGER": false, "EVENT": false}
	usage := false
	for _, statement := range statements {
		i := strings.LastIndex(statement, " TO ")
		if i < 0 || (statement[i+4:] != to[0] && statement[i+4:] != to[1]) || !strings.HasPrefix(statement, "GRANT ") {
			return ErrUnavailable
		}
		p := strings.Split(statement[len("GRANT "):i], " ON ")
		if len(p) != 2 || p[1] != "*.*" {
			return ErrUnavailable
		}
		if p[0] == "USAGE" {
			if usage {
				return ErrUnavailable
			}
			usage = true
			continue
		}
		for _, raw := range strings.Split(p[0], ",") {
			privilege := strings.TrimSpace(raw)
			seen, ok := required[privilege]
			if !ok || seen {
				return ErrUnavailable
			}
			required[privilege] = true
		}
	}
	for _, seen := range required {
		if !seen {
			return ErrUnavailable
		}
	}
	pin, err := GrantsDigest(statements)
	if err != nil || pin != s.c.GrantsSHA256 {
		return ErrUnavailable
	}
	return nil
}

const identitySQL = `SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE(),CONNECTION_ID(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6)),@@version,@@character_set_client,@@character_set_connection,@@character_set_results`
const grantsSQL = `SHOW GRANTS`

type identity struct {
	server, database, account, role, version, client, connection, results string
	id                                                                    uint64
	now                                                                   time.Time
	offset                                                                int64
}

func (s *Source) identity(ctx context.Context, c *sql.Conn) (identity, error) {
	var v identity
	err := c.QueryRowContext(ctx, identitySQL).Scan(&v.server, &v.database, &v.account, &v.role, &v.id, &v.now, &v.offset, &v.version, &v.client, &v.connection, &v.results)
	_, offset := v.now.Zone()
	if err != nil || v.server != s.c.ServerUUID || v.database != s.c.Database || v.account != s.c.Account || v.role != "NONE" || v.id == 0 || v.version != s.c.Version || v.client != "utf8mb4" || v.connection != "utf8mb4" || v.results != "utf8mb4" || v.offset != 0 || v.now.IsZero() || offset != 0 || v.now.Nanosecond()%1000 != 0 || time.Since(v.now) > maxReadTime || time.Until(v.now) > maxReadTime {
		return v, ErrUnavailable
	}
	return v, nil
}
func (s *Source) readGrants(ctx context.Context, c *sql.Conn) error {
	rows, err := c.QueryContext(ctx, grantsSQL)
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	var statements []string
	for rows.Next() {
		if len(statements) >= 128 {
			return ErrUnavailable
		}
		var stmt string
		if rows.Scan(&stmt) != nil {
			return ErrUnavailable
		}
		statements = append(statements, stmt)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return ErrUnavailable
	}
	return s.grants(statements)
}

type definition struct {
	kind, table, body, fields string
	keys                      []string
}

var definitions = []definition{
	{"triggers", "TRIGGERS", "ACTION_STATEMENT", "TRIGGER_SCHEMA,TRIGGER_NAME,EVENT_OBJECT_SCHEMA,EVENT_OBJECT_TABLE,ACTION_TIMING,EVENT_MANIPULATION,ACTION_ORDER,ACTION_ORIENTATION,ACTION_STATEMENT,ACTION_STATEMENT_BYTES,SQL_MODE,DEFINER,CHARACTER_SET_CLIENT,COLLATION_CONNECTION,DATABASE_COLLATION", []string{"TRIGGER_SCHEMA", "TRIGGER_NAME"}},
	{"routines", "ROUTINES", "ROUTINE_DEFINITION", "SPECIFIC_NAME,ROUTINE_CATALOG,ROUTINE_SCHEMA,ROUTINE_NAME,ROUTINE_TYPE,DATA_TYPE,CHARACTER_MAXIMUM_LENGTH,CHARACTER_OCTET_LENGTH,NUMERIC_PRECISION,NUMERIC_SCALE,DATETIME_PRECISION,CHARACTER_SET_NAME,COLLATION_NAME,DTD_IDENTIFIER,ROUTINE_BODY,ROUTINE_DEFINITION,ROUTINE_DEFINITION_BYTES,EXTERNAL_NAME,EXTERNAL_LANGUAGE,PARAMETER_STYLE,IS_DETERMINISTIC,SQL_DATA_ACCESS,SQL_PATH,SECURITY_TYPE,SQL_MODE,DEFINER,CHARACTER_SET_CLIENT,COLLATION_CONNECTION,DATABASE_COLLATION", []string{"ROUTINE_SCHEMA", "ROUTINE_NAME", "ROUTINE_TYPE"}},
	{"parameters", "PARAMETERS", "", "SPECIFIC_CATALOG,SPECIFIC_SCHEMA,SPECIFIC_NAME,ROUTINE_TYPE,ORDINAL_POSITION,PARAMETER_MODE,PARAMETER_NAME,DATA_TYPE,CHARACTER_MAXIMUM_LENGTH,CHARACTER_OCTET_LENGTH,NUMERIC_PRECISION,NUMERIC_SCALE,DATETIME_PRECISION,CHARACTER_SET_NAME,COLLATION_NAME,DTD_IDENTIFIER", []string{"SPECIFIC_SCHEMA", "SPECIFIC_NAME", "ROUTINE_TYPE", "ORDINAL_POSITION"}},
	{"events", "EVENTS", "EVENT_DEFINITION", "EVENT_SCHEMA,EVENT_NAME,DEFINER,TIME_ZONE,EVENT_BODY,EVENT_DEFINITION,EVENT_DEFINITION_BYTES,EVENT_TYPE,EXECUTE_AT,INTERVAL_VALUE,INTERVAL_FIELD,STARTS,ENDS,STATUS,ON_COMPLETION,ORIGINATOR,SQL_MODE,CHARACTER_SET_CLIENT,COLLATION_CONNECTION,DATABASE_COLLATION", []string{"EVENT_SCHEMA", "EVENT_NAME"}},
	{"views", "VIEWS", "VIEW_DEFINITION", "TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME,VIEW_DEFINITION,VIEW_DEFINITION_BYTES,CHECK_OPTION,IS_UPDATABLE,DEFINER,SECURITY_TYPE,CHARACTER_SET_CLIENT,COLLATION_CONNECTION", []string{"TABLE_SCHEMA", "TABLE_NAME"}},
}

func (d definition) columns() []string { return strings.Split(d.fields, ",") }
func (d definition) query() string {
	var fields, order []string
	for _, f := range d.columns() {
		switch {
		case d.body != "" && f == d.body:
			fields = append(fields, "IF(OCTET_LENGTH("+f+") BETWEEN 1 AND 16384,"+f+",NULL)")
		case d.body != "" && f == d.body+"_BYTES":
			fields = append(fields, "CAST(OCTET_LENGTH("+d.body+") AS CHAR)")
		default:
			fields = append(fields, "CAST("+f+" AS CHAR CHARACTER SET utf8mb4)")
		}
	}
	for _, k := range d.keys {
		if k == "ORDINAL_POSITION" {
			order = append(order, k)
		} else {
			order = append(order, "BINARY "+k)
		}
	}
	return "SELECT " + strings.Join(fields, ",") + " FROM INFORMATION_SCHEMA." + d.table + " ORDER BY " + strings.Join(order, ",") + " LIMIT 10001"
}

type Query struct {
	Kind, SQL string
	Columns   int
}

// Fixed catalog projections. SHOW CREATE VIEW separately uses bounded,
// individually backtick-escaped identifiers from the observed view keys.
func Queries() []Query {
	out := []Query{{"identity", identitySQL, 11}, {"grants", grantsSQL, 1}}
	for _, d := range definitions {
		out = append(out, Query{d.kind, d.query(), len(d.columns())})
	}
	return out
}

type record map[string]sql.NullString

func text(r record, k string) (string, bool) { v := r[k]; return v.String, v.Valid }
func identifier(v string) bool {
	return len(v) > 0 && len(v) <= 256 && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func counter(v sql.NullString) (uint64, bool) {
	n, e := strconv.ParseUint(v.String, 10, 64)
	return n, v.Valid && e == nil && strconv.FormatUint(n, 10) == v.String
}
func routineKey(schema, name, kind string) string { return schema + "\x00" + name + "\x00" + kind }

var typeFields = []string{"DATA_TYPE", "CHARACTER_MAXIMUM_LENGTH", "CHARACTER_OCTET_LENGTH", "NUMERIC_PRECISION", "NUMERIC_SCALE", "DATETIME_PRECISION", "CHARACTER_SET_NAME", "COLLATION_NAME", "DTD_IDENTIFIER"}

type signature struct {
	kind     string
	next     uint64
	returned bool
	returns  []sql.NullString
}

func returnType(r record) []sql.NullString {
	var out []sql.NullString
	for _, k := range typeFields {
		out = append(out, r[k])
	}
	return out
}
func sameType(a, b []sql.NullString) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if a[n] != b[n] {
			return false
		}
	}
	return true
}

func crossCheck(d definition, r record, signatures map[string]*signature) error {
	if d.kind == "routines" {
		schema, _ := text(r, "ROUTINE_SCHEMA")
		name, _ := text(r, "ROUTINE_NAME")
		kind, _ := text(r, "ROUTINE_TYPE")
		specific, ok := text(r, "SPECIFIC_NAME")
		if !ok || specific != name || (kind != "PROCEDURE" && kind != "FUNCTION") {
			return ErrUnavailable
		}
		key := routineKey(schema, name, kind)
		if signatures[key] != nil {
			return ErrUnavailable
		}
		next := uint64(1)
		if kind == "FUNCTION" {
			next = 0
		}
		signatures[key] = &signature{kind: kind, next: next, returns: returnType(r)}
	}
	if d.kind == "parameters" {
		schema, _ := text(r, "SPECIFIC_SCHEMA")
		name, _ := text(r, "SPECIFIC_NAME")
		kind, _ := text(r, "ROUTINE_TYPE")
		s := signatures[routineKey(schema, name, kind)]
		ordinal, ok := counter(r["ORDINAL_POSITION"])
		if s == nil || !ok || ordinal != s.next {
			return ErrUnavailable
		}
		if ordinal == 0 {
			if kind != "FUNCTION" || r["PARAMETER_MODE"].Valid || r["PARAMETER_NAME"].Valid || !sameType(s.returns, returnType(r)) {
				return ErrUnavailable
			}
			s.returned = true
		} else {
			mode, m := text(r, "PARAMETER_MODE")
			name, n := text(r, "PARAMETER_NAME")
			if !m || !n || !identifier(name) || (mode != "IN" && mode != "OUT" && mode != "INOUT") || kind == "FUNCTION" && mode != "IN" {
				return ErrUnavailable
			}
		}
		s.next++
	}
	return nil
}

func readDomain(ctx context.Context, c *sql.Conn, d definition, total *int, signatures map[string]*signature, views *[]viewRef) (Digest, error) {
	rows, err := c.QueryContext(ctx, d.query())
	if err != nil {
		return Digest{}, ErrUnavailable
	}
	defer rows.Close()
	h := beginDigest(d.kind)
	var count uint64
	var previous []string
	var previousOrdinal uint64
	for rows.Next() {
		if ctx.Err() != nil || count >= maxRows {
			return Digest{}, ErrUnavailable
		}
		fields := d.columns()
		cells := make([]sql.NullString, len(fields))
		args := make([]any, len(fields))
		for n := range cells {
			args[n] = &cells[n]
		}
		if rows.Scan(args...) != nil {
			return Digest{}, ErrUnavailable
		}
		r := record{}
		cost := 9
		for n, v := range cells {
			if v.Valid {
				if len(v.String) > maxFieldBytes || !utf8.ValidString(v.String) {
					return Digest{}, ErrUnavailable
				}
				cost += 9 + len(v.String)
			} else {
				cost++
			}
			r[fields[n]] = v
		}
		if cost > maxTotalBytes-*total {
			return Digest{}, ErrUnavailable
		}
		*total += cost
		var key []string
		var ordinal uint64
		for _, k := range d.keys {
			v, ok := text(r, k)
			if k == "ORDINAL_POSITION" {
				var valid bool
				ordinal, valid = counter(r[k])
				if !valid {
					return Digest{}, ErrUnavailable
				}
				continue
			}
			if !ok || !identifier(v) {
				return Digest{}, ErrUnavailable
			}
			key = append(key, v)
		}
		if previous != nil {
			cmp := 0
			for n := range key {
				if cmp = strings.Compare(previous[n], key[n]); cmp != 0 {
					break
				}
			}
			if cmp > 0 || cmp == 0 && (d.kind != "parameters" || ordinal <= previousOrdinal) {
				return Digest{}, ErrUnavailable
			}
		}
		previous, previousOrdinal = key, ordinal
		if d.body != "" {
			body, ok := text(r, d.body)
			size, valid := counter(r[d.body+"_BYTES"])
			if !ok || !valid || len(body) == 0 || size != uint64(len(body)) {
				return Digest{}, ErrUnavailable
			}
		}
		if crossCheck(d, r, signatures) != nil {
			return Digest{}, ErrUnavailable
		}
		if d.kind == "events" {
			originator, valid := counter(r["ORIGINATOR"])
			if !valid || originator > 1<<32-1 {
				return Digest{}, ErrUnavailable
			}
		}
		if d.kind == "views" {
			client, clientOK := text(r, "CHARACTER_SET_CLIENT")
			collation, collationOK := text(r, "COLLATION_CONNECTION")
			if !clientOK || client == "" || !collationOK || collation == "" {
				return Digest{}, ErrUnavailable
			}
			*views = append(*views, viewRef{key[0], key[1], client, collation})
		}
		frame(h, cells)
		count++
	}
	if rows.Err() != nil || rows.Close() != nil {
		return Digest{}, ErrUnavailable
	}
	return finishDigest(h, count), nil
}

// Read owns only an observer connection. It never begins/commits a transaction,
// locks tables, invokes a stored program, executes DDL or borrows the GC tx.
// The two identity/grant checks do NOT prove a freeze between observations.
func (s *Source) Read(ctx context.Context) (Observation, error) {
	if s == nil || s.c.DB == nil || ctx == nil || ctx.Err() != nil {
		return Observation{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, maxReadTime)
	defer cancel()
	c, err := s.c.DB.Conn(ctx)
	if err != nil {
		return Observation{}, ErrUnavailable
	}
	defer c.Close()
	first, err := s.identity(ctx, c)
	if err != nil || s.readGrants(ctx, c) != nil {
		return Observation{}, ErrUnavailable
	}
	var pins []Digest
	total := 0
	signatures := map[string]*signature{}
	var views []viewRef
	for _, d := range definitions {
		p, e := readDomain(ctx, c, d, &total, signatures, &views)
		if e != nil {
			return Observation{}, ErrUnavailable
		}
		pins = append(pins, p)
	}
	for _, s := range signatures {
		if s.kind == "FUNCTION" && !s.returned {
			return Observation{}, ErrUnavailable
		}
	}
	creates, err := readViewCreates(ctx, c, views, &total)
	if err != nil || creates.Rows != pins[4].Rows {
		return Observation{}, ErrUnavailable
	}
	last, err := s.identity(ctx, c)
	if err != nil || last.id != first.id || last.now.Before(first.now) || last.now.Sub(first.now) > maxReadTime || s.readGrants(ctx, c) != nil || ctx.Err() != nil {
		return Observation{}, ErrUnavailable
	}
	h := beginDigest("scope")
	frame(h, []sql.NullString{{String: s.c.ServerUUID, Valid: true}, {String: s.c.Database, Valid: true}, {String: s.c.Account, Valid: true}, {String: s.c.Version, Valid: true}, {String: s.c.GrantsSHA256, Valid: true}})
	for n, p := range pins {
		frame(h, []sql.NullString{{String: definitions[n].kind, Valid: true}, {String: p.SHA256, Valid: true}, {String: strconv.FormatUint(p.Rows, 10), Valid: true}})
	}
	frame(h, []sql.NullString{{String: "view-create", Valid: true}, {String: creates.SHA256, Valid: true}, {String: strconv.FormatUint(creates.Rows, 10), Valid: true}})
	out := Observation{Digests{Triggers: pins[0], Routines: pins[1], Parameters: pins[2], Events: pins[3], Views: pins[4], ViewCreates: creates, Combined: finishDigest(h, 7).SHA256}, first.now, last.now}
	// Conn.Close can wait for the driver even after the final SQL checks.
	// A cancellation during that wait must not release a late observation.
	if c.Close() != nil || ctx.Err() != nil {
		return Observation{}, ErrUnavailable
	}
	return out, nil
}
