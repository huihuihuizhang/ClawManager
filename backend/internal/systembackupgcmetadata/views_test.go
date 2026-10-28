package systembackupgcmetadata

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
)

func TestViewCreateAlgorithmAndIdentifierBinding(t *testing.T) {
	t.Run("independent_framing", func(t *testing.T) {
		m, s := fixture(t)
		o, e := s.Read(context.Background())
		if e != nil || o.Digests().ViewCreates.SHA256 != "1b1c825fae16fe4e2b5d187ee89dee1fb70bf213fae4f930d14d8f3782a8bba4" {
			t.Fatal("independent CREATE frame", e, o.Digests())
		}
		m.rows["views"] = nil
		o, e = s.Read(context.Background())
		if e != nil || o.Digests().ViewCreates.SHA256 != "ff181e67d549e334d4a9c47c9ecda298384965698953aebd398ed8fde194288b" || o.Digests().ViewCreates.Rows != 0 {
			t.Fatal("independent empty CREATE frame", e, o.Digests())
		}
	})
	for _, algorithm := range []string{"MERGE", "TEMPTABLE"} {
		t.Run(algorithm, func(t *testing.T) {
			m, s := fixture(t)
			before, e := s.Read(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			m.viewResponse = func(row []driver.Value) [][]driver.Value {
				row[1] = strings.Replace(row[1].(string), "ALGORITHM=UNDEFINED", "ALGORITHM="+algorithm, 1)
				return [][]driver.Value{row}
			}
			after, e := s.Read(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			a, b := before.Digests(), after.Digests()
			if a.Views != b.Views || a.ViewCreates == b.ViewCreates || a.Combined == b.Combined || b.ViewCreates.Rows != b.Views.Rows {
				t.Fatal("ALGORITHM change absent from combined observation")
			}
		})
	}
	t.Run("quoted_names", func(t *testing.T) {
		m, s := fixture(t)
		d := definitions[4]
		m.rows["views"][0][cell(d, "TABLE_SCHEMA")] = "库`名"
		m.rows["views"][0][cell(d, "TABLE_NAME")] = "v`; DROP TABLE x; --"
		if _, e := s.Read(context.Background()); e != nil {
			t.Fatal(e)
		}
		want := "SHOW CREATE VIEW `库``名`.`v``; DROP TABLE x; --`"
		found := false
		for _, q := range m.queries {
			if q == want {
				found = true
			}
		}
		if !found {
			t.Fatal("identifier quoting changed SQL statement boundary", m.queries)
		}
	})
	for _, name := range []string{"", "bad\x00name", "\xff", strings.Repeat("x", 257)} {
		if q, e := viewCreateSQL(viewRef{schema: "sample", name: name}); !errors.Is(e, ErrUnavailable) || q != "" {
			t.Fatal("bad view name accepted")
		}
		if q, e := viewCreateSQL(viewRef{schema: name, name: "view_a"}); !errors.Is(e, ErrUnavailable) || q != "" {
			t.Fatal("bad schema name accepted")
		}
	}
}

func TestViewCreateFailuresAndBounds(t *testing.T) {
	for _, mode := range []string{"query", "scan", "read", "close", "resultset", "missing", "multiple", "name", "null_name", "null_create", "empty_create", "non_create", "null_client", "client", "null_collation", "collation", "oversize", "bad_utf8", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			m, s := fixture(t)
			m.viewFault = mode
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.viewResponse = func(row []driver.Value) [][]driver.Value {
				switch mode {
				case "missing":
					return nil
				case "multiple":
					return [][]driver.Value{row, append([]driver.Value(nil), row...)}
				case "name":
					row[0] = "other_view"
				case "null_name":
					row[0] = nil
				case "null_create":
					row[1] = nil
				case "empty_create":
					row[1] = ""
				case "non_create":
					row[1] = "SELECT 1"
				case "null_client":
					row[2] = nil
				case "client":
					row[2] = "latin1"
				case "null_collation":
					row[3] = nil
				case "collation":
					row[3] = "utf8mb4_general_ci"
				case "oversize":
					row[1] = "CREATE " + strings.Repeat("a", maxCreateBytes)
				case "bad_utf8":
					row[1] = "CREATE \xff"
				}
				return [][]driver.Value{row}
			}
			if mode == "canceled" {
				m.onQuery = func(kind string) {
					if kind == "view-create" {
						cancel()
					}
				}
			}
			denied(t, m, s, ctx)
		})
	}
	t.Run("create_exact_byte_bound", func(t *testing.T) {
		m, s := fixture(t)
		m.viewResponse = func(row []driver.Value) [][]driver.Value {
			row[1] = "CREATE " + strings.Repeat("a", maxCreateBytes-len("CREATE "))
			return [][]driver.Value{row}
		}
		if _, e := s.Read(context.Background()); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("shared_aggregate_budget", func(t *testing.T) {
		m, s := fixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), maxReadTime)
		defer cancel()
		c, e := s.c.DB.Conn(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		total := maxTotalBytes - 1
		p, e := readViewCreates(ctx, c, []viewRef{{"sample", "view_a", "utf8mb4", "utf8mb4_bin"}}, &total)
		if !errors.Is(e, ErrUnavailable) || p != (Digest{}) || total != maxTotalBytes-1 {
			t.Fatal("SHOW data escaped shared aggregate bound")
		}
		if m.openRows != 0 {
			t.Fatal("failed SHOW leaked rows")
		}
	})
	t.Run("view_count_bound", func(t *testing.T) {
		total := 0
		if p, e := readViewCreates(context.Background(), nil, make([]viewRef, maxRows+1), &total); !errors.Is(e, ErrUnavailable) || p != (Digest{}) {
			t.Fatal("view count bound")
		}
	})
}

func TestEventOriginatorIsPartOfObservation(t *testing.T) {
	for _, value := range []driver.Value{nil, "", "-1", "01", "4294967296", "bad"} {
		m, s := fixture(t)
		m.rows["events"][0][cell(definitions[3], "ORIGINATOR")] = value
		denied(t, m, s, context.Background())
	}
	for _, value := range []string{"0", "2", "4294967295"} {
		t.Run(value, func(t *testing.T) {
			m, s := fixture(t)
			a, e := s.Read(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			m.rows["events"][0][cell(definitions[3], "ORIGINATOR")] = value
			b, e := s.Read(context.Background())
			if e != nil || a.Digests().Events == b.Digests().Events || a.Digests().Combined == b.Digests().Combined {
				t.Fatal("originator omitted", e)
			}
		})
	}
}
