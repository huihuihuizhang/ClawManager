package systembackupgcmetadata

import (
	"context"
	"database/sql"
	"strings"
	"unicode/utf8"
)

// Retain only bounded keys and compile context, never view bodies, while the
// catalog rows are open. SHOW statements must wait until those rows are closed.
type viewRef struct{ schema, name, client, collation string }

// The full CREATE wrapper adds identifiers and attributes to the already
// bounded 16 KiB SELECT definition. The common aggregate budget still applies.
const maxCreateBytes = 2 * maxFieldBytes

func viewCreateSQL(v viewRef) (string, error) {
	if !identifier(v.schema) || !identifier(v.name) {
		return "", ErrUnavailable
	}
	quote := func(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
	return "SHOW CREATE VIEW " + quote(v.schema) + "." + quote(v.name), nil
}

func readViewCreate(ctx context.Context, c *sql.Conn, v viewRef, total *int) ([]sql.NullString, error) {
	query, err := viewCreateSQL(v)
	if err != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	rows, err := c.QueryContext(ctx, query)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	var name, create, client, collation sql.NullString
	if !rows.Next() || rows.Scan(&name, &create, &client, &collation) != nil {
		return nil, ErrUnavailable
	}
	if !name.Valid || name.String != v.name || !create.Valid || !strings.HasPrefix(create.String, "CREATE ") || !client.Valid || client.String != v.client || !collation.Valid || collation.String != v.collation {
		return nil, ErrUnavailable
	}
	// A SHOW response cannot be server-side LIMIT/IF capped. These limits bound
	// accepted/local framed data, not the driver's packet allocation. Actual
	// deployment must also review driver packet limits and MySQL behavior.
	cells := []sql.NullString{{String: v.schema, Valid: true}, name, create, client, collation}
	cost := 9
	for n, cell := range cells {
		limit := maxFieldBytes
		if n == 2 {
			limit = maxCreateBytes
		}
		if len(cell.String) > limit || !utf8.ValidString(cell.String) {
			return nil, ErrUnavailable
		}
		cost += 9 + len(cell.String)
	}
	if cost > maxTotalBytes-*total || rows.Next() || rows.NextResultSet() || rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	*total += cost
	return cells, nil
}

func readViewCreates(ctx context.Context, c *sql.Conn, views []viewRef, total *int) (Digest, error) {
	if len(views) > maxRows {
		return Digest{}, ErrUnavailable
	}
	h := beginDigest("view-create")
	for _, view := range views {
		cells, err := readViewCreate(ctx, c, view, total)
		if err != nil {
			return Digest{}, ErrUnavailable
		}
		frame(h, cells)
	}
	return finishDigest(h, uint64(len(views))), nil
}
