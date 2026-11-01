package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A disposable localhost TLS server and SELECT/session-only statements exercise
// the production source/restore transport. This grants no task/source authority.
// Exact quote, binary, NULL and Unicode values must survive both SQL modes;
// the server counter proves queries avoid implicit prepare round trips.
func TestDatabaseTransportPreservesNativeParametersWithoutPrepare(t *testing.T) {
	file := os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS")
	if file == "" {
		t.Skip("requires the separate owned localhost TLS MySQL fixture")
	}
	var credential struct {
		Host, User, Password, CAFile, TLSServerName, ServerUUID string
		Port                                                int
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.ServerUUID != "f3756194-d52b-11f1-b8cc-745d22085e06" {
		t.Fatal("owned TLS fixture identity unavailable")
	}
	clear(raw)
	ca, err := os.ReadFile(credential.CAFile)
	if err != nil {
		t.Fatal("owned TLS CA unavailable")
	}
	spec := DatabaseSpec{Address: net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port)), Name: "information_schema", ServerUUID: credential.ServerUUID, TLSServerName: credential.TLSServerName, RootCA: ca, MaxRows: 1, MaxMemoryBytes: 1 << 20}
	secret := &DatabaseCredential{Username: credential.User, Password: []byte(credential.Password)}
	db, err := OpenDatabase(&spec, secret)
	clear(secret.Password)
	credential.Password = ""
	if err != nil {
		t.Fatal("production transport construction failed")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal("owned TLS connection failed")
	}
	defer conn.Close()
	var uuid, zone, mode, name, cipher string
	if conn.QueryRowContext(ctx, "SELECT @@server_uuid,@@session.time_zone,@@session.sql_mode").Scan(&uuid, &zone, &mode) != nil || uuid != spec.ServerUUID || zone != "+00:00" || conn.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&name, &cipher) != nil || cipher == "" {
		t.Fatal("original TLS/UUID/UTC pins changed")
	}
	preparedCount := func() uint64 {
		t.Helper()
		var key string
		var count uint64
		if conn.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Com_stmt_prepare'").Scan(&key, &count) != nil {
			t.Fatal("native session statement counter unavailable")
		}
		return count
	}
	before := preparedCount()
	var originalModes []string
	for _, value := range strings.Split(mode, ",") {
		if value != "NO_BACKSLASH_ESCAPES" && value != "" {
			originalModes = append(originalModes, value)
		}
	}
	for _, noBackslash := range []bool{false, true} {
		activeModes := append([]string{}, originalModes...)
		if noBackslash {
			activeModes = append(activeModes, "NO_BACKSLASH_ESCAPES")
		}
		if _, err := conn.ExecContext(ctx, "SET SESSION sql_mode = ?", strings.Join(activeModes, ",")); err != nil {
			t.Fatal("session-only mode setup failed")
		}
		for _, sample := range []struct {
			value any
			want  []byte
		}{
			{"literal'; SELECT 'unexpected'; -- 中文\\\x00\n\r\x1a\"", []byte("literal'; SELECT 'unexpected'; -- 中文\\\x00\n\r\x1a\"")},
			{[]byte{0, 255, '\'', '\\', 0, 26}, []byte{0, 255, '\'', '\\', 0, 26}},
			{nil, nil}, {"", []byte{}}, {int64(-123456789), []byte("-123456789")},
		} {
			var got []byte
			if err := conn.QueryRowContext(ctx, "SELECT ?", sample.value).Scan(&got); err != nil || !bytes.Equal(got, sample.want) || (got == nil) != (sample.want == nil) {
				t.Fatal("parameter bytes/null semantics changed", noBackslash, err)
			}
		}
	}
	if after := preparedCount(); after != before {
		t.Fatalf("production transport used implicit prepare round trips: before=%d after=%d", before, after)
	}
}
