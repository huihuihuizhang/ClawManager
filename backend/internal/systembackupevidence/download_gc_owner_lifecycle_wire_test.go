package systembackupevidence

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

var dGCOwnerLifecycleCases = []string{"known_commit_unlock", "known_commit_discard", "known_rollback_discard", "commit_reply_lost", "rollback_reply_lost", "unlock_reply_lost", "canceled_holder", "killed_holder"}

const (
	dGCLifecycleCommit uint32 = iota + 1
	dGCLifecycleRollback
	dGCLifecycleUnlock
	dGCLifecycleLock
)

var dGCLifecycleWireInvalid = errors.New("lifecycle wire fault did not observe the exact command and bounded terminal OK")

// Test transport only. Arming is explicit and single-use, after the preceding
// command has finished. Read consumes a real terminal OK and closes the socket
// without returning any of that packet to the SQL driver. It never invents a
// driver error after a successful driver Commit/Rollback response.
type dGCLifecycleFaultConn struct {
	net.Conn
	armed   atomic.Uint32
	used    atomic.Bool
	seen    atomic.Bool
	dropped atomic.Bool
	counts  [5]atomic.Int32
}

func dGCLifecycleSQL(kind uint32) string {
	switch kind {
	case dGCLifecycleCommit:
		return "COMMIT"
	case dGCLifecycleRollback:
		return "ROLLBACK"
	case dGCLifecycleUnlock:
		return "UNLOCK INSTANCE"
	case dGCLifecycleLock:
		return "LOCK INSTANCE FOR BACKUP"
	}
	return ""
}
func (c *dGCLifecycleFaultConn) arm(kind uint32) error {
	if kind < dGCLifecycleCommit || kind > dGCLifecycleUnlock || !c.used.CompareAndSwap(false, true) {
		return dGCLifecycleWireInvalid
	}
	c.armed.Store(kind)
	return nil
}
func (c *dGCLifecycleFaultConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil && n == len(p) && len(p) >= 5 && p[3] == 0 && p[4] == 3 {
		length := int(p[0]) | int(p[1])<<8 | int(p[2])<<16
		if length == len(p)-4 {
			for kind := dGCLifecycleCommit; kind <= dGCLifecycleLock; kind++ {
				if string(p[5:]) == dGCLifecycleSQL(kind) {
					c.counts[kind].Add(1)
					if c.armed.Load() == kind {
						c.seen.Store(true)
					}
				}
			}
		}
	}
	return n, err
}
func (c *dGCLifecycleFaultConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.armed.Load() == 0 {
		return c.Conn.Read(p)
	}
	fail := func() (int, error) { _ = c.Conn.Close(); return 0, dGCLifecycleWireInvalid }
	if !c.seen.Load() {
		return fail()
	}
	var header [4]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return fail()
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if header[3] != 1 || length < 7 || length > 1024 {
		return fail()
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return fail()
	}
	// For these exact three commands, affected_rows/last_insert_id must be zero
	// and SERVER_STATUS_IN_TRANS must be absent. ERR/EOF and partial packets deny.
	if payload[0] != 0 || payload[1] != 0 || payload[2] != 0 || payload[3]&9 != 0 {
		return fail()
	}
	c.dropped.Store(true)
	c.armed.Store(0)
	_ = c.Conn.Close()
	return 0, io.EOF
}
func dGCLifecyclePacket(sequence byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), sequence}, payload...)
}

func TestDDownloadGCOwnerLifecycleCaseCatalog(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range dGCOwnerLifecycleCases {
		if name == "" || seen[name] {
			t.Fatal("ambiguous lifecycle case catalog")
		}
		seen[name] = true
	}
	if len(seen) != 8 {
		t.Fatal("lifecycle case count")
	}
}
func TestDDownloadGCLifecycleWireResponseLoss(t *testing.T) {
	ok := dGCLifecyclePacket(1, []byte{0, 0, 0, 2, 0, 0, 0})
	tests := []struct {
		name        string
		kind        uint32
		command     string
		reply       []byte
		fragment    bool
		wantDrop    bool
		passthrough bool
	}{
		{name: "commit_ok", kind: dGCLifecycleCommit, command: "COMMIT", reply: ok, wantDrop: true},
		{name: "rollback_ok", kind: dGCLifecycleRollback, command: "ROLLBACK", reply: ok, wantDrop: true},
		{name: "unlock_ok", kind: dGCLifecycleUnlock, command: "UNLOCK INSTANCE", reply: ok, wantDrop: true},
		{name: "fragmented_ok", kind: dGCLifecycleCommit, command: "COMMIT", reply: ok, fragment: true, wantDrop: true},
		{name: "unarmed_passthrough", command: "COMMIT", reply: ok, passthrough: true},
		{name: "wrong_command", kind: dGCLifecycleCommit, command: "ROLLBACK", reply: ok},
		{name: "error_packet", kind: dGCLifecycleCommit, command: "COMMIT", reply: dGCLifecyclePacket(1, []byte{255, 1, 2, '#', 'H', 'Y', '0', '0', '0'})},
		{name: "eof_packet", kind: dGCLifecycleCommit, command: "COMMIT", reply: dGCLifecyclePacket(1, []byte{254, 0, 0, 0, 0})},
		{name: "wrong_sequence", kind: dGCLifecycleCommit, command: "COMMIT", reply: dGCLifecyclePacket(2, []byte{0, 0, 0, 2, 0, 0, 0})},
		{name: "still_in_transaction", kind: dGCLifecycleCommit, command: "COMMIT", reply: dGCLifecyclePacket(1, []byte{0, 0, 0, 3, 0, 0, 0})},
		{name: "more_results", kind: dGCLifecycleCommit, command: "COMMIT", reply: dGCLifecyclePacket(1, []byte{0, 0, 0, 10, 0, 0, 0})},
		{name: "short_ok", kind: dGCLifecycleCommit, command: "COMMIT", reply: dGCLifecyclePacket(1, []byte{0})},
		{name: "oversized", kind: dGCLifecycleCommit, command: "COMMIT", reply: []byte{1, 4, 0, 1}},
		{name: "truncated_header", kind: dGCLifecycleCommit, command: "COMMIT", reply: []byte{7, 0}},
		{name: "truncated_body", kind: dGCLifecycleCommit, command: "COMMIT", reply: []byte{7, 0, 0, 1, 0, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { client.Close(); server.Close() })
			deadline := time.Now().Add(5 * time.Second)
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)
			wire := &dGCLifecycleFaultConn{Conn: client}
			if tc.kind != 0 {
				if wire.arm(tc.kind) != nil {
					t.Fatal("arm rejected")
				}
				if wire.arm(tc.kind) != dGCLifecycleWireInvalid {
					t.Fatal("fault armed twice")
				}
			}
			request := dGCLifecyclePacket(0, append([]byte{3}, []byte(tc.command)...))
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				received := make([]byte, len(request))
				if _, err := io.ReadFull(server, received); err != nil {
					done <- err
					return
				}
				if !bytes.Equal(received, request) {
					done <- errors.New("request changed")
					return
				}
				if tc.fragment {
					for _, b := range tc.reply {
						if _, err := server.Write([]byte{b}); err != nil {
							done <- err
							return
						}
					}
				} else {
					_, _ = server.Write(tc.reply)
				}
				done <- nil
			}()
			if n, err := wire.Write(request); err != nil || n != len(request) {
				t.Fatal("request transport failed", err)
			}
			out := make([]byte, len(tc.reply))
			if tc.passthrough {
				if _, err := io.ReadFull(wire, out); err != nil || !bytes.Equal(out, tc.reply) {
					t.Fatal("unarmed bytes changed", err)
				}
			} else {
				n, err := wire.Read(out)
				if n != 0 {
					t.Fatal("fault leaked response bytes")
				}
				if tc.wantDrop && err != io.EOF || !tc.wantDrop && err != dGCLifecycleWireInvalid {
					t.Fatal("wrong fault outcome", err)
				}
			}
			if wire.dropped.Load() != tc.wantDrop {
				t.Fatal("invalid packet claimed as a dropped success")
			}
			if wire.counts[dGCLifecycleCommit].Load() != int32(boolToGCLifecycleInt(tc.command == "COMMIT")) || wire.counts[dGCLifecycleRollback].Load() != int32(boolToGCLifecycleInt(tc.command == "ROLLBACK")) {
				t.Fatal("wire command count changed")
			}
			select {
			case err := <-done:
				if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal("wire peer request failed", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("wire peer did not stop")
			}
		})
	}
}
func boolToGCLifecycleInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
