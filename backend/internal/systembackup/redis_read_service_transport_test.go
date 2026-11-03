package systembackup

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Protocol fixture only: it verifies that an invalid/unknown reply cannot be
// left on the original ordered stream and consumed as a later success.
func TestRedisReadServiceTransportPoisonsUnknownReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	peer := make(chan error, 1)
	go func() {
		request := make([]byte, len("*1\r\n$4\r\nPING\r\n"))
		if _, e := io.ReadFull(server, request); e != nil {
			peer <- e
			return
		}
		_, e := server.Write([]byte("?unknown\r\n"))
		peer <- e
	}()
	g := &RedisReadServiceGate{admin: &RedisClient{conn: client, reader: bufio.NewReader(client), max: 1024}}
	if _, e := g.command(ctx, []byte("PING")); e == nil || !g.transportFailed {
		t.Fatal("unknown reply left a reusable native stream")
	}
	if e := <-peer; e != nil {
		t.Fatal(e)
	}
	if _, e := g.command(ctx, []byte("PING")); e == nil {
		t.Fatal("poisoned stream accepted another command")
	}
}
