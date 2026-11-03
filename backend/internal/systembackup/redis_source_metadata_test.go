package systembackup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This fixture exercises the actual RedisClient RESP command/parser with a
// controlled pipe. It does not claim TLS factory or a complete V2 owner proof.
func TestSourceRedisMetadataCompleteScopedProtocol(t *testing.T) {
	for _, mode := range []string{"complete", "empty", "wrong-account", "wrong-server", "foreign-scan", "cursor-cycle", "unknown-type", "malformed-groups", "duplicate-row", "revoked-at-script", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			policy := redisSourcePolicyFixture()
			if mode == "capacity" {
				policy.Policy.MaxBytes = 8
			}
			local, remote := net.Pipe()
			t.Cleanup(func() { local.Close(); remote.Close() })
			client := &RedisClient{conn: local, reader: bufio.NewReader(local), max: 1 << 20, database: 2}
			var revoked atomic.Bool
			commands := make(chan []string, 1)
			go func() {
				defer remote.Close()
				var observed []string
				defer func() { commands <- observed }()
				reader := bufio.NewReader(remote)
				scan := 0
				for {
					budget := int64(1 << 20)
					value, err := readRedisReply(reader, &budget, 0)
					if err != nil {
						return
					}
					row, ok := value.([]any)
					if !ok || len(row) == 0 {
						return
					}
					args := make([][]byte, len(row))
					for n, item := range row {
						var valid bool
						args[n], valid = item.([]byte)
						if !valid {
							return
						}
					}
					op := string(args[0])
					observed = append(observed, op)
					var reply any
					switch op {
					case "ACL":
						if len(args) != 2 || string(args[1]) != "WHOAMI" {
							return
						}
						reply = []byte("original-reader")
						if mode == "wrong-account" {
							reply = []byte("other-reader")
						}
					case "INFO":
						server := policy.ServerID
						if mode == "wrong-server" {
							server = strings.Repeat("c", 40)
						}
						reply = []byte("run_id:" + server + "\r\n")
					case "SCAN":
						if len(args) != 6 || string(args[2]) != "MATCH" || string(args[3]) != "app:*" || string(args[4]) != "COUNT" {
							return
						}
						scan++
						if mode == "empty" {
							reply = []any{[]byte("0"), []any{}}
						} else if scan == 1 {
							key := "app:events"
							if mode == "foreign-scan" {
								key = "outside:key"
							}
							reply = []any{[]byte("1"), []any{[]byte(key), []byte("app:control:lease")}}
						} else {
							cursor := "0"
							if mode == "cursor-cycle" {
								cursor = "1"
							}
							reply = []any{[]byte(cursor), []any{[]byte("app:state")}}
						}
					case "EVAL_RO":
						if len(args) < 3 {
							return
						}
						script := string(args[1])
						if !strings.Contains(script, "TYPE") || !strings.Contains(script, "XINFO") || strings.Contains(script, "DUMP") || strings.Contains(script, "PTTL") || strings.Contains(script, "RESTORE") {
							return
						}
						if mode == "revoked-at-script" {
							revoked.Store(true)
						}
						if mode == "empty" {
							if len(args) != 3 || string(args[2]) != "0" {
								return
							}
							reply = []any{}
						} else {
							if len(args) != 5 || string(args[2]) != "2" || string(args[3]) != "app:events" || string(args[4]) != "app:state" {
								return
							}
							groups := []any{[]any{[]byte("name"), []byte("workers"), []byte("consumers"), int64(1), []byte("pending"), int64(2), []byte("last-delivered-id"), []byte("1-0")}}
							if mode == "malformed-groups" {
								groups = []any{[]any{[]byte("unknown"), []byte("value")}}
							}
							kind := "stream"
							if mode == "unknown-type" {
								kind = "module-type"
							}
							items := []any{[]any{[]byte("app:events"), []byte(kind), groups}, []any{[]byte("app:state"), []byte("string"), []any{}}}
							if mode == "duplicate-row" {
								items[1] = items[0]
							}
							reply = items
						}
					default:
						return
					}
					if writeSourceRedisMetadataReply(remote, reply) != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			calls := 0
			actual, err := ObserveSourceRedisMetadata(ctx, client, policy, "original-reader", func(context.Context) error {
				calls++
				if revoked.Load() {
					return errors.New("revoked")
				}
				return nil
			})
			client.Close()
			var observed []string
			select {
			case observed = <-commands:
			case <-ctx.Done():
				t.Fatal("protocol fixture did not finish")
			}
			valid := mode == "complete" || mode == "empty"
			if !valid {
				if err == nil {
					t.Fatal("incomplete or unauthorized metadata accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "complete" && (len(actual) != 2 || string(actual[0].Key) != "app:events" || actual[0].Type != "stream" || !validRedisSourceGroups(actual[0].Groups) || string(actual[1].Key) != "app:state") {
				t.Fatal("lost complete original scoped key/group metadata")
			}
			if mode == "empty" && len(actual) != 0 {
				t.Fatal("empty native result changed")
			}
			scripts := 0
			for _, op := range observed {
				if op == "EVAL_RO" {
					scripts++
				}
				if op != "ACL" && op != "INFO" && op != "SCAN" && op != "EVAL_RO" {
					t.Fatal("unexpected value read or mutation", op)
				}
			}
			if scripts != 1 || calls < 8 {
				t.Fatal("missing bounded script or original checks")
			}
		})
	}
}

func writeSourceRedisMetadataReply(dst io.Writer, value any) error {
	switch v := value.(type) {
	case []byte:
		if _, err := fmt.Fprintf(dst, "$%d\r\n", len(v)); err != nil {
			return err
		}
		if _, err := dst.Write(v); err != nil {
			return err
		}
		_, err := io.WriteString(dst, "\r\n")
		return err
	case int64:
		_, err := fmt.Fprintf(dst, ":%d\r\n", v)
		return err
	case []any:
		if _, err := fmt.Fprintf(dst, "*%d\r\n", len(v)); err != nil {
			return err
		}
		for _, item := range v {
			if err := writeSourceRedisMetadataReply(dst, item); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("invalid metadata fixture reply")
	}
}
