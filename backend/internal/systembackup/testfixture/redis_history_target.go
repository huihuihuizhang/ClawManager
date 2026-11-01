package testfixture

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// RedisHistoryTarget is an authenticated, isolated RESP protocol fixture, NOT
// a Redis engine. It stores opaque DUMP bytes and cannot certify Lua/RDB/ACL
// engine behavior. Readers never write; revoked writers lose authentication.
type RedisHistoryTarget struct {
	Address         string
	mu              sync.Mutex
	keys            map[string]RedisKey
	known           []RedisKey
	revoked         bool
	failAfter       int // guarded by mu; 0 disables injected failure
	restoreAttempts int
}

func NewRedisHistoryTarget(t testing.TB, known []RedisKey) *RedisHistoryTarget {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &RedisHistoryTarget{Address: l.Addr().String(), keys: map[string]RedisKey{}, known: known}
	var wg sync.WaitGroup
	var mu sync.Mutex
	conns := map[net.Conn]bool{}
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(conns, c); mu.Unlock() }()
				r := bufio.NewReader(c)
				user := ""
				for {
					args, err := readCommand(r)
					if err != nil || len(args) == 0 {
						return
					}
					op := string(args[0])
					f.mu.Lock()
					var reply any
					denied := false
					if op == "AUTH" {
						if len(args) != 3 || string(args[2]) != "named-fixture-password" || (string(args[1]) != "writer" && string(args[1]) != "reader") || (string(args[1]) == "writer" && f.revoked) {
							denied = true
						} else {
							user = string(args[1])
							reply = redisStatus("OK")
						}
					} else if user == "" || (user == "writer" && f.revoked) {
						denied = true
					} else {
						switch op {
						case "SELECT":
							reply = redisStatus("OK")
						case "INFO":
							reply = []byte("run_id:" + strings.Repeat("b", 40) + "\r\n")
						case "DBSIZE":
							reply = int64(len(f.keys))
						case "RESTORE":
							f.restoreAttempts++
							if user != "writer" || len(args) != 4 || string(args[2]) != "0" || !strings.HasPrefix(string(args[1]), "cm:restore-history:sdr_") || (f.failAfter > 0 && len(f.keys) >= f.failAfter) {
								denied = true
								break
							}
							if _, exists := f.keys[string(args[1])]; exists {
								denied = true
								break
							}
							found := false
							for _, k := range f.known {
								if bytes.Equal(k.Dump, args[3]) {
									k.Key = string(args[1])
									k.Dump = append([]byte(nil), k.Dump...)
									k.PTTL = -1
									f.keys[k.Key] = k
									found = true
									break
								}
							}
							if !found {
								denied = true
							} else {
								reply = redisStatus("OK")
							}
						case "EVAL_RO":
							if len(args) != 4 || string(args[2]) != "1" {
								denied = true
								break
							}
							k, ok := f.keys[string(args[3])]
							if !ok {
								denied = true
								break
							}
							reply = []any{k.Dump, []byte(k.Type), int64(-1)}
						default:
							denied = true
						}
					}
					f.mu.Unlock()
					if denied {
						if _, err = io.WriteString(c, "-NOPERM named fixture denies operation\r\n"); err != nil {
							return
						}
					} else if writeReply(c, reply) != nil {
						return
					}
				}
			}()
		}
	}()
	return f
}

func (f *RedisHistoryTarget) RevokeWriter()      { f.mu.Lock(); defer f.mu.Unlock(); f.revoked = true }
func (f *RedisHistoryTarget) SetFailAfter(n int) { f.mu.Lock(); defer f.mu.Unlock(); f.failAfter = n }
func (f *RedisHistoryTarget) RestoreAttempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.restoreAttempts
}
func (f *RedisHistoryTarget) Keys() []RedisKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []RedisKey
	for _, k := range f.keys {
		k.Dump = append([]byte(nil), k.Dump...)
		out = append(out, k)
	}
	return out
}
