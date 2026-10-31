// Package testfixture contains named local protocol fixtures, never production
// source adapters or evidence. RedisProtocol does not execute Lua or certify
// Redis DUMP internals; it exercises real TCP/TLS/RESP/source authorization.
package testfixture

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type RedisKey struct {
	Key, Type string
	Dump      []byte
	PTTL      int64
	Groups    []any
}
type RedisScenario struct {
	ExpectedUser, ExpectedPassword string
	TLS                            bool
	ServerID                       string
	Keys                           []RedisKey
	PageSize                       int
	RepeatCursor                   bool
	ClockOffset                    time.Duration
	BeforeCommand                  func(string)
}
type RedisProtocol struct {
	Address  string
	CAPEM    []byte
	mu       sync.Mutex
	commands []string
}

func NewRedisProtocol(t testing.TB, scenario RedisScenario) *RedisProtocol {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &RedisProtocol{Address: listener.Addr().String()}
	if scenario.TLS {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "redis-fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		fixture.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	}
	if scenario.ServerID == "" {
		scenario.ServerID = strings.Repeat("a", 40)
	}
	if scenario.PageSize <= 0 {
		scenario.PageSize = 2
	}
	var active sync.WaitGroup
	var connectionsMu sync.Mutex
	connections := map[net.Conn]bool{}
	t.Cleanup(func() {
		listener.Close()
		connectionsMu.Lock()
		for conn := range connections {
			conn.Close()
		}
		connectionsMu.Unlock()
		active.Wait()
	})
	active.Add(1)
	go func() {
		defer active.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connectionsMu.Lock()
			connections[conn] = true
			connectionsMu.Unlock()
			active.Add(1)
			go func() {
				defer active.Done()
				defer conn.Close()
				defer func() { connectionsMu.Lock(); delete(connections, conn); connectionsMu.Unlock() }()
				reader := bufio.NewReader(conn)
				for {
					args, err := readCommand(reader)
					if err != nil {
						return
					}
					if len(args) == 0 {
						return
					}
					op := string(args[0])
					fixture.mu.Lock()
					fixture.commands = append(fixture.commands, op)
					fixture.mu.Unlock()
					if scenario.BeforeCommand != nil {
						scenario.BeforeCommand(op)
					}
					var reply any
					switch op {
					case "AUTH":
						if scenario.ExpectedPassword != "" && (len(args) != 3 || string(args[1]) != scenario.ExpectedUser || string(args[2]) != scenario.ExpectedPassword) {
							io.WriteString(conn, "-WRONGPASS source authentication denied\r\n")
							continue
						}
						reply = redisStatus("OK")
					case "SELECT":
						reply = redisStatus("OK")
					case "INFO":
						reply = []byte("# Server\r\nrun_id:" + scenario.ServerID + "\r\n")
					case "SCAN":
						if len(args) < 2 {
							return
						}
						offset, err := strconv.Atoi(string(args[1]))
						if err != nil || offset < 0 {
							return
						}
						prefix := ""
						for n := 2; n+1 < len(args); n += 2 {
							if string(args[n]) == "MATCH" {
								prefix = strings.TrimSuffix(string(args[n+1]), "*")
							}
						}
						var matches []any
						for _, key := range scenario.Keys {
							if strings.HasPrefix(key.Key, prefix) {
								matches = append(matches, []byte(key.Key))
							}
						}
						if offset > len(matches) {
							return
						}
						end := offset + scenario.PageSize
						if end > len(matches) {
							end = len(matches)
						}
						next := "0"
						if end < len(matches) {
							next = strconv.Itoa(end)
						}
						if scenario.RepeatCursor {
							next = "1"
						}
						reply = []any{[]byte(next), matches[offset:end]}
					case "EVAL_RO":
						if len(args) < 4 || !strings.Contains(string(args[1]), "XINFO") || !strings.Contains(string(args[1]), "TIME") {
							return
						}
						count, err := strconv.Atoi(string(args[2]))
						if err != nil || count < 0 || len(args) != count+4 {
							return
						}
						at := time.Now().Add(scenario.ClockOffset)
						replyItems := []any{[]byte(strconv.FormatInt(at.Unix(), 10)), []byte(strconv.FormatInt(int64(at.Nanosecond()/1000), 10))}
						for _, requested := range args[3 : 3+count] {
							for _, key := range scenario.Keys {
								if string(requested) == key.Key {
									groups := key.Groups
									if groups == nil {
										groups = []any{}
									}
									replyItems = append(replyItems, []any{[]byte(key.Key), key.Dump, []byte(key.Type), key.PTTL, groups})
								}
							}
						}
						reply = replyItems
					default:
						return
					}
					if writeReply(conn, reply) != nil {
						return
					}
				}
			}()
		}
	}()
	return fixture
}

func (f *RedisProtocol) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.commands...)
}

type redisStatus string

func writeReply(dst io.Writer, value any) error {
	switch v := value.(type) {
	case redisStatus:
		_, err := fmt.Fprintf(dst, "+%s\r\n", v)
		return err
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
			if err := writeReply(dst, item); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid fixture RESP type")
	}
}
func readCommand(reader *bufio.Reader) ([][]byte, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") || !strings.HasSuffix(line, "\r\n") {
		return nil, io.ErrUnexpectedEOF
	}
	count, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(line, "*"), "\r\n"))
	if err != nil || count < 1 || count > 10004 {
		return nil, io.ErrUnexpectedEOF
	}
	var args [][]byte
	var total int
	for n := 0; n < count; n++ {
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "$") || !strings.HasSuffix(line, "\r\n") {
			return nil, io.ErrUnexpectedEOF
		}
		size, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(line, "$"), "\r\n"))
		if err != nil || size < 0 || size > 1<<20 {
			return nil, io.ErrUnexpectedEOF
		}
		total += size
		if total > 8<<20 {
			return nil, io.ErrUnexpectedEOF
		}
		raw := make([]byte, size+2)
		if _, err := io.ReadFull(reader, raw); err != nil || string(raw[size:]) != "\r\n" {
			return nil, io.ErrUnexpectedEOF
		}
		args = append(args, raw[:size])
	}
	return args, nil
}
