//go:build linux && redis7411native

package systembackup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Explicit native qualification of a NEW isolated Redis process. This does not
// contact a supplied Redis endpoint, production Pod or original installation,
// and cannot create an original holder, task, permission or recovery proof.
func TestRedis7411NativeQualification(t *testing.T) {
	binary, pin := os.Getenv("REDIS_7411_NATIVE_BINARY"), os.Getenv("REDIS_7411_NATIVE_BINARY_SHA256")
	if !filepath.IsAbs(binary) || len(pin) != 64 {
		t.Fatal("explicit independently pinned Redis 7.4.11 binary required")
	}
	raw, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal("native binary unavailable")
	}
	sum := sha256.Sum256(raw)
	clear(raw)
	if hex.EncodeToString(sum[:]) != pin {
		t.Fatal("native binary pin mismatch")
	}
	directory := t.TempDir()
	write := func(name string, raw []byte) string {
		p := filepath.Join(directory, name)
		if os.WriteFile(p, raw, 0600) != nil {
			t.Fatal("private fixture material write failed")
		}
		return p
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-redis-native-qualification"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(keyDER)
	caFile := write("ca.pem", ca)
	certFile := write("server.pem", ca)
	keyFile := write("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	acl := write("users.acl", []byte("user default on nopass ~* &* +@all\n"))
	port := func() string {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
		listener.Close()
		return p
	}
	clearPort, tlsPort := port(), port()
	if clearPort == tlsPort {
		t.Fatal("port collision; no server started")
	}
	args := []string{"--bind", "127.0.0.1", "--port", clearPort, "--tls-port", tlsPort, "--tls-cert-file", certFile, "--tls-key-file", keyFile, "--tls-ca-cert-file", caFile, "--tls-auth-clients", "no", "--appendonly", "yes", "--dir", directory, "--aclfile", acl, "--save", ""}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var process *exec.Cmd
	start := func() {
		process = exec.Command(binary, args...)
		process.Stdout = nil
		process.Stderr = nil
		if process.Start() != nil {
			t.Fatal("isolated native process failed to start")
		}
	}
	stop := func() {
		if process != nil {
			p := process
			process = nil
			p.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- p.Wait() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				p.Process.Kill()
				<-done
				t.Error("native Redis required forced termination")
			}
		}
	}
	defer stop()
	start()
	connect := func(user, password string) *RedisClient {
		var client *RedisClient
		var e error
		for n := 0; n < 100; n++ {
			client, e = ConnectRedis(ctx, RedisOptions{Address: net.JoinHostPort("127.0.0.1", tlsPort), Username: user, Password: password, Database: 0, TLS: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}, MaxReplyBytes: 4 << 20})
			if e == nil {
				return client
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("native TLS/authentication connection unavailable")
		return nil
	}
	admin := connect("", "")
	defer func() { admin.Close() }()
	command := func(args ...string) any {
		wire := make([][]byte, len(args))
		for n, a := range args {
			wire[n] = []byte(a)
		}
		v, e := admin.command(ctx, wire...)
		if e != nil {
			t.Fatal("native qualification command rejected")
		}
		return v
	}
	info := stringBytes(command("INFO", "server"))
	if !strings.Contains(info, "redis_version:7.4.11\r\n") {
		t.Fatal("qualification requires exact real Redis 7.4.11")
	}
	originalRun, _, e := admin.Identity(ctx)
	if e != nil {
		t.Fatal("native original RunID unavailable")
	}
	if command("DBSIZE") != int64(0) {
		t.Fatal("new isolated database is not empty")
	}
	if value, e := redisBootstrapConfig(ctx, admin, "aclfile"); e != nil || value != acl {
		t.Fatal("actual startup ACL file not loaded")
	}
	if _, e := admin.command(ctx, []byte("CONFIG"), []byte("SET"), []byte("aclfile"), []byte(acl+".other")); e == nil {
		t.Fatal("native immutable ACL setting unexpectedly changed")
	}
	command("ACL", "SETUSER", "alice", "reset", "on", ">qualification-alice-password-32bytes", "~fixture:*", "&fixture:*", "+@all", "(+get ~extra:*)")
	command("ACL", "SETUSER", "reader", "reset", "on", ">qualification-reader-password-32bytes", "~fixture:*", "-@all", "+@read", "+eval_ro", "+time", "+info", "+select", "+ping", "+acl|whoami")
	alice := connect("alice", "qualification-alice-password-32bytes")
	defer alice.Close()
	if _, e := alice.command(ctx, []byte("SET"), []byte("fixture:key"), []byte("retained-aof-value")); e != nil {
		t.Fatal("native original writer failed")
	}
	baseline, e := redisGateUserFrom("alice", command("ACL", "GETUSER", "alice"))
	if e != nil || len(baseline.Selectors) != 1 {
		t.Fatal("native GETUSER/selectors format incompatible")
	}
	catalogue, e := redisGateStrings(command("COMMAND", "LIST"))
	if e != nil {
		t.Fatal(e)
	}
	all := map[string]bool{}
	for _, name := range catalogue {
		all[name] = true
	}
	cats, e := redisGateStrings(command("ACL", "CAT"))
	if e != nil {
		t.Fatal(e)
	}
	categories := map[string][]string{}
	for _, cat := range cats {
		names, e := redisGateStrings(command("ACL", "CAT", cat))
		if e != nil {
			t.Fatal(e)
		}
		categories[cat] = names
	}
	safe := map[string]bool{}
	for _, name := range categories["read"] {
		safe[name] = true
	}
	for _, write := range []string{"hexpire", "hpexpire", "hpersist"} {
		if !all[write] || safe[write] {
			t.Fatal("native 7.4 hash-field category incompatible")
		}
	}
	allowed, e := redisGateAllowed(baseline.Commands, all, categories)
	if e != nil {
		t.Fatal(e)
	}
	reduced := baseline.redisGateSelector
	reduced.Commands = redisGateReadCommands(allowed, safe)
	if _, e = admin.command(ctx, redisGateSetUser(baseline, reduced, baseline.Selectors)...); e != nil {
		t.Fatal("actual native ACL renderer incompatible")
	}
	if stringBytes(command("ACL", "SAVE")) != "OK" {
		t.Fatal("native ACL SAVE failed")
	}
	if _, e = alice.command(ctx, []byte("SET"), []byte("fixture:key"), []byte("forbidden")); e == nil {
		t.Fatal("already authenticated writer retained write permission")
	}
	if value, e := alice.command(ctx, []byte("GET"), []byte("fixture:key")); e != nil || stringBytes(value) != "retained-aof-value" {
		t.Fatal("native original read was lost")
	}
	reader := connect("reader", "qualification-reader-password-32bytes")
	if stringBytes(func() any {
		v, e := reader.command(ctx, []byte("ACL"), []byte("WHOAMI"))
		if e != nil {
			t.Fatal(e)
		}
		return v
	}()) != "reader" {
		t.Fatal("native reader identity mismatch")
	}
	sample, e := reader.command(ctx, []byte("EVAL_RO"), []byte(`local v=redis.call('DUMP',KEYS[1]); local kind=redis.call('TYPE',KEYS[1]).ok; local ttl=redis.call('PTTL',KEYS[1]); local clock=redis.call('TIME'); return {v,kind,ttl,clock[1],clock[2]}`), []byte("1"), []byte("fixture:key"))
	sampled, ok := sample.([]any)
	if e != nil || !ok || len(sampled) != 5 || stringBytes(sampled[1]) != "string" || len(stringBytes(sampled[0])) == 0 {
		t.Fatal("native reader could not execute actual atomic DUMP/type/expiry/clock sample")
	}
	if _, e := reader.command(ctx, []byte("EVAL"), []byte(`return redis.call('SET',KEYS[1],'forbidden')`), []byte("1"), []byte("fixture:key")); e == nil {
		t.Fatal("reader gained mutating script authority")
	}
	reader.Close()
	if _, e = admin.command(ctx, redisGateSetUser(baseline, baseline.redisGateSelector, baseline.Selectors)...); e != nil {
		t.Fatal("native original ACL restore failed")
	}
	restored, e := redisGateUserFrom("alice", command("ACL", "GETUSER", "alice"))
	if e != nil || !reflect.DeepEqual(restored, baseline) {
		t.Fatal("actual original native ACL values not restored")
	}
	command("ACL", "SAVE")
	command("SET", "fixture:barrier", "aof-sync")
	ack, ok := command("WAITAOF", "1", "0", "5000").([]any)
	if !ok || len(ack) != 2 || ack[0] != int64(1) {
		t.Fatal("native local AOF fsync was not acknowledged")
	}
	alice.Close()
	admin.Close()
	stop()
	start()
	admin = connect("", "")
	newRun, _, e := admin.Identity(ctx)
	if e != nil || newRun == originalRun {
		t.Fatal("actual Redis process did not restart")
	}
	restored, e = redisGateUserFrom("alice", command("ACL", "GETUSER", "alice"))
	if e != nil || !reflect.DeepEqual(restored, baseline) {
		t.Fatal("actual restarted process did not load original ACL file")
	}
	if stringBytes(command("GET", "fixture:key")) != "retained-aof-value" {
		t.Fatal("actual AOF data did not survive process restart")
	}
	t.Log("native Redis 7.4.11 TLS/auth/GETUSER/selectors/catalogue/ACL reduction/ACL SAVE/existing-client denial/exact restoration/AOF fsync/process restart qualified; not a host reboot or original source hold")
}
