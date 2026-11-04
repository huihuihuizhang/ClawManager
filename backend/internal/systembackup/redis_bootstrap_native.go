package systembackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Installation transport only. This is not a task grant, source fence, gated
// observation or backup. The outer real Installer pins the actual original
// Pod/container/image, operator, namespace, persistent data mount and helper.
type RedisBootstrapNativeRequest struct {
	HelperInvocation                                                     string
	Version, Mode, Operation, HelperSHA256, ExpectedRunID, DataDirectory string
	Keeper, Reader                                                       string
	KeeperPassword, ReaderPassword, CA, Certificate, Key                 []byte
	Prefixes                                                             []string
}
type RedisBootstrapNativeFacts struct {
	Version, RunID, ServerVersion, DataDirectory, Bind, ACLFile, TLSport, AppendOnly string
	ACLSHA256                                                                        string
}
type redisBootstrapJournal struct {
	Version, Operation string
	Before             RedisBootstrapNativeFacts
	Keeper, Reader     string
	Files              map[string]string
	ClientID           int64
}

func RedisNativeReadGateVersion(version string) bool {
	if version == "7.4.11" {
		return true
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 || parts[0] != "7" || parts[1] != "2" {
		return false
	}
	patch, e := strconv.ParseUint(parts[2], 10, 32)
	return e == nil && strconv.FormatUint(patch, 10) == parts[2]
}

func redisBootstrapHash(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func redisBootstrapInfo(raw string, key string) string {
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(line, key+":") {
			return strings.TrimPrefix(line, key+":")
		}
	}
	return ""
}
func redisBootstrapConfig(ctx context.Context, c *RedisClient, key string) (string, error) {
	v, e := c.command(ctx, []byte("CONFIG"), []byte("GET"), []byte(key))
	fields, ok := v.([]any)
	if e != nil || !ok || len(fields) != 2 || stringBytes(fields[0]) != key {
		return "", ErrRedisReadGate
	}
	value, ok := fields[1].([]byte)
	if !ok {
		return "", ErrRedisReadGate
	}
	return string(value), nil
}
func redisBootstrapFacts(ctx context.Context, c *RedisClient) (RedisBootstrapNativeFacts, error) {
	var zero RedisBootstrapNativeFacts
	v, e := c.command(ctx, []byte("INFO"), []byte("server"))
	raw, ok := v.([]byte)
	if e != nil || !ok || redisBootstrapInfo(string(raw), "process_id") != "1" {
		return zero, ErrRedisReadGate
	}
	version := redisBootstrapInfo(string(raw), "redis_version")
	runID := redisBootstrapInfo(string(raw), "run_id")
	if !RedisNativeReadGateVersion(version) || len(runID) != 40 {
		return zero, ErrRedisReadGate
	}
	v, e = c.command(ctx, []byte("ROLE"))
	role, ok := v.([]any)
	if e != nil || !ok || len(role) != 3 || stringBytes(role[0]) != "master" {
		return zero, ErrRedisReadGate
	}
	replicas, ok := role[2].([]any)
	if !ok || len(replicas) != 0 {
		return zero, ErrRedisReadGate
	}
	v, e = c.command(ctx, []byte("INFO"), []byte("cluster"))
	raw, ok = v.([]byte)
	if e != nil || !ok || redisBootstrapInfo(string(raw), "cluster_enabled") != "0" {
		return zero, ErrRedisReadGate
	}
	v, e = c.command(ctx, []byte("MODULE"), []byte("LIST"))
	modules, ok := v.([]any)
	if e != nil || !ok || len(modules) != 0 {
		return zero, ErrRedisReadGate
	}
	out := RedisBootstrapNativeFacts{Version: "original-redis-native-install-facts.v1", ServerVersion: version, RunID: runID}
	for name, dst := range map[string]*string{"dir": &out.DataDirectory, "bind": &out.Bind, "aclfile": &out.ACLFile, "tls-port": &out.TLSport, "appendonly": &out.AppendOnly} {
		value, e := redisBootstrapConfig(ctx, c, name)
		if e != nil {
			return zero, e
		}
		*dst = value
	}
	socket, e := redisBootstrapConfig(ctx, c, "unixsocket")
	if e != nil || socket != "" || out.AppendOnly != "yes" {
		return zero, ErrRedisReadGate
	}
	v, e = c.command(ctx, []byte("ACL"), []byte("LIST"))
	lines, e2 := redisGateStrings(v)
	if e != nil || e2 != nil || len(lines) > 32 {
		return zero, ErrRedisReadGate
	}
	sort.Strings(lines)
	encoded, _ := json.Marshal(lines)
	out.ACLSHA256 = redisBootstrapHash(encoded)
	return out, nil
}

func redisBootstrapUID() (int, int, error) {
	raw, e := os.ReadFile("/proc/1/status")
	if e != nil {
		return 0, 0, ErrRedisReadGate
	}
	uid, gid := -1, -1
	for _, line := range strings.Split(string(raw), "\n") {
		values := strings.Fields(line)
		if len(values) < 3 {
			continue
		}
		if values[0] == "Uid:" {
			uid, e = strconv.Atoi(values[2])
		}
		if values[0] == "Gid:" {
			gid, e = strconv.Atoi(values[2])
		}
		if e != nil {
			return 0, 0, ErrRedisReadGate
		}
	}
	if uid < 0 || gid < 0 || os.Geteuid() != 0 && os.Geteuid() != uid {
		return 0, 0, ErrRedisReadGate
	}
	return uid, gid, nil
}
func redisBootstrapFile(dir, name string, raw []byte, uid, gid int) error {
	root, e := os.OpenRoot(dir)
	if e != nil {
		return ErrRedisReadGate
	}
	defer root.Close()
	f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrRedisReadGate
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Chown(uid, gid)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil || closed != nil {
		return ErrRedisReadGate
	}
	disk, e := root.ReadFile(name)
	same := e == nil && bytes.Equal(disk, raw)
	clear(disk)
	if !same {
		return ErrRedisReadGate
	}
	return nil
}
func redisBootstrapOwned(ctx context.Context, c *RedisClient, operation string) error {
	value, e := c.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
	if e != nil || stringBytes(value) != "install/"+operation {
		return ErrRedisReadGate
	}
	return nil
}
func redisBootstrapDefaultOnly(ctx context.Context, c *RedisClient) error {
	value, e := c.command(ctx, []byte("ACL"), []byte("USERS"))
	users, e2 := redisGateStrings(value)
	if e != nil || e2 != nil || !reflect.DeepEqual(users, []string{"default"}) {
		return ErrRedisReadGate
	}
	value, e = c.command(ctx, []byte("ACL"), []byte("GETUSER"), []byte("default"))
	u, e2 := redisGateUserFrom("default", value)
	if e != nil || e2 != nil || len(u.Passwords) != 0 || u.Commands != "+@all" || u.Keys != "~*" || u.Channels != "&*" || len(u.Selectors) != 0 {
		return ErrRedisReadGate
	}
	flags := map[string]bool{}
	for _, f := range u.Flags {
		if f != "on" && f != "nopass" && f != "sanitize-payload" {
			return ErrRedisReadGate
		}
		flags[f] = true
	}
	if !flags["on"] || !flags["nopass"] {
		return ErrRedisReadGate
	}
	return nil
}

func redisBootstrapPrepare(ctx context.Context, c *RedisClient, in RedisBootstrapNativeRequest, before RedisBootstrapNativeFacts) (RedisBootstrapNativeFacts, error) {
	var zero RedisBootstrapNativeFacts
	if before.RunID != in.ExpectedRunID || before.DataDirectory != in.DataDirectory || before.ACLFile != "" || before.TLSport != "0" || redisBootstrapDefaultOnly(ctx, c) != nil || len(in.CA) == 0 || len(in.Certificate) == 0 || len(in.Key) == 0 || len(in.KeeperPassword) < 32 || len(in.ReaderPassword) < 32 || !redisGateName(in.Keeper) || !redisGateName(in.Reader) || in.Keeper == in.Reader || len(in.Prefixes) == 0 {
		return zero, ErrRedisReadGate
	}
	for _, prefix := range in.Prefixes {
		if prefix == "" || strings.ContainsAny(prefix, " \t\r\n\x00*?[]\\\"'") {
			return zero, ErrRedisReadGate
		}
	}
	canonical, e := filepath.EvalSymlinks(in.DataDirectory)
	if e != nil || canonical != in.DataDirectory || !filepath.IsAbs(canonical) {
		return zero, ErrRedisReadGate
	}
	uid, gid, e := redisBootstrapUID()
	if e != nil {
		return zero, e
	}
	directory := filepath.Join(canonical, ".system-backup-redis-"+in.Operation)
	if os.Mkdir(directory, 0700) != nil || os.Chown(directory, uid, gid) != nil {
		return zero, ErrRedisReadGate
	}
	clientID, e := c.command(ctx, []byte("CLIENT"), []byte("ID"))
	id, ok := clientID.(int64)
	if e != nil || !ok || id < 1 {
		return zero, ErrRedisReadGate
	}
	journal := redisBootstrapJournal{Version: "original-redis-install-journal.v1", Operation: in.Operation, Before: before, Keeper: in.Keeper, Reader: in.Reader, Files: map[string]string{}, ClientID: id}
	for name, raw := range map[string][]byte{"ca.pem": in.CA, "server.pem": in.Certificate, "server-key.pem": in.Key} {
		journal.Files[name] = redisBootstrapHash(raw)
	}
	journalRaw, _ := json.Marshal(journal)
	// Native durable intent precedes EVERY first ACL/listener mutation. The
	// outer Installer also fsyncs its own immutable intent before this call.
	if redisBootstrapFile(directory, "intent.private.json", journalRaw, uid, gid) != nil {
		return zero, ErrRedisReadGate
	}
	mutate := func(args ...[]byte) (any, error) {
		if _, e := os.Lstat(filepath.Join(directory, "cancelled")); !os.IsNotExist(e) {
			return nil, ErrRedisReadGate
		}
		return c.command(ctx, args...)
	}
	value, e := mutate([]byte("SET"), []byte(redisGateOwnerKey), []byte("install/"+in.Operation), []byte("NX"))
	if e != nil || stringBytes(value) != "OK" {
		return zero, ErrRedisReadGate
	}
	if _, e = mutate([]byte("CONFIG"), []byte("SET"), []byte("bind"), []byte("127.0.0.1")); e != nil {
		return zero, ErrRedisReadGate
	}
	for _, kind := range []string{"normal", "pubsub"} {
		if _, e = mutate([]byte("CLIENT"), []byte("KILL"), []byte("TYPE"), []byte(kind), []byte("SKIPME"), []byte("yes")); e != nil {
			return zero, ErrRedisReadGate
		}
	}
	value, e = c.command(ctx, []byte("CLIENT"), []byte("LIST"))
	if e != nil || len(strings.Split(strings.TrimSpace(stringBytes(value)), "\n")) != 1 || redisBootstrapDefaultOnly(ctx, c) != nil || redisBootstrapOwned(ctx, c, in.Operation) != nil {
		return zero, ErrRedisReadGate
	}
	for name, raw := range map[string][]byte{"ca.pem": in.CA, "server.pem": in.Certificate, "server-key.pem": in.Key} {
		if redisBootstrapFile(directory, name, raw, uid, gid) != nil {
			return zero, ErrRedisReadGate
		}
	}
	keeper := []string{"-@all", "+acl|list", "+acl|users", "+acl|getuser", "+acl|setuser", "+acl|deluser", "+acl|save", "+acl|whoami", "+acl|cat", "+config|get", "+module|list", "+command|list", "+command", "+info", "+role", "+select", "+ping", "+get", "+set", "+del", "~" + redisGateOwnerKey}
	reader := []string{"-@all", "+@read", "+eval_ro", "+time", "+info", "+select", "+ping", "+acl|whoami"}
	for _, p := range in.Prefixes {
		reader = append(reader, "~"+p+"*")
	}
	for name, rules := range map[string][]string{in.Keeper: keeper, in.Reader: reader} {
		secret := in.KeeperPassword
		if name == in.Reader {
			secret = in.ReaderPassword
		}
		sum := sha256.Sum256(secret)
		args := [][]byte{[]byte("ACL"), []byte("SETUSER"), []byte(name), []byte("reset"), []byte("clearselectors"), []byte("on"), []byte("#" + hex.EncodeToString(sum[:]))}
		for _, rule := range rules {
			args = append(args, []byte(rule))
		}
		value, e = mutate(args...)
		if e != nil || stringBytes(value) != "OK" {
			return zero, ErrRedisReadGate
		}
	}
	value, e = c.command(ctx, []byte("ACL"), []byte("LIST"))
	lines, e2 := redisGateStrings(value)
	if e != nil || e2 != nil || len(lines) != 3 {
		return zero, ErrRedisReadGate
	}
	sort.Strings(lines)
	acl := []byte(strings.Join(lines, "\n") + "\n")
	if redisBootstrapFile(directory, "users.acl", acl, uid, gid) != nil {
		return zero, ErrRedisReadGate
	}
	// One write from this connection follows all drained preceding writes. Its
	// actual WAITAOF acknowledgement must be [>=1,>=0]; timeout alone is no proof.
	// Advance THIS connection beyond every write from the now-drained clients.
	value, e = mutate([]byte("SET"), []byte(redisGateOwnerKey), []byte("install/"+in.Operation), []byte("XX"))
	if e != nil || stringBytes(value) != "OK" {
		return zero, ErrRedisReadGate
	}
	value, e = c.command(ctx, []byte("WAITAOF"), []byte("1"), []byte("0"), []byte("5000"))
	ack, ok := value.([]any)
	if e != nil || !ok || len(ack) != 2 || ack[0] != int64(1) || redisBootstrapOwned(ctx, c, in.Operation) != nil {
		return zero, ErrRedisReadGate
	}
	after, e := redisBootstrapFacts(ctx, c)
	if e != nil || after.RunID != before.RunID || after.Bind != "127.0.0.1" {
		return zero, ErrRedisReadGate
	}
	return after, nil
}

func redisBootstrapFinish(ctx context.Context, c *RedisClient, in RedisBootstrapNativeRequest, before RedisBootstrapNativeFacts) (RedisBootstrapNativeFacts, error) {
	var zero RedisBootstrapNativeFacts
	directory := filepath.Join(in.DataDirectory, ".system-backup-redis-"+in.Operation)
	raw, e := os.ReadFile(filepath.Join(directory, "intent.private.json"))
	if e != nil || len(raw) > 65536 {
		return zero, ErrRedisReadGate
	}
	var journal redisBootstrapJournal
	if json.Unmarshal(raw, &journal) != nil || journal.Version != "original-redis-install-journal.v1" || journal.Operation != in.Operation || journal.Before.RunID != in.ExpectedRunID || journal.Before.DataDirectory != in.DataDirectory {
		return zero, ErrRedisReadGate
	}
	if in.Mode != "verify-finished" && redisBootstrapOwned(ctx, c, in.Operation) != nil {
		return zero, ErrRedisReadGate
	}
	if in.Mode == "finish" || in.Mode == "verify-finished" {
		if before.ACLFile != filepath.Join(directory, "users.acl") || before.TLSport != "6380" || before.ServerVersion != journal.Before.ServerVersion {
			return zero, ErrRedisReadGate
		}
		value, e := c.command(ctx, []byte("ACL"), []byte("LIST"))
		lines, e2 := redisGateStrings(value)
		sort.Strings(lines)
		disk, e3 := os.ReadFile(before.ACLFile)
		if e != nil || e2 != nil || e3 != nil || !bytes.Equal(disk, []byte(strings.Join(lines, "\n")+"\n")) {
			return zero, ErrRedisReadGate
		}
		for name, sha := range journal.Files {
			disk, e := os.ReadFile(filepath.Join(directory, name))
			same := e == nil && redisBootstrapHash(disk) == sha
			clear(disk)
			if !same {
				return zero, ErrRedisReadGate
			}
		}
		if in.Mode == "verify-finished" {
			value, e := c.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
			if e != nil || value != nil || before.Bind != journal.Before.Bind {
				return zero, ErrRedisReadGate
			}
			return before, nil
		}
	} else if in.Mode == "rollback" {
		// The outer fresh-authority recovery first restores the exact original
		// Deployment. Native rollback also works if its prepare send was uncertain.
		if before.ACLFile != "" || before.TLSport != "0" {
			return zero, ErrRedisReadGate
		}
		for _, name := range []string{journal.Keeper, journal.Reader} {
			if !redisGateName(name) {
				return zero, ErrRedisReadGate
			}
			if _, e = c.command(ctx, []byte("ACL"), []byte("DELUSER"), []byte(name)); e != nil {
				return zero, ErrRedisReadGate
			}
		}
		if redisBootstrapDefaultOnly(ctx, c) != nil {
			return zero, ErrRedisReadGate
		}
	} else {
		return zero, ErrRedisReadGate
	}
	// Restore original native listener configuration only after exact file/ACL
	// readback. No durable install owner is removed until that succeeds.
	if _, e = c.command(ctx, []byte("CONFIG"), []byte("SET"), []byte("bind"), []byte(journal.Before.Bind)); e != nil {
		return zero, ErrRedisReadGate
	}
	if redisBootstrapOwned(ctx, c, in.Operation) != nil {
		return zero, ErrRedisReadGate
	}
	value, e := c.command(ctx, []byte("DEL"), []byte(redisGateOwnerKey))
	if e != nil || value != int64(1) {
		return zero, ErrRedisReadGate
	}
	return redisBootstrapFacts(ctx, c)
}

func redisBootstrapCancel(ctx context.Context, c *RedisClient, in RedisBootstrapNativeRequest, before RedisBootstrapNativeFacts) (RedisBootstrapNativeFacts, error) {
	var zero RedisBootstrapNativeFacts
	if before.DataDirectory != in.DataDirectory || !filepath.IsAbs(in.DataDirectory) {
		return zero, ErrRedisReadGate
	}
	canonical, e := filepath.EvalSymlinks(in.DataDirectory)
	if e != nil || canonical != in.DataDirectory {
		return zero, ErrRedisReadGate
	}
	uid, gid, e := redisBootstrapUID()
	if e != nil {
		return zero, e
	}
	directory := filepath.Join(in.DataDirectory, ".system-backup-redis-"+in.Operation)
	if e = os.Mkdir(directory, 0700); e != nil && !os.IsExist(e) {
		return zero, ErrRedisReadGate
	}
	st, e := os.Lstat(directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return zero, ErrRedisReadGate
	}
	marker := filepath.Join(directory, "cancelled")
	if e = redisBootstrapFile(directory, "cancelled", []byte(in.Operation), uid, gid); e != nil {
		raw, e := os.ReadFile(marker)
		if e != nil || string(raw) != in.Operation {
			return zero, ErrRedisReadGate
		}
	}
	raw, e := os.ReadFile(filepath.Join(directory, "intent.private.json"))
	if os.IsNotExist(e) {
		return before, nil
	}
	var journal redisBootstrapJournal
	if e != nil || len(raw) > 65536 || json.Unmarshal(raw, &journal) != nil || journal.Operation != in.Operation || journal.Before.RunID != in.ExpectedRunID || journal.ClientID < 1 {
		return zero, ErrRedisReadGate
	}
	if before.RunID == journal.Before.RunID {
		// Kill the original native helper connection after durable cancellation.
		// Redis processes this command in order; no old queued command can execute
		// after it returns. New late helpers refuse the existing cancelled directory.
		if _, e = c.command(ctx, []byte("CLIENT"), []byte("KILL"), []byte("ID"), []byte(strconv.FormatInt(journal.ClientID, 10))); e != nil {
			return zero, ErrRedisReadGate
		}
	}
	return redisBootstrapFacts(ctx, c)
}

func RunRedisBootstrapNative(ctx context.Context, input io.Reader, output io.Writer) error {
	if runtime.GOOS != "linux" || ctx == nil || ctx.Err() != nil || input == nil || output == nil {
		return ErrRedisReadGate
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return ErrRedisReadGate
	}
	var in RedisBootstrapNativeRequest
	decoder := json.NewDecoder(io.LimitReader(input, 524289))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(new(any)) != io.EOF || in.Version != "original-redis-native-install-request.v1" || len(in.Operation) != 32 {
		return ErrRedisReadGate
	}
	nonce, e := hex.DecodeString(in.Operation)
	if e != nil || len(nonce) != 16 || hex.EncodeToString(nonce) != in.Operation {
		return ErrRedisReadGate
	}
	defer clear(in.Key)
	defer clear(in.KeeperPassword)
	defer clear(in.ReaderPassword)
	exe, e := os.Executable()
	invocation, e := hex.DecodeString(in.HelperInvocation)
	if e != nil || len(invocation) != 16 || hex.EncodeToString(invocation) != in.HelperInvocation {
		return ErrRedisReadGate
	}
	expected := "/tmp/sbk-redis-bootstrap-" + in.Operation + "-" + in.HelperInvocation + "/helper"
	if e != nil || exe != expected {
		return ErrRedisReadGate
	}
	own, e := os.ReadFile(exe)
	same := e == nil && redisBootstrapHash(own) == in.HelperSHA256
	clear(own)
	if !same {
		return ErrRedisReadGate
	}
	// Remove only this invocation's uploaded helper and private temporary dir.
	defer os.Remove(filepath.Dir(exe))
	defer os.Remove(exe)
	client, e := ConnectRedis(ctx, RedisOptions{Address: "127.0.0.1:6379", Database: 0, MaxReplyBytes: 4 << 20})
	if e != nil {
		return ErrRedisReadGate
	}
	defer client.Close()
	before, e := redisBootstrapFacts(ctx, client)
	if e != nil {
		return e
	}
	result := before
	switch in.Mode {
	case "inspect":
		if redisBootstrapDefaultOnly(ctx, client) != nil {
			return ErrRedisReadGate
		}
	case "prepare":
		result, e = redisBootstrapPrepare(ctx, client, in, before)
	case "finish", "verify-finished", "rollback":
		result, e = redisBootstrapFinish(ctx, client, in, before)
	case "cancel":
		result, e = redisBootstrapCancel(ctx, client, in, before)
	default:
		return ErrRedisReadGate
	}
	if e != nil || ctx.Err() != nil {
		return ErrRedisReadGate
	}
	return json.NewEncoder(output).Encode(result)
}
