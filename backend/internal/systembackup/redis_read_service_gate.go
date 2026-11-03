package systembackup

import (
	"clawreef/internal/systembackup/staging"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var ErrRedisReadGate = errors.New("original Redis read-service gate unavailable; retain source admission")

const redisGateOwnerKey = "clawreef:system-backup:redis-acl-owner"
const redisGateMarkerPrefix = "clawreef_gate_"

// These are deployment-owned INPUTS. The concrete API/Redis observations below
// prove only this native gate; the external check must enforce real original
// installer/task authority, complete source scope and all other writers.
type RedisReadGateInput struct {
	Namespace, NamespaceUID, Pod, PodUID, Container, ImageID, ACLFile, ServerVersion string
	KeeperAccount, ReaderAccount, Operation, InventorySHA256                         string
	Policy                                                                           RedisCapturePolicy
	CustodyDirectory                                                                 string
}
type redisGateSelector struct{ Commands, Keys, Channels string }
type redisGateUser struct {
	Name             string
	Flags, Passwords []string
	redisGateSelector
	Selectors []redisGateSelector
}
type RedisReadServiceGate struct {
	mu                               sync.Mutex
	origin                           *RedisReadServiceGate
	admin, reader                    *RedisClient
	kube                             kubernetes.Interface
	in                               RedisReadGateInput
	check                            TeamSourceCheck
	original, gated                  []redisGateUser
	changes                          map[string][][]byte
	expected                         map[string]redisGateUser
	commandNames                     map[string]bool
	categories                       map[string][]string
	custody                          *os.Root
	custodyDirectoryIdentity         os.FileInfo
	custodyKey                       []byte
	custodyBinding                   staging.Binding
	custodyName                      string
	ownerValue, marker, digest       string
	ownerSent, mutated, held, closed bool
	transportFailed                  bool
	aclStorage                       *redisACLStoragePin
}

func (*RedisReadServiceGate) MarshalJSON() ([]byte, error) { return nil, ErrRedisReadGate }
func redisGateHash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func redisGateName(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
func redisGateStrings(v any) ([]string, error) {
	array, ok := v.([]any)
	if !ok || len(array) > 10000 {
		return nil, ErrRedisReadGate
	}
	out := []string{}
	for _, item := range array {
		b, ok := item.([]byte)
		if !ok || len(b) > 65536 {
			return nil, ErrRedisReadGate
		}
		out = append(out, string(b))
	}
	return out, nil
}
func redisGateFields(v any) (map[string]any, error) {
	a, ok := v.([]any)
	if !ok || len(a)%2 != 0 || len(a) > 32 {
		return nil, ErrRedisReadGate
	}
	m := map[string]any{}
	for n := 0; n < len(a); n += 2 {
		k, ok := a[n].([]byte)
		if !ok || m[string(k)] != nil {
			return nil, ErrRedisReadGate
		}
		m[string(k)] = a[n+1]
	}
	return m, nil
}
func redisGateSelectorFrom(v any) (redisGateSelector, error) {
	var out redisGateSelector
	m, e := redisGateFields(v)
	if e != nil || len(m) != 3 {
		return out, ErrRedisReadGate
	}
	for key, dst := range map[string]*string{"commands": &out.Commands, "keys": &out.Keys, "channels": &out.Channels} {
		b, ok := m[key].([]byte)
		if !ok || strings.ContainsAny(string(b), "\x00\r\n\t\\\"'") {
			return out, ErrRedisReadGate
		}
		*dst = string(b)
	}
	return out, nil
}
func redisGateUserFrom(name string, v any) (redisGateUser, error) {
	out := redisGateUser{Name: name}
	m, e := redisGateFields(v)
	if e != nil || len(m) != 6 {
		return out, ErrRedisReadGate
	}
	out.Flags, e = redisGateStrings(m["flags"])
	if e != nil {
		return out, e
	}
	out.Passwords, e = redisGateStrings(m["passwords"])
	if e != nil {
		return out, e
	}
	for _, h := range out.Passwords {
		if len(h) != 64 {
			return out, ErrRedisReadGate
		}
		if _, e = hex.DecodeString(h); e != nil {
			return out, ErrRedisReadGate
		}
	}
	for key, dst := range map[string]*string{"commands": &out.Commands, "keys": &out.Keys, "channels": &out.Channels} {
		b, ok := m[key].([]byte)
		if !ok || strings.ContainsAny(string(b), "\x00\r\n\t\\\"'") {
			return out, ErrRedisReadGate
		}
		*dst = string(b)
	}
	selectors, ok := m["selectors"].([]any)
	if !ok || len(selectors) > 32 {
		return out, ErrRedisReadGate
	}
	for _, v := range selectors {
		s, e := redisGateSelectorFrom(v)
		if e != nil {
			return out, e
		}
		out.Selectors = append(out.Selectors, s)
	}
	return out, nil
}

func (g *RedisReadServiceGate) users(ctx context.Context) ([]redisGateUser, error) {
	v, e := g.command(ctx, []byte("ACL"), []byte("USERS"))
	if e != nil {
		return nil, ErrRedisReadGate
	}
	names, e := redisGateStrings(v)
	if e != nil || len(names) > 256 {
		return nil, ErrRedisReadGate
	}
	sort.Strings(names)
	users := []redisGateUser{}
	for n, name := range names {
		if !redisGateName(name) || n > 0 && names[n-1] == name {
			return nil, ErrRedisReadGate
		}
		v, e = g.command(ctx, []byte("ACL"), []byte("GETUSER"), []byte(name))
		if e != nil {
			return nil, ErrRedisReadGate
		}
		u, e := redisGateUserFrom(name, v)
		if e != nil {
			return nil, e
		}
		users = append(users, u)
	}
	return users, nil
}
func (g *RedisReadServiceGate) identity(ctx context.Context) error {
	if g == nil || g.origin != g || g.transportFailed || ctx == nil || ctx.Err() != nil || g.check == nil || g.check(ctx) != nil {
		return ErrRedisReadGate
	}
	id, db, e := g.admin.Identity(ctx)
	if e != nil {
		g.poisonTransport()
		return ErrRedisReadGate
	}
	if id != g.in.Policy.ServerID || db != 0 {
		return ErrRedisReadGate
	}
	info, e := g.command(ctx, []byte("INFO"), []byte("server"))
	raw, ok := info.([]byte)
	if e != nil || !ok || !strings.Contains(string(raw), "\r\nredis_version:"+g.in.ServerVersion+"\r\n") {
		return ErrRedisReadGate
	}
	v, e := g.command(ctx, []byte("ROLE"))
	role, ok := v.([]any)
	if e != nil || !ok || len(role) != 3 || stringBytes(role[0]) != "master" {
		return ErrRedisReadGate
	}
	replicas, replicasOK := role[2].([]any)
	if !replicasOK || len(replicas) != 0 {
		return ErrRedisReadGate
	}
	v, e = g.command(ctx, []byte("INFO"), []byte("cluster"))
	b, ok := v.([]byte)
	if e != nil || !ok || !strings.Contains(string(b), "cluster_enabled:0\r\n") {
		return ErrRedisReadGate
	}
	v, e = g.command(ctx, []byte("MODULE"), []byte("LIST"))
	modules, ok := v.([]any)
	if e != nil || !ok || len(modules) != 0 {
		return ErrRedisReadGate
	}
	v, e = g.command(ctx, []byte("CONFIG"), []byte("GET"), []byte("aclfile"))
	config, ok := v.([]any)
	if e != nil || !ok || len(config) != 2 || stringBytes(config[0]) != "aclfile" || stringBytes(config[1]) != g.in.ACLFile {
		return ErrRedisReadGate
	}
	pod, e := g.kube.CoreV1().Pods(g.in.Namespace).Get(ctx, g.in.Pod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != g.in.PodUID || pod.DeletionTimestamp != nil {
		return ErrRedisReadGate
	}
	namespace, e := g.kube.CoreV1().Namespaces().Get(ctx, g.in.Namespace, metav1.GetOptions{})
	if e != nil || string(namespace.UID) != g.in.NamespaceUID || namespace.DeletionTimestamp != nil {
		return ErrRedisReadGate
	}
	for _, client := range []*RedisClient{g.admin, g.reader} {
		connection, ok := client.conn.(*tls.Conn)
		if !ok || connection.ConnectionState().Version < tls.VersionTLS13 || len(connection.ConnectionState().VerifiedChains) == 0 {
			return ErrRedisReadGate
		}
		host, _, err := net.SplitHostPort(client.conn.RemoteAddr().String())
		if err != nil || pod.Status.PodIP == "" || host != pod.Status.PodIP {
			return ErrRedisReadGate
		}
	}
	found := false
	for _, c := range pod.Spec.Containers {
		if c.Name != g.in.Container {
			continue
		}
		args := append(append([]string{}, c.Command...), c.Args...)
		if len(c.Command) != 1 || c.Command[0] != "redis-server" || len(pod.Spec.InitContainers) != 0 {
			return ErrRedisReadGate
		}
		startup := false
		for n, arg := range args {
			startup = startup || arg == "--aclfile" && n+1 < len(args) && args[n+1] == g.in.ACLFile
		}
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == c.Name && status.ImageID == g.in.ImageID && status.State.Running != nil && status.Ready && startup {
				found = true
			}
		}
		persistent := false
		for _, mount := range c.VolumeMounts {
			if mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" || g.in.ACLFile == mount.MountPath || !strings.HasPrefix(g.in.ACLFile, strings.TrimSuffix(mount.MountPath, "/")+"/") {
				continue
			}
			for _, volume := range pod.Spec.Volumes {
				if volume.Name == mount.Name && volume.PersistentVolumeClaim != nil && !volume.PersistentVolumeClaim.ReadOnly {
					persistent = true
				}
			}
			for _, other := range pod.Spec.Containers {
				if other.Name == c.Name {
					continue
				}
				for _, v := range other.VolumeMounts {
					if v.Name == mount.Name && !v.ReadOnly {
						return ErrRedisReadGate
					}
				}
			}
		}
		if !persistent || g.checkACLStorage(ctx, pod, c) != nil {
			return ErrRedisReadGate
		}
	}
	if !found {
		return ErrRedisReadGate
	}
	return g.check(ctx)
}
func stringBytes(v any) string {
	b, ok := v.([]byte)
	if !ok {
		return ""
	}
	return string(b)
}

// All categories are resolved from this exact actual Redis COMMAND catalogue.
// Rules are interpreted in native ACL order; +parent includes its subcommands.
func redisGateAllowed(commands string, all map[string]bool, categories map[string][]string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, token := range strings.Fields(commands) {
		if len(token) < 2 || token[0] != '+' && token[0] != '-' {
			return nil, ErrRedisReadGate
		}
		name := strings.ToLower(token[1:])
		names := []string{}
		if strings.HasPrefix(name, "@") {
			if name == "@all" {
				for c := range all {
					names = append(names, c)
				}
			} else {
				v, ok := categories[name[1:]]
				if !ok {
					return nil, ErrRedisReadGate
				}
				names = v
			}
		} else {
			for c := range all {
				if c == name || strings.HasPrefix(c, name+"|") {
					names = append(names, c)
				}
			}
			if len(names) == 0 {
				return nil, ErrRedisReadGate
			}
		}
		for _, c := range names {
			if token[0] == '+' {
				out[c] = true
			} else {
				delete(out, c)
			}
		}
	}
	return out, nil
}
func redisGateReadCommands(allowed, safe map[string]bool) string {
	names := []string{}
	for name := range allowed {
		if safe[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	out := "-@all"
	for _, name := range names {
		out += " +" + name
	}
	return out
}
func redisGateSetUser(user redisGateUser, root redisGateSelector, selectors []redisGateSelector) [][]byte {
	args := [][]byte{[]byte("ACL"), []byte("SETUSER"), []byte(user.Name), []byte("resetcommands"), []byte("clearselectors")}
	for _, token := range strings.Fields(root.Commands) {
		args = append(args, []byte(token))
	}
	for _, s := range selectors {
		args = append(args, []byte("("+s.Commands+" "+s.Keys+" "+s.Channels+")"))
	}
	return args
}

// Prepare performs ONLY native/Kubernetes reads. It accepts no observed ACK,
// boolean, lease count, native response, caller-produced gated hash or TTL.
// Version 7.2.x is the reviewed ACL SAVE/selector/script profile; other versions
// require explicit native compatibility validation, not a latest-tag guess.
func PrepareRedisReadServiceGate(ctx context.Context, admin, reader *RedisClient, kube kubernetes.Interface, in RedisReadGateInput, check TeamSourceCheck, custodyKey []byte) (*RedisReadServiceGate, error) {
	op, e1 := hex.DecodeString(in.Operation)
	inventory, e2 := hex.DecodeString(in.InventorySHA256)
	if e1 != nil || e2 != nil || len(op) != 16 || len(inventory) != 32 || hex.EncodeToString(op) != in.Operation || hex.EncodeToString(inventory) != in.InventorySHA256 {
		return nil, ErrRedisReadGate
	}
	if admin == nil || reader == nil || admin == reader || kube == nil || check == nil || in.Policy.Validate() != nil || !strings.HasPrefix(in.ServerVersion, "7.2.") || !redisGateName(in.KeeperAccount) || !redisGateName(in.ReaderAccount) || in.KeeperAccount == in.ReaderAccount || len(in.Operation) != 32 || len(in.InventorySHA256) != 64 || !path.IsAbs(in.ACLFile) || path.Clean(in.ACLFile) != in.ACLFile || in.Policy.allows(redisGateOwnerKey) {
		return nil, ErrRedisReadGate
	}
	g := &RedisReadServiceGate{admin: admin, reader: reader, kube: kube, in: in, check: check, changes: map[string][][]byte{}, expected: map[string]redisGateUser{}, marker: redisGateMarkerPrefix + in.Operation}
	g.origin = g
	prepared := false
	defer func() {
		if !prepared {
			g.Close()
		}
	}()
	if g.identity(ctx) != nil {
		return nil, ErrRedisReadGate
	}
	for client, name := range map[*RedisClient]string{admin: in.KeeperAccount, reader: in.ReaderAccount} {
		v, e := client.command(ctx, []byte("ACL"), []byte("WHOAMI"))
		if e != nil || stringBytes(v) != name {
			return nil, ErrRedisReadGate
		}
		id, db, e := client.Identity(ctx)
		expectedDB := in.Policy.Policy.DB
		if client == admin {
			expectedDB = 0
		}
		if e != nil || id != in.Policy.ServerID || db != expectedDB {
			return nil, ErrRedisReadGate
		}
	}
	v, e := admin.command(ctx, []byte("COMMAND"), []byte("LIST"))
	list, e2 := redisGateStrings(v)
	if e != nil || e2 != nil {
		return nil, ErrRedisReadGate
	}
	all := map[string]bool{}
	for _, name := range list {
		all[strings.ToLower(name)] = true
	}
	v, e = admin.command(ctx, []byte("ACL"), []byte("CAT"))
	cats, e2 := redisGateStrings(v)
	if e != nil || e2 != nil || len(cats) > 64 {
		return nil, ErrRedisReadGate
	}
	categories := map[string][]string{}
	for _, cat := range cats {
		v, e = admin.command(ctx, []byte("ACL"), []byte("CAT"), []byte(cat))
		names, e2 := redisGateStrings(v)
		if e != nil || e2 != nil {
			return nil, ErrRedisReadGate
		}
		categories[cat] = names
	}
	g.commandNames, g.categories = all, categories
	if len(categories["read"]) == 0 {
		return nil, ErrRedisReadGate
	}
	safe := map[string]bool{}
	for _, name := range categories["read"] {
		safe[name] = true
	}
	for _, name := range []string{"eval_ro", "fcall_ro", "auth", "hello", "select", "ping", "echo", "quit", "info", "time", "acl|whoami"} {
		if all[name] {
			safe[name] = true
		}
	}
	users, e := g.users(ctx)
	if e != nil {
		return nil, e
	}
	keeper, source := false, false
	for _, user := range users {
		if strings.HasPrefix(user.Name, redisGateMarkerPrefix) {
			return nil, ErrRedisReadGate
		}
		allowed, e := redisGateAllowed(user.Commands, all, categories)
		if e != nil {
			return nil, e
		}
		if user.Name == in.KeeperAccount {
			// This trusted maintenance account can alter ACLs and only its own
			// coordination key. It cannot issue protected keyspace mutations.
			keeper = true
			permitted := map[string]bool{}
			for _, name := range []string{"acl|list", "acl|users", "acl|getuser", "acl|setuser", "acl|deluser", "acl|save", "acl|whoami", "acl|cat", "config|get", "module|list", "command|list", "command", "info", "role", "select", "ping", "get", "set", "del"} {
				permitted[name] = true
			}
			for name := range allowed {
				if !permitted[name] {
					return nil, ErrRedisReadGate
				}
			}
			for _, name := range []string{"acl|users", "acl|getuser", "acl|setuser", "acl|deluser", "acl|save", "acl|cat", "config|get", "module|list", "command|list", "info", "role", "get", "set", "del"} {
				if !allowed[name] {
					return nil, ErrRedisReadGate
				}
			}
			if len(user.Selectors) != 0 || user.Keys != "~"+redisGateOwnerKey {
				return nil, ErrRedisReadGate
			}
			continue
		}
		if user.Name == in.ReaderAccount {
			source = true
			for name := range allowed {
				if !safe[name] {
					return nil, ErrRedisReadGate
				}
			}
			for _, selector := range user.Selectors {
				a, e := redisGateAllowed(selector.Commands, all, categories)
				if e != nil {
					return nil, e
				}
				for name := range a {
					if !safe[name] {
						return nil, ErrRedisReadGate
					}
				}
			}
			continue
		}
		root := user.redisGateSelector
		root.Commands = redisGateReadCommands(allowed, safe)
		selectors := []redisGateSelector{}
		for _, s := range user.Selectors {
			a, e := redisGateAllowed(s.Commands, all, categories)
			if e != nil {
				return nil, e
			}
			s.Commands = redisGateReadCommands(a, safe)
			selectors = append(selectors, s)
		}
		g.changes[user.Name] = redisGateSetUser(user, root, selectors)
		wanted := user
		wanted.redisGateSelector = root
		wanted.Selectors = selectors
		g.expected[user.Name] = wanted
	}
	if !keeper || !source {
		return nil, ErrRedisReadGate
	}
	g.original = users
	g.ownerValue = redisGateHash(struct {
		Version, Operation, Inventory, Source string
		DB                                    int
		Original                              string
	}{"original-redis-native-read-gate.v1", in.Operation, in.InventorySHA256, in.Policy.ServerID, in.Policy.Policy.DB, redisGateHash(users)})
	if g.sealOriginal(ctx, custodyKey) != nil {
		return nil, ErrRedisReadGate
	}
	if g.identity(ctx) != nil {
		return nil, ErrRedisReadGate
	}
	prepared = true
	return g, nil
}

// Acquire invokes real native ACL mutations. Any send/commit/readback error
// retains the owner/marker and original snapshot; there is NO timed unpause,
// automatic rollback, DELUSER-all, guessed TTL or new Redis replacement.
func (g *RedisReadServiceGate) Acquire(ctx context.Context) error {
	if g == nil {
		return ErrRedisReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.ownerSent || g.identity(ctx) != nil {
		return ErrRedisReadGate
	}
	if g.readOriginalCustody(ctx) != nil {
		return ErrRedisReadGate
	}
	users, e := g.users(ctx)
	if e != nil || !reflect.DeepEqual(users, g.original) {
		return ErrRedisReadGate
	}
	g.ownerSent = true
	v, e := g.command(ctx, []byte("SET"), []byte(redisGateOwnerKey), []byte(g.ownerValue), []byte("NX"))
	if e != nil || stringBytes(v) != "OK" {
		return ErrRedisReadGate
	}
	g.mutated = true
	if _, e = g.command(ctx, []byte("ACL"), []byte("SETUSER"), []byte(g.marker), []byte("reset"), []byte("off")); e != nil {
		return ErrRedisReadGate
	}
	names := []string{}
	for name := range g.changes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if g.identity(ctx) != nil || g.owner(ctx) != nil {
			return ErrRedisReadGate
		}
		if _, e = g.command(ctx, g.changes[name]...); e != nil {
			return ErrRedisReadGate
		}
	}
	if _, e = g.command(ctx, []byte("ACL"), []byte("SAVE")); e != nil {
		return ErrRedisReadGate
	}
	users, e = g.users(ctx)
	if e != nil {
		return ErrRedisReadGate
	}
	g.gated = users
	g.digest = redisGateHash(users)
	// Compare expected native ACL GETUSER results, not just this new digest.
	for _, user := range g.original {
		found := false
		for _, now := range users {
			if user.Name != now.Name {
				continue
			}
			found = true
			if user.Name == g.in.KeeperAccount || user.Name == g.in.ReaderAccount {
				if !reflect.DeepEqual(user, now) {
					return ErrRedisReadGate
				}
			} else if g.expectedUser(now, g.expected[user.Name]) != nil {
				return ErrRedisReadGate
			}
		}
		if !found {
			return ErrRedisReadGate
		}
	}
	if len(users) != len(g.original)+1 || g.owner(ctx) != nil || g.identity(ctx) != nil {
		return ErrRedisReadGate
	}
	markerFound := false
	for _, u := range users {
		if u.Name != g.marker {
			continue
		}
		markerFound = true
		off, on := false, false
		for _, f := range u.Flags {
			off = off || f == "off"
			on = on || f == "on"
		}
		allowed, e := redisGateAllowed(u.Commands, g.commandNames, g.categories)
		if e != nil || !off || on || len(allowed) != 0 || len(u.Selectors) != 0 || len(u.Passwords) != 0 {
			return ErrRedisReadGate
		}
	}
	if !markerFound {
		return ErrRedisReadGate
	}
	g.held = true
	return g.checkHeld(ctx)
}

func (g *RedisReadServiceGate) expectedUser(actual, want redisGateUser) error {
	if actual.Name != want.Name || !reflect.DeepEqual(actual.Flags, want.Flags) || !reflect.DeepEqual(actual.Passwords, want.Passwords) || actual.Keys != want.Keys || actual.Channels != want.Channels || len(actual.Selectors) != len(want.Selectors) {
		return ErrRedisReadGate
	}
	a, e := redisGateAllowed(actual.Commands, g.commandNames, g.categories)
	b, e2 := redisGateAllowed(want.Commands, g.commandNames, g.categories)
	if e != nil || e2 != nil || !reflect.DeepEqual(a, b) {
		return ErrRedisReadGate
	}
	for n, s := range actual.Selectors {
		w := want.Selectors[n]
		if s.Keys != w.Keys || s.Channels != w.Channels {
			return ErrRedisReadGate
		}
		a, e = redisGateAllowed(s.Commands, g.commandNames, g.categories)
		b, e2 = redisGateAllowed(w.Commands, g.commandNames, g.categories)
		if e != nil || e2 != nil || !reflect.DeepEqual(a, b) {
			return ErrRedisReadGate
		}
	}
	return nil
}
func (g *RedisReadServiceGate) owner(ctx context.Context) error {
	v, e := g.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
	if e != nil || stringBytes(v) != g.ownerValue {
		return ErrRedisReadGate
	}
	return nil
}
func (g *RedisReadServiceGate) checkHeld(ctx context.Context) error {
	if g.closed || !g.held || g.identity(ctx) != nil || g.owner(ctx) != nil {
		return ErrRedisReadGate
	}
	users, e := g.users(ctx)
	if e != nil || !reflect.DeepEqual(users, g.gated) || redisGateHash(users) != g.digest {
		return ErrRedisReadGate
	}
	return nil
}
func (g *RedisReadServiceGate) Recheck(ctx context.Context) error {
	if g == nil {
		return ErrRedisReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checkHeld(ctx)
}

// Actual collector consumption. Its repeated TeamSourceCheck performs the real
// native gate check in addition to original source/SQL/task authority. Daemon
// AOF writes and logical expiry are not mislabeled as application writes.
func (g *RedisReadServiceGate) Capture(ctx context.Context, dst io.Writer, sourceCheck TeamSourceCheck) error {
	if g == nil || sourceCheck == nil {
		return ErrRedisReadGate
	}
	err := CaptureSourceRedis(ctx, g.reader, dst, g.in.Policy, func(ctx context.Context) error {
		if sourceCheck(ctx) != nil {
			return ErrRedisReadGate
		}
		return g.Recheck(ctx)
	})
	if err != nil {
		g.mu.Lock()
		g.poisonTransport()
		_ = g.reader.Close()
		g.mu.Unlock()
	}
	return err
}

// Fresh recovery check is supplied by the genuine installation/task owner.
// The old capture check is not used after its context/deadline expires. Each
// same-connection request is acknowledged before the owner key is removed;
// unknown sends keep ownership and prevent a later acquisition from crossing.
func (g *RedisReadServiceGate) Restore(ctx context.Context, freshRecoveryCheck TeamSourceCheck) error {
	if g == nil || freshRecoveryCheck == nil {
		return ErrRedisReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || !g.ownerSent || freshRecoveryCheck(ctx) != nil {
		return ErrRedisReadGate
	}
	oldCheck := g.check
	g.check = freshRecoveryCheck
	defer func() { g.check = oldCheck }()
	if g.identity(ctx) != nil || g.readOriginalCustody(ctx) != nil {
		return ErrRedisReadGate
	}
	owner, ownerErr := g.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
	if ownerErr != nil {
		return ErrRedisReadGate
	}
	if owner == nil {
		// Reconcile only a genuine dispatched acquisition or an unknown final
		// DEL on this same original native incarnation. No owner + exact full
		// original ACLs is affirmative readback; absence alone is insufficient.
		users, e := g.users(ctx)
		if e != nil || !reflect.DeepEqual(users, g.original) || g.identity(ctx) != nil {
			return ErrRedisReadGate
		}
		g.closed, g.held = true, false
		return nil
	}
	if stringBytes(owner) != g.ownerValue || g.compatibleCurrent(ctx) != nil {
		return ErrRedisReadGate
	}
	for _, user := range g.original {
		if freshRecoveryCheck(ctx) != nil || g.owner(ctx) != nil {
			return ErrRedisReadGate
		}
		if user.Name == g.in.KeeperAccount {
			continue
		}
		if _, e := g.command(ctx, redisGateSetUser(user, user.redisGateSelector, user.Selectors)...); e != nil {
			return ErrRedisReadGate
		}
	}
	if _, e := g.command(ctx, []byte("ACL"), []byte("DELUSER"), []byte(g.marker)); e != nil {
		return ErrRedisReadGate
	}
	if _, e := g.command(ctx, []byte("ACL"), []byte("SAVE")); e != nil {
		return ErrRedisReadGate
	}
	users, e := g.users(ctx)
	if e != nil || !reflect.DeepEqual(users, g.original) || freshRecoveryCheck(ctx) != nil || g.owner(ctx) != nil {
		return ErrRedisReadGate
	}
	if _, e = g.command(ctx, []byte("DEL"), []byte(redisGateOwnerKey)); e != nil {
		return ErrRedisReadGate
	}
	v, e := g.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
	if e != nil || v != nil || g.identity(ctx) != nil {
		return ErrRedisReadGate
	}
	g.closed = true
	g.held = false
	return nil
}
