package systembackup

import "context"

// Caller holds g.mu (or is still inside the unexposed constructor). Any error,
// including an ACL refusal, conservatively poisons this ordered RESP stream.
// No later reply can be mistaken for a previous unknown command's response.
func (g *RedisReadServiceGate) command(ctx context.Context, args ...[]byte) (any, error) {
	if g.transportFailed || g.admin == nil {
		return nil, ErrRedisReadGate
	}
	v, err := g.admin.command(ctx, args...)
	if err != nil {
		g.poisonTransport()
		return nil, ErrRedisReadGate
	}
	return v, nil
}
func (g *RedisReadServiceGate) poisonTransport() {
	g.transportFailed = true
	if g.admin != nil {
		_ = g.admin.Close()
	}
}

// RestoreWithFreshClients requires two newly authenticated TLS connections.
// The genuine owner's fresh recovery authority is checked before replacing
// the old streams. Native same-runID, PodUID, complete ACL snapshot, custody,
// endpoint and exact account/DB identities are rechecked before any mutation.
// This is not a process-reopen or cross-incarnation recovery mechanism.
func (g *RedisReadServiceGate) RestoreWithFreshClients(ctx context.Context, admin, reader *RedisClient, fresh TeamSourceCheck) error {
	if g == nil || admin == nil || reader == nil || admin == reader || fresh == nil || fresh(ctx) != nil {
		return ErrRedisReadGate
	}
	g.mu.Lock()
	if g.origin != g || admin == g.admin || reader == g.reader || admin == g.reader || reader == g.admin || admin.database != 0 || reader.database != g.in.Policy.Policy.DB {
		g.mu.Unlock()
		return ErrRedisReadGate
	}
	oldAdmin, oldReader := g.admin, g.reader
	if oldAdmin != nil {
		_ = oldAdmin.Close()
	}
	if oldReader != nil {
		_ = oldReader.Close()
	}
	g.admin, g.reader, g.transportFailed = admin, reader, false
	for client, name := range map[*RedisClient]string{admin: g.in.KeeperAccount, reader: g.in.ReaderAccount} {
		v, e := client.command(ctx, []byte("ACL"), []byte("WHOAMI"))
		id, _, identityErr := client.Identity(ctx)
		if e != nil || identityErr != nil || stringBytes(v) != name || id != g.in.Policy.ServerID {
			g.poisonTransport()
			_ = reader.Close()
			g.mu.Unlock()
			return ErrRedisReadGate
		}
	}
	closed := g.closed
	g.mu.Unlock()
	if closed {
		_, e := g.ObserveRecovered(ctx, fresh)
		return e
	}
	return g.Restore(ctx, fresh)
}

// Close releases only local descriptors/key bytes. It never thaws a native
// ACL, removes the ownership key, deletes custody, or reports source recovery.
func (g *RedisReadServiceGate) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.transportFailed = true
	if g.admin != nil {
		_ = g.admin.Close()
	}
	if g.reader != nil {
		_ = g.reader.Close()
	}
	if g.custody != nil {
		_ = g.custody.Close()
		g.custody = nil
	}
	clear(g.custodyKey)
}

// A genuine owner uses this only for an undispatched actor during partial
// recovery/admission abort. It samples native original ACLs and absence of the
// coordination owner; the private dispatch flag cannot be supplied as DATA.
func (g *RedisReadServiceGate) ConfirmNeverAcquired(ctx context.Context, fresh TeamSourceCheck) error {
	if g == nil || fresh == nil {
		return ErrRedisReadGate
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.origin != g || g.ownerSent || g.mutated || g.held || fresh(ctx) != nil {
		return ErrRedisReadGate
	}
	old := g.check
	g.check = fresh
	defer func() { g.check = old }()
	if g.identity(ctx) != nil || g.readOriginalCustody(ctx) != nil {
		return ErrRedisReadGate
	}
	owner, e := g.command(ctx, []byte("GET"), []byte(redisGateOwnerKey))
	if e != nil || owner != nil {
		return ErrRedisReadGate
	}
	users, e := g.users(ctx)
	if e != nil || redisGateHash(users) != redisGateHash(g.original) || g.identity(ctx) != nil {
		return ErrRedisReadGate
	}
	g.closed = true
	return nil
}
