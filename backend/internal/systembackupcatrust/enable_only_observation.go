package systembackupcatrust

import (
	"bytes"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// EnableOnlyObservation is a native CA observation, not a config writer or
// bootstrap check. The separate original signed mapping and mutation authority
// MUST be authenticated by the concrete production composition.
type EnableOnlyObservation struct {
	mu                                sync.Mutex
	origin                            *EnableOnlyObservation
	failed                            atomic.Bool
	validator                         *Validator
	ctx                               context.Context
	started, until, floor, inputFloor time.Time
	tx                                *sql.Tx
}

func (*EnableOnlyObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (o *EnableOnlyObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o || o.failed.Load() {
		return time.Time{}
	}
	return o.until
}
func (v *Validator) ObserveEnableOnly(ctx context.Context, in sec.ConfigMutationResourceInput) (*EnableOnlyObservation, error) {
	fail := func() (*EnableOnlyObservation, error) { return nil, sec.ErrRegistrationUnavailable }
	if v == nil || v.now == nil || !sameCandidateCAContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil || in.InstallationID() != v.binding.InstallationID {
		return fail()
	}
	current, _ := in.Configs()
	return v.observeEnableOnlyCurrent(ctx, current)
}
func (v *Validator) observeEnableOnlyCurrent(ctx context.Context, current sec.ConfigValues) (*EnableOnlyObservation, error) {
	fail := func() (*EnableOnlyObservation, error) { return nil, sec.ErrRegistrationUnavailable }
	if v == nil || v.now == nil || ctx == nil || ctx.Err() != nil {
		return fail()
	}

	if current.SHA256() != v.binding.ConfigSHA256 {
		return fail()
	}
	started := v.now().UTC().Truncate(time.Microsecond)
	if !v.live(started) {
		return fail()
	}
	ref, raw, err := v.files()
	if err != nil {
		return fail()
	}
	matched := 0
	for _, pin := range current.References() {
		if pin.Purpose == v.binding.Purpose && ref.MatchesBootstrapPin(pin) {
			matched++
		}
	}
	if matched != 1 {
		return fail()
	}
	pool := x509.NewCertPool()
	expires := v.binding.ExpiresAt
	certificates := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		// pem.Decode otherwise skips arbitrary leading text. Only public CERTIFICATE
		// blocks and whitespace are permitted; private keys/junk cannot be ignored.
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return fail()
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fail()
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || started.Before(cert.NotBefore) || !started.Before(cert.NotAfter) {
			return fail()
		}
		pool.AddCert(cert)
		expires = earliest(expires, cert.NotAfter)
		certificates++
		if certificates > 128 {
			return fail()
		}
		raw = rest
	}
	if certificates == 0 {
		return fail()
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: v.host}}
	networkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(networkCtx, "tcp", v.address)
	if err != nil {
		return fail()
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return fail()
	}
	state := tlsConn.ConnectionState()
	closeErr := conn.Close()
	if closeErr != nil || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || ctx.Err() != nil {
		return fail()
	}
	for _, cert := range state.VerifiedChains[0] {
		expires = earliest(expires, cert.NotAfter)
	}
	observed := v.now().UTC()
	expires = earliest(expires, started.Add(30*time.Second))
	if deadline, ok := ctx.Deadline(); ok {
		expires = earliest(expires, deadline)
	}
	if !v.live(observed) || observed.Before(started) || !observed.Before(expires) {
		return fail()
	}
	// Check the exact local authority inputs again after external work. Recheck
	// later performs the same reads without opening another network connection.
	if _, _, err = v.files(); err != nil {
		return fail()
	}
	finished := v.now().UTC()
	if ctx.Err() != nil || finished.Before(observed) || !finished.Before(expires) || !v.live(finished) {
		return fail()
	}
	copy := *v
	o := &EnableOnlyObservation{validator: &copy, ctx: ctx, started: started, until: expires}
	o.origin = o
	return o, nil
}
func (o *EnableOnlyObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (o *EnableOnlyObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return sec.ErrRegistrationUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.origin != o || o.failed.Load() || !sameCandidateCAContext(ctx, o.ctx) || ctx.Err() != nil || tx == nil || o.tx != nil && o.tx != tx || !o.inputFloor.IsZero() && now.Before(o.inputFloor) {
		return o.fail()
	}
	valid := func(t time.Time) bool { return o.validator.live(t) && !t.Before(o.started) && t.Before(o.until) }
	if !valid(now) || !valid(o.validator.now().UTC()) {
		return o.fail()
	}
	if _, _, e := o.validator.files(); e != nil {
		return o.fail()
	}
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != o.validator.binding.ServerUUID || database != o.validator.binding.Database {
		return o.fail()
	}
	if _, _, e := o.validator.files(); e != nil {
		return o.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !o.floor.IsZero() && tail.Before(o.floor) || !valid(tail) || !valid(o.validator.now().UTC()) || ctx.Err() != nil {
		return o.fail()
	}
	o.tx = tx
	o.floor = tail
	o.inputFloor = now
	return nil
}
