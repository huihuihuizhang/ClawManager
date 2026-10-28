package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"clawreef/internal/config"
	"github.com/go-ldap/ldap/v3"
)

// The connection/upgrade retains the existing five-second dial budget. A
// request timeout also bounds LDAP operations whose server ignores timeLimit.
const ldapConnectTimeout = 5 * time.Second
const ldapRequestTimeout = 10 * time.Second

// Closing the transport on cancellation interrupts TLS, LDAP reads and writes.
// Normal LDAP Close unregisters the hook instead of retaining a completed
// connection until a long-lived caller context eventually ends.
type ldapRequestConn struct {
	net.Conn
	stop func() bool
}

func (c *ldapRequestConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func ldapRequestError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func dialLDAPRequest(ctx context.Context, cfg config.LDAPConfig, tlsConfig *tls.Config) (*ldap.Conn, error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	connectCtx, cancel := context.WithTimeout(ctx, ldapConnectTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		return nil, ldapRequestError(ctx, fmt.Errorf("%w: ldap dial failed: %v", ErrEnterpriseUnavailable, err))
	}
	bound := &ldapRequestConn{Conn: raw}
	// Close raw, not ldap.Conn: its reader/process goroutines may themselves
	// be waiting on the interrupted operation or transitioning through StartTLS.
	bound.stop = context.AfterFunc(ctx, func() { _ = raw.Close() })
	deadline, _ := connectCtx.Deadline()
	if err := bound.SetDeadline(deadline); err != nil {
		_ = bound.Close()
		return nil, ldapRequestError(ctx, ErrEnterpriseUnavailable)
	}
	var transport net.Conn = bound
	if cfg.UseTLS {
		secure := tls.Client(bound, tlsConfig)
		if err := secure.HandshakeContext(connectCtx); err != nil {
			_ = bound.Close()
			return nil, ldapRequestError(ctx, fmt.Errorf("%w: ldap dial failed: %v", ErrEnterpriseUnavailable, err))
		}
		transport = secure
	}
	conn := ldap.NewConn(transport, cfg.UseTLS)
	conn.SetTimeout(ldapRequestTimeout)
	conn.Start()
	ready := false
	defer func() {
		if !ready {
			_ = conn.Close()
		}
	}()
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			return nil, ldapRequestError(ctx, fmt.Errorf("%w: ldap starttls failed: %v", ErrEnterpriseUnavailable, err))
		}
	}
	if err := connectCtx.Err(); err != nil {
		return nil, ldapRequestError(ctx, fmt.Errorf("%w: ldap dial failed: %v", ErrEnterpriseUnavailable, err))
	}
	// Only the setup deadline ends here. The request cancellation hook and
	// per-operation LDAP timeout remain active for service/search/user binds.
	if err := bound.SetDeadline(time.Time{}); err != nil {
		return nil, ldapRequestError(ctx, ErrEnterpriseUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ready = true
	return conn, nil
}
