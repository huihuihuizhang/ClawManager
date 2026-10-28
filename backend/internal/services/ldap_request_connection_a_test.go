package services

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/config"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const ldapAUserDN = "uid=alice,dc=example,dc=test"
const ldapAServiceDN = "cn=service,dc=example,dc=test"

// A controlled wire peer, not an enterprise directory. It exercises the real
// go-ldap client, TCP, certificate validation and TLS/StartTLS handshake.
type ldapAPeer struct {
	cfg                      config.LDAPConfig
	listener                 net.Listener
	certificate              tls.Certificate
	mode, stall              string
	rejectUpgrade, rejectTLS bool
	reached, done            chan struct{}
	err                      chan error
	mu                       sync.Mutex
	raw                      net.Conn
	accepted                 atomic.Int32
}

func newLDAPAPeer(t *testing.T, mode, stall string, rejectUpgrade, rejectTLS bool) *ldapAPeer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ldap.loopback.test"}, DNSNames: []string{"ldap.loopback.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	p := &ldapAPeer{listener: ln, certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, mode: mode, stall: stall, rejectUpgrade: rejectUpgrade, rejectTLS: rejectTLS, reached: make(chan struct{}), done: make(chan struct{}), err: make(chan error, 1)}
	p.cfg = config.LDAPConfig{Host: "127.0.0.1", Port: n, UseTLS: mode == "ldaps", StartTLS: mode == "starttls", TLSCAFile: ca, TLSServerName: "ldap.loopback.test", BindDN: ldapAServiceDN, BindPassword: "fixture-service-password", BaseDN: "dc=example,dc=test", UserFilter: "(uid=%s)", GroupFilter: "(member=%s)", UsernameAttribute: "uid", EmailAttribute: "mail", DefaultRole: "user"}
	if mode == "plain" {
		p.cfg.TLSCAFile = ""
	}
	t.Cleanup(func() {
		p.stop()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("LDAP fixture did not stop")
		}
		select {
		case err := <-p.err:
			t.Error(err)
		default:
		}
	})
	go func() {
		defer close(p.done)
		raw, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.err <- errors.New("LDAP fixture accept failed")
			}
			return
		}
		p.accepted.Add(1)
		p.mu.Lock()
		p.raw = raw
		p.mu.Unlock()
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
		if err := p.serve(raw); err != nil {
			p.err <- err
		}
	}()
	return p
}

func (p *ldapAPeer) stop() {
	_ = p.listener.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.raw != nil {
		_ = p.raw.Close()
	}
}

func (p *ldapAPeer) waitStage(t *testing.T) {
	t.Helper()
	select {
	case <-p.reached:
	case <-p.done:
		t.Fatal("LDAP peer stopped before the intended operation")
	case <-time.After(5 * time.Second):
		t.Fatal("LDAP operation did not reach wire peer")
	}
}

func (p *ldapAPeer) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("LDAP request left its transport open")
	}
}

func (p *ldapAPeer) hold(c net.Conn) error {
	close(p.reached)
	_, _ = io.Copy(io.Discard, c)
	return nil
}

func (p *ldapAPeer) handshake(c net.Conn) (net.Conn, error) {
	secure := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{p.certificate}, MinVersion: tls.VersionTLS12})
	err := secure.Handshake()
	if p.rejectTLS {
		if err == nil {
			return nil, errors.New("unexpectedly accepted TLS fixture")
		}
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("LDAP fixture TLS handshake failed")
	}
	return secure, nil
}

func ldapARead(c net.Conn, tag ber.Tag) (*ber.Packet, int64, error) {
	packet, err := ber.ReadPacket(c)
	if err != nil || len(packet.Children) < 2 || packet.Children[1].Tag != tag {
		return nil, 0, errors.New("unexpected LDAP wire operation")
	}
	id, ok := packet.Children[0].Value.(int64)
	if !ok {
		return nil, 0, errors.New("invalid LDAP message ID")
	}
	return packet.Children[1], id, nil
}

func ldapAWrite(c net.Conn, id int64, op *ber.Packet) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "response")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "id"))
	packet.AppendChild(op)
	_, err := io.Copy(c, bytes.NewReader(packet.Bytes()))
	return err
}

func ldapAResult(c net.Conn, id int64, tag ber.Tag, code int64) error {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "code"))
	for range 2 {
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "text"))
	}
	return ldapAWrite(c, id, op)
}

func ldapASearchEntry(c net.Conn, id int64) error {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ldapAUserDN, "dn"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, pair := range [][2]string{{"uid", "alice"}, {"mail", "alice@example.test"}} {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, pair[0], "name"))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "values")
		values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, pair[1], "value"))
		attr.AppendChild(values)
		attrs.AppendChild(attr)
	}
	op.AppendChild(attrs)
	if err := ldapAWrite(c, id, op); err != nil {
		return err
	}
	return ldapAResult(c, id, ldap.ApplicationSearchResultDone, 0)
}

func (p *ldapAPeer) serve(raw net.Conn) error {
	var c net.Conn = raw
	if p.mode == "starttls" {
		_, id, err := ldapARead(c, ldap.ApplicationExtendedRequest)
		if err != nil {
			return err
		}
		if p.stall == "upgrade-response" {
			return p.hold(c)
		}
		code := int64(0)
		if p.rejectUpgrade {
			code = 53
		}
		if err := ldapAResult(c, id, ldap.ApplicationExtendedResponse, code); err != nil {
			return err
		}
		if p.rejectUpgrade {
			_, _ = io.Copy(io.Discard, c)
			return nil
		}
	}
	if p.mode != "plain" {
		if p.stall == "handshake" {
			var hello [1]byte
			if _, err := io.ReadFull(c, hello[:]); err != nil || hello[0] != 22 {
				return errors.New("TLS ClientHello missing before cancellation")
			}
			return p.hold(c)
		}
		secure, err := p.handshake(c)
		if err != nil || secure == nil {
			return err
		}
		c = secure
	}
	for _, stage := range []string{"service-bind", "search", "user-bind"} {
		tag := ber.Tag(ldap.ApplicationBindRequest)
		if stage == "search" {
			tag = ldap.ApplicationSearchRequest
		}
		op, id, err := ldapARead(c, tag)
		if err != nil {
			return err
		}
		if stage != "search" {
			wantDN, wantPassword := ldapAServiceDN, "fixture-service-password"
			if stage == "user-bind" {
				wantDN, wantPassword = ldapAUserDN, "fixture-user-password"
			}
			if len(op.Children) != 3 || op.Children[1].Data.String() != wantDN || op.Children[2].Data.String() != wantPassword {
				return errors.New("LDAP fixture received wrong bind identity")
			}
		}
		if p.stall == stage {
			return p.hold(c)
		}
		if stage == "search" {
			err = ldapASearchEntry(c, id)
		} else {
			err = ldapAResult(c, id, ldap.ApplicationBindResponse, 0)
		}
		if err != nil {
			return err
		}
	}
	_, _ = io.Copy(io.Discard, c)
	return nil
}

type ldapAOutcome struct {
	user *EnterpriseUser
	err  error
}

func ldapAAuthenticate(t *testing.T, p *ldapAPeer, ctx context.Context) <-chan ldapAOutcome {
	t.Helper()
	a, err := NewLDAPAuthenticator(p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan ldapAOutcome, 1)
	go func() {
		u, err := a.AuthenticateByIdentity(ctx, ldapAUserDN, "fixture-user-password")
		result <- ldapAOutcome{u, err}
	}()
	return result
}

func ldapAAwait(t *testing.T, p *ldapAPeer, result <-chan ldapAOutcome, timeout time.Duration) ldapAOutcome {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(timeout):
		p.stop()
		select {
		case <-result:
		case <-time.After(5 * time.Second):
			t.Error("LDAP client did not stop after peer cleanup")
		}
		t.Fatal("LDAP operation exceeded its cancellation/timeout bound")
		return ldapAOutcome{}
	}
}

func TestLDAPRequestARealTransportAuthentication(t *testing.T) {
	for _, mode := range []string{"plain", "ldaps", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			p := newLDAPAPeer(t, mode, "", false, false)
			r := ldapAAwait(t, p, ldapAAuthenticate(t, p, context.Background()), 5*time.Second)
			if r.err != nil || r.user == nil || r.user.ExternalID != ldapAUserDN || r.user.Username != "alice" || r.user.Email != "alice@example.test" || r.user.Role != "user" {
				t.Fatal("real LDAP/TLS login failed", r.err)
			}
			p.waitClosed(t)
		})
	}
}

func TestLDAPRequestACancelClosesTransport(t *testing.T) {
	for _, tc := range []struct{ mode, stage string }{{"plain", "service-bind"}, {"plain", "search"}, {"plain", "user-bind"}, {"ldaps", "handshake"}, {"ldaps", "service-bind"}, {"ldaps", "user-bind"}, {"starttls", "upgrade-response"}, {"starttls", "handshake"}} {
		t.Run(tc.mode+"/"+tc.stage, func(t *testing.T) {
			p := newLDAPAPeer(t, tc.mode, tc.stage, false, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := ldapAAuthenticate(t, p, ctx)
			p.waitStage(t)
			cancel()
			r := ldapAAwait(t, p, result, 2*time.Second)
			if r.user != nil || !errors.Is(r.err, context.Canceled) {
				t.Fatal("cancelled LDAP request returned identity or wrong error", r.err)
			}
			p.waitClosed(t)
		})
	}
}

func TestLDAPRequestATLSFailuresStayClosed(t *testing.T) {
	for _, kind := range []string{"ldaps-name", "ldaps-ca", "starttls-name", "starttls-reject"} {
		t.Run(kind, func(t *testing.T) {
			mode := "ldaps"
			if kind == "starttls-name" || kind == "starttls-reject" {
				mode = "starttls"
			}
			p := newLDAPAPeer(t, mode, "", kind == "starttls-reject", kind != "starttls-reject")
			if kind == "ldaps-ca" {
				p.cfg.TLSCAFile = ""
			} else if kind != "starttls-reject" {
				p.cfg.TLSServerName = "wrong.example.test"
			}
			r := ldapAAwait(t, p, ldapAAuthenticate(t, p, context.Background()), 5*time.Second)
			if r.user != nil || !errors.Is(r.err, ErrEnterpriseUnavailable) {
				t.Fatal("TLS failure authenticated or lost unavailable status", r.err)
			}
			p.waitClosed(t)
		})
	}
}

func TestLDAPRequestAInvalidContextsDontDial(t *testing.T) {
	for _, kind := range []string{"nil", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			p := newLDAPAPeer(t, "plain", "", false, false)
			var ctx context.Context
			if kind == "cancelled" {
				c, cancel := context.WithCancel(context.Background())
				cancel()
				ctx = c
			}
			r := ldapAAwait(t, p, ldapAAuthenticate(t, p, ctx), time.Second)
			if r.user != nil || !errors.Is(r.err, context.Canceled) || p.accepted.Load() != 0 {
				t.Fatal("invalid request reached directory")
			}
		})
	}
}

func TestLDAPRequestADeadlineClosesServiceBind(t *testing.T) {
	p := newLDAPAPeer(t, "plain", "service-bind", false, false)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := ldapAAuthenticate(t, p, ctx)
	p.waitStage(t)
	r := ldapAAwait(t, p, result, 5*time.Second)
	if r.user != nil || !errors.Is(r.err, context.DeadlineExceeded) {
		t.Fatal("request deadline was ignored", r.err)
	}
	p.waitClosed(t)
}

func TestLDAPRequestAListCancellationReturnsNoRows(t *testing.T) {
	p := newLDAPAPeer(t, "plain", "search", false, false)
	a, err := NewLDAPAuthenticator(p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan ldapAOutcome, 1)
	go func() {
		users, err := a.ListUsers(ctx)
		if len(users) != 0 {
			result <- ldapAOutcome{err: fmt.Errorf("partial rows returned: %d", len(users))}
			return
		}
		result <- ldapAOutcome{err: err}
	}()
	p.waitStage(t)
	cancel()
	r := ldapAAwait(t, p, result, 2*time.Second)
	if !errors.Is(r.err, context.Canceled) {
		t.Fatal("cancelled directory listing returned rows or wrong error", r.err)
	}
	p.waitClosed(t)
}

func TestLDAPRequestAUnresponsiveServerHasRequestTimeout(t *testing.T) {
	p := newLDAPAPeer(t, "plain", "service-bind", false, false)
	started := time.Now()
	result := ldapAAuthenticate(t, p, context.Background())
	p.waitStage(t)
	r := ldapAAwait(t, p, result, 15*time.Second)
	if r.user != nil || !errors.Is(r.err, ErrEnterpriseUnavailable) || time.Since(started) < 9*time.Second {
		t.Fatal("unresponsive directory was not bounded by LDAP timeout", r.err)
	}
	p.waitClosed(t)
}
