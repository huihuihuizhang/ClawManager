package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

func providerCapabilityFixture(t *testing.T, b reg.Binding, op kms.Operation) (ProviderCapabilityRecord, ProviderCapabilityPin, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ref, path := b.GenerateRef, "transit/datakey/plaintext/"+b.Provider.KeyName
	if op == kms.Unwrap {
		ref, path = b.UnwrapRef, "transit/decrypt/"+b.Provider.KeyName
	}
	now := time.Now().UTC()
	r := ProviderCapabilityRecord{Facts: ProviderCapabilityFacts{Binding: b, Operation: op, Permission: ProviderCapabilityPermission{Path: path, ProviderVersion: b.Key.ProviderVersion, AuthMount: "original-jwt", Role: "original-role-" + string(op), Policy: "original-policy-" + string(op), PolicySHA256: strings.Repeat("a", 64), RoleSHA256: strings.Repeat("b", 64), JWTTrustSHA256: strings.Repeat("c", 64), Reference: ref}}, Source: reg.SourceRecord{SourceID: "independent-original-permission-owner", RecordID: "sev_capability_" + string(op), RecordVersion: "original-r7"}, Revision: "observer-r5", NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	raw, _ := json.Marshal(r.Facts)
	h := sha256.Sum256(raw)
	r.Source.ContentSHA256 = hex.EncodeToString(h[:])
	return r, ProviderCapabilityPin{Source: r.Source, Issuer: public}, key
}

func signCapabilityFixture(t *testing.T, r ProviderCapabilityRecord, key ed25519.PrivateKey) capabilityEvidence {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(SignedProviderCapabilityRecord{Record: raw, Signature: ed25519.Sign(key, append([]byte(ProviderCapabilityDomain), raw...))})
	if err != nil {
		t.Fatal(err)
	}
	return capabilityEvidence{raw: envelope, until: time.Now().Add(time.Minute)}
}

type capabilitySQLState struct {
	installation string
	database     reg.DatabaseIdentity
	now          time.Time
	items        map[string]capabilityEvidence
	queries      []string
	wrongDB      bool
}
type capabilityConnector struct{ s *capabilitySQLState }

func (c capabilityConnector) Driver() driver.Driver { return ownerDriver{} }
func (c capabilityConnector) Connect(context.Context) (driver.Conn, error) {
	return &capabilitySQLConn{s: c.s}, nil
}

type capabilitySQLConn struct{ s *capabilitySQLState }

func (*capabilitySQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*capabilitySQLConn) Close() error                        { return nil }
func (c *capabilitySQLConn) Begin() (driver.Tx, error)         { return capabilitySQLTx{}, nil }
func (c *capabilitySQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return capabilitySQLTx{}, nil
}

type capabilitySQLTx struct{}

func (capabilitySQLTx) Commit() error   { return nil }
func (capabilitySQLTx) Rollback() error { return nil }
func (c *capabilitySQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.queries = append(c.s.queries, q)
	if strings.Contains(q, "@@server_uuid") {
		db := c.s.database.Database
		if c.s.wrongDB {
			db = "foreign"
		}
		return &ownerRows{columns: []string{"uuid", "database", "now"}, values: []driver.Value{c.s.database.ServerUUID, db, c.s.now}}, nil
	}
	r := &ownerRows{columns: []string{"raw", "hash", "size", "expires"}}
	if len(args) != 2 || args[1].Value != c.s.installation || !strings.Contains(q, "evidence_type='capability_snapshot'") {
		return r, nil
	}
	e, ok := c.s.items[args[0].Value.(string)]
	if !ok {
		return r, nil
	}
	h := sha256.Sum256(e.raw)
	r.values = []driver.Value{e.raw, hex.EncodeToString(h[:]), int64(len(e.raw)), e.until}
	return r, nil
}

func TestSQLProviderCapabilityPreparationReadsAndRechecksOriginalEvidence(t *testing.T) {
	owner, _, _ := ownerRecordFixture(t)
	b := owner.Binding
	g, gpin, gkey := providerCapabilityFixture(t, b, kms.Generate)
	u, upin, ukey := providerCapabilityFixture(t, b, kms.Unwrap)
	state := &capabilitySQLState{installation: b.InstallationID, database: reg.DatabaseIdentity{ServerUUID: "isolated-uuid", Database: "isolated-db"}, now: time.Now(), items: map[string]capabilityEvidence{gpin.Source.RecordID: signCapabilityFixture(t, g, gkey), upin.Source.RecordID: signCapabilityFixture(t, u, ukey)}}
	db := sql.OpenDB(capabilityConnector{state})
	defer db.Close()
	p, err := NewSQLProviderCapabilityPreparation(db, state.database, b.InstallationID, gpin, upin)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := p.PrepareCapabilities(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if caps.Generate.Operation() != kms.Generate || caps.Unwrap.Operation() != kms.Unwrap || caps.Generate.Source() != gpin.Source || caps.Unwrap.Source() != upin.Source {
		t.Fatal("purpose/source lost")
	}
	copy := caps.Generate.Binding()
	copy.GenerateRef.RawJSON[0] = ' '
	if caps.Generate.Binding().GenerateRef.RawJSON[0] == ' ' {
		t.Fatal("prepared binding exposed mutable bytes")
	}
	facts := reg.Snapshot{Database: state.database, InstallationID: b.InstallationID}
	prepared := caps.Generate.(*sqlPreparedCapability)
	if prepared.recheck(context.Background(), db, facts, state.now) != nil {
		t.Fatal("original current capability rejected")
	}
	if !strings.Contains(state.queries[len(state.queries)-1], "FOR SHARE") {
		t.Fatal("transaction recheck lacks current locking read")
	}
	if prepared.Recheck(context.Background(), db, reg.LockedSnapshot{}, state.now) == nil {
		t.Fatal("unbound/foreign locked snapshot accepted")
	}
	e := state.items[gpin.Source.RecordID]
	e.until = e.until.Add(time.Second)
	state.items[gpin.Source.RecordID] = e
	if prepared.recheck(context.Background(), db, facts, state.now) == nil {
		t.Fatal("evidence expiry renewed original capability")
	}
	delete(state.items, gpin.Source.RecordID)
	if _, err = p.PrepareCapabilities(context.Background(), b); err == nil {
		t.Fatal("missing original capability accepted")
	}
	state.wrongDB = true
	if _, err = p.PrepareCapabilities(context.Background(), b); err == nil {
		t.Fatal("foreign database accepted")
	}
}

func TestProviderCapabilityRecordRejectsWrongPurposeVersionAndRevocation(t *testing.T) {
	owner, _, _ := ownerRecordFixture(t)
	b := owner.Binding
	base, pin, key := providerCapabilityFixture(t, b, kms.Generate)
	for name, change := range map[string]func(*ProviderCapabilityRecord){
		"wrong operation":        func(r *ProviderCapabilityRecord) { r.Facts.Operation = kms.Unwrap },
		"wrong version":          func(r *ProviderCapabilityRecord) { r.Facts.Permission.ProviderVersion = "4" },
		"wrong path":             func(r *ProviderCapabilityRecord) { r.Facts.Permission.Path = "transit/decrypt/" + b.Provider.KeyName },
		"wrong typed purpose":    func(r *ProviderCapabilityRecord) { r.Facts.Permission.Reference = b.UnwrapRef },
		"root policy":            func(r *ProviderCapabilityRecord) { r.Facts.Permission.Policy = "root" },
		"expired":                func(r *ProviderCapabilityRecord) { r.Until = time.Now().Add(-time.Second) },
		"future":                 func(r *ProviderCapabilityRecord) { r.NotBefore = time.Now().Add(time.Minute) },
		"revoked":                func(r *ProviderCapabilityRecord) { r.Revoked = true },
		"foreign installation":   func(r *ProviderCapabilityRecord) { r.Facts.Binding.InstallationID = "other" },
		"missing provider proof": func(r *ProviderCapabilityRecord) { r.Facts.Permission.RoleSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			change(&r)
			// Even an original observer's signature over malformed/wrong-purpose
			// material and a recomputed source digest cannot change the operation.
			raw, _ := json.Marshal(r.Facts)
			h := sha256.Sum256(raw)
			r.Source.ContentSHA256 = hex.EncodeToString(h[:])
			p := pin
			p.Source = r.Source
			if _, err := authenticateProviderCapability(signCapabilityFixture(t, r, key), p, b, kms.Generate, time.Now()); err == nil {
				t.Fatal("invalid capability record accepted")
			}
		})
	}
	e := signCapabilityFixture(t, base, key)
	bad := pin
	bad.Issuer = append(ed25519.PublicKey(nil), pin.Issuer...)
	bad.Issuer[0] ^= 0xff
	if _, err := authenticateProviderCapability(e, bad, b, kms.Generate, time.Now()); err == nil {
		t.Fatal("wrong permission issuer accepted")
	}
	var envelope SignedProviderCapabilityRecord
	json.Unmarshal(e.raw, &envelope)
	envelope.Record = bytesDuplicateRevision(envelope.Record)
	envelope.Signature = ed25519.Sign(key, append([]byte(ProviderCapabilityDomain), envelope.Record...))
	e.raw, _ = json.Marshal(envelope)
	if _, err := authenticateProviderCapability(e, pin, b, kms.Generate, time.Now()); err == nil {
		t.Fatal("duplicate signed field accepted")
	}
}

func bytesDuplicateRevision(raw []byte) []byte {
	return []byte(strings.Replace(string(raw), `"Revision":"observer-r5"`, `"Revision":"observer-r5","Revision":"observer-r5"`, 1))
}
