package systembackupsecurity

import (
	"bytes"
	"context"
	"testing"
)

func TestLoginSessionsCloseErasesOwnedKeyAndRejectsReuse(t *testing.T) {
	s, _, mint := loginSessionsFixture(t)
	pair := mint()
	db := s.db
	held := s.secret
	if _, err := s.token(pair.AccessToken, "access"); err != nil {
		t.Fatal("fixture token invalid", err)
	}
	s.Close()
	s.Close()
	if s.db != nil || len(s.secret) != 0 || !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("owned session key retained")
	}
	if _, err := s.token(pair.AccessToken, "access"); err == nil {
		t.Fatal("closed recorder verified token")
	}
	if s.RecordPair(context.Background(), pair) == nil || s.RevokeUserSessions(context.Background(), 42) == nil {
		t.Fatal("closed recorder accessed database")
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal("borrowed DB was closed", err)
	}
}
