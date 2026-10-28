package systembackupread

import (
	"errors"
	"strings"
	"testing"
)

func TestCursorBindsAuthorizedTaskPage(t *testing.T) {
	codec, err := NewCursorCodec([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	request := PageRequest{Kind: BackupTask, Limit: 2}
	page := TaskPage{InstallationID: "installation_test", CutoffID: 3, BeforeID: 2, HasMore: true,
		Consistency: "stable_cutoff", Items: []TaskHeader{
			{InstallationID: "installation_test", Kind: BackupTask, ID: 3},
			{InstallationID: "installation_test", Kind: BackupTask, ID: 2},
		}}
	token, err := codec.Encode(request, page)
	if err != nil || len(token) == 0 || len(token) > maxCursorBytes {
		t.Fatal("encode", err)
	}
	decoded, err := codec.Decode(token, BackupTask, "", 2)
	if err != nil || decoded.InstallationID != page.InstallationID || decoded.CutoffID != 3 || decoded.BeforeID != 2 {
		t.Fatal("decode", decoded, err)
	}
	tampered := "A" + token[1:]
	if token[0] == 'A' {
		tampered = "B" + token[1:]
	}
	for _, test := range []struct {
		name   string
		token  string
		kind   TaskKind
		status string
		limit  int
	}{
		{"different task", token, DrillTask, "", 2},
		{"different filter", token, BackupTask, "failed", 2},
		{"different limit", token, BackupTask, "", 3},
		{"tampered payload", tampered, BackupTask, "", 2},
		{"oversized", strings.Repeat("x", maxCursorBytes+1), BackupTask, "", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			if next, err := codec.Decode(test.token, test.kind, test.status, test.limit); !errors.Is(err, ErrInvalid) || next != (PageRequest{}) {
				t.Fatal("cursor binding escaped", next, err)
			}
		})
	}
	page.Items[1].InstallationID = "installation_other"
	if token, err := codec.Encode(request, page); !errors.Is(err, ErrInvalid) || token != "" {
		t.Fatal("mixed installation page signed", token, err)
	}
}

func TestCursorRequiresDedicatedKeyAndCanonicalPayload(t *testing.T) {
	if c, err := NewCursorCodec([]byte("short")); !errors.Is(err, ErrInvalid) || c != nil {
		t.Fatal("weak key accepted", c, err)
	}
	key := []byte(strings.Repeat("k", 32))
	codec, err := NewCursorCodec(key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 'z'
	request := PageRequest{Kind: BackupTask, Status: "pending", Limit: 1}
	page := TaskPage{InstallationID: "installation_test", CutoffID: 2, BeforeID: 2, HasMore: true,
		Consistency: "eventual", Items: []TaskHeader{{InstallationID: "installation_test", Kind: BackupTask, Status: "pending", ID: 2}}}
	token, err := codec.Encode(request, page)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decode(token, BackupTask, "pending", 1); err != nil {
		t.Fatal("key was not copied", err)
	}
	other, _ := NewCursorCodec([]byte(strings.Repeat("z", 32)))
	if _, err := other.Decode(token, BackupTask, "pending", 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("another key accepted token", err)
	}
	page.BeforeID = 3
	if _, err := codec.Encode(request, page); !errors.Is(err, ErrInvalid) {
		t.Fatal("cursor above cutoff accepted", err)
	}
}
