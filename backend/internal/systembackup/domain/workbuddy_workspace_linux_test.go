//go:build linux

package domain

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkBuddyUIDWorkspace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated Linux root required to create distinct test owners")
	}
	want := WorkBuddyUIDIdentity{Schema: 1, InstanceID: 7, UserID: 4, UID: 21000, GID: 21000}
	for _, name := range []string{"valid", "wrong-uid", "wrong-gid", "wrong-instance", "wrong-user", "wrong-schema", "unknown-field", "duplicate-field", "trailing-json", "home-owner", "home-link", "marker-link"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			home := filepath.Join(dir, "home")
			marker := filepath.Join(dir, ".workbuddy-identity.json")
			if e := os.Mkdir(home, 0700); e != nil {
				t.Fatal(e)
			}
			if e := os.Chown(home, want.UID, want.GID); e != nil {
				t.Fatal(e)
			}
			got := want
			switch name {
			case "wrong-uid":
				got.UID++
			case "wrong-gid":
				got.GID++
			case "wrong-instance":
				got.InstanceID++
			case "wrong-user":
				got.UserID++
			case "wrong-schema":
				got.Schema++
			}
			raw, _ := json.Marshal(got)
			switch name {
			case "unknown-field":
				raw = append(raw[:len(raw)-1], []byte(`,"extra":1}`)...)
			case "duplicate-field":
				raw = append(raw[:len(raw)-1], []byte(`,"uid":21000}`)...)
			case "trailing-json":
				raw = append(raw, []byte(`{}`)...)
			}
			if e := os.WriteFile(marker, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if name == "home-owner" {
				if e := os.Chown(home, 21001, 21001); e != nil {
					t.Fatal(e)
				}
			}
			if name == "home-link" {
				if e := os.Rename(home, home+"-real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("home-real", home); e != nil {
					t.Fatal(e)
				}
			}
			if name == "marker-link" {
				if e := os.Rename(marker, marker+"-real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(".workbuddy-identity.json-real", marker); e != nil {
					t.Fatal(e)
				}
			}
			root, e := os.OpenRoot(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer root.Close()
			e = VerifyWorkBuddyUIDWorkspace(root, want)
			if name == "valid" && e != nil {
				t.Fatal(e)
			}
			if name != "valid" && !errors.Is(e, ErrData) {
				t.Fatalf("accepted invalid workspace: %v", e)
			}
		})
	}
}
