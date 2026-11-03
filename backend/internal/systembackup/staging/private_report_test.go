package staging

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestPrivateReportCustodyCreateReplayRefusesConflict(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native private custody modes and lock profile")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := CustodyPolicy{Installation: "installation_report_test", MaxBytes: 1 << 20}
	name := "report-" + strings.Repeat("a", 64) + ".json"
	body := []byte(`{"scope":"private_same_ready"}`)
	current := func(context.Context) error { return nil }
	first, err := StorePrivateReport(context.Background(), root, policy, name, body, current)
	if err != nil {
		t.Fatal(err)
	}
	original, err := root.Stat(name)
	if err != nil || original.Mode().Perm() != 0400 {
		t.Fatal("private report not durable0400", err)
	}
	again, err := StorePrivateReport(context.Background(), root, policy, name, body, current)
	if err != nil || again != first {
		t.Fatal("exact original replay failed", err)
	}
	after, _ := root.Stat(name)
	if !os.SameFile(original, after) {
		t.Fatal("replay replaced original inode")
	}
	if _, err = StorePrivateReport(context.Background(), root, policy, name, []byte(`{"other":true}`), current); err == nil {
		t.Fatal("conflicting original report overwritten")
	}
	denied := errors.New("current original authority revoked")
	if _, err = StorePrivateReport(context.Background(), root, policy, "report-"+strings.Repeat("b", 64)+".json", body, func(context.Context) error { return denied }); !errors.Is(err, denied) {
		t.Fatal("revoked scope accepted", err)
	}
	if _, err = root.Stat("report-" + strings.Repeat("b", 64) + ".json"); !os.IsNotExist(err) {
		t.Fatal("revoked scope wrote report")
	}
}
func TestPrivateReportCountsUnknownFilesAndRejectsWritableExisting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native private custody modes and lock profile")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := CustodyPolicy{Installation: "installation_report_test", MaxBytes: 1 << 20}
	name := "report-" + strings.Repeat("a", 64) + ".json"
	body := []byte(`{"ok":true}`)
	current := func(context.Context) error { return nil }
	if _, err = StorePrivateReport(context.Background(), root, policy, name, body, current); err != nil {
		t.Fatal(err)
	}
	if root.Chmod(name, 0600) != nil {
		t.Fatal("fixture chmod")
	}
	if _, err = StorePrivateReport(context.Background(), root, policy, name, body, current); err == nil {
		t.Fatal("writable report accepted")
	}
	root.Chmod(name, 0400)
	unknown, err := root.OpenFile("unknown-retained.bin", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		t.Fatal(err)
	}
	if err = unknown.Truncate(1 << 20); err != nil {
		t.Fatal(err)
	}
	unknown.Close()
	if _, err = StorePrivateReport(context.Background(), root, policy, "report-"+strings.Repeat("b", 64)+".json", body, current); !errors.Is(err, ErrCapacity) {
		t.Fatal("unknown files ignored by capacity", err)
	}
	if _, err = root.Stat("unknown-retained.bin"); err != nil {
		t.Fatal("unknown file removed", err)
	}
}

func TestPrivateReportRejectsNonPrivateCustodyRoot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native private custody modes and lock profile")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	name := "report-" + strings.Repeat("c", 64) + ".json"
	policy := CustodyPolicy{Installation: "installation_report_test", MaxBytes: 1 << 20}
	_, err = StorePrivateReport(context.Background(), root, policy, name, []byte(`{"scope":"private_same_ready"}`), func(context.Context) error { return nil })
	if !errors.Is(err, ErrFile) {
		t.Fatal("non-private custody root accepted", err)
	}
	if _, err = root.Stat(name); !os.IsNotExist(err) {
		t.Fatal("non-private root wrote report", err)
	}
	if _, err = root.Stat(".custody-policy.json"); !os.IsNotExist(err) {
		t.Fatal("non-private root installed custody policy", err)
	}
}
