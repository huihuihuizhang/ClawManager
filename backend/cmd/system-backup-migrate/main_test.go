package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
)

// Exercise the real flag parser and main's public error boundary in a fresh
// process. No DSN is supplied and no database is required by these cases.
func TestMigrationCLIProcess(t *testing.T) {
	if os.Getenv("CLAWREEF_MIGRATION_CLI_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(99)
}

func TestMigrationCLIConnectionLossPublicError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// A real driver EOF used to bypass main's standard-log suppression.
			conn.Close()
		}
	}()
	defer func() { listener.Close(); <-done }()
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	dsn := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(dsn, []byte("private-user:private-password@tcp("+listener.Addr().String()+")/clawmanager"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrationCLIProcess$", "--", "--apply", "--dsn-file", dsn, "--expected-server-uuid", "11111111-1111-1111-1111-111111111111", "--expected-database", "clawmanager", "--expected-catalog-sha256", catalog.Hash)
	cmd.Env = append(os.Environ(), "CLAWREEF_MIGRATION_CLI_TEST=1")
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || strings.TrimSpace(string(out)) != "migration rejected or failed; partial DDL may exist; retain the same target/catalog for recovery" {
		t.Fatalf("connection loss escaped public error boundary: exit=%v output=%q", err, out)
	}
}

func invokeCLI(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestMigrationCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "CLAWREEF_MIGRATION_CLI_TEST=1")
	return cmd.CombinedOutput()
}

func TestMigrationCLICatalogAndHelp(t *testing.T) {
	out, err := invokeCLI(t, "--catalog-only")
	if err != nil {
		t.Fatalf("catalog: %v: %s", err, out)
	}
	var got struct {
		SHA   string   `json:"sha256"`
		Count int      `json:"file_count"`
		Files []string `json:"filenames"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	want, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if got.SHA != want.Hash || got.Count != len(want.Filenames) || strings.Join(got.Files, "\n") != strings.Join(want.Filenames, "\n") {
		t.Fatal("CLI catalog differs from embedded catalog")
	}
	out, err = invokeCLI(t, "--help")
	if err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, name := range []string{"history-review-file", "expected-history-review-sha256", "historical-sql-dir"} {
		if !strings.Contains(string(out), "-"+name) {
			t.Fatalf("missing CLI flag %s", name)
		}
	}
}

func TestMigrationCLIRejectsBeforeDatabase(t *testing.T) {
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	pins := []string{"--apply", "--expected-server-uuid", "11111111-1111-1111-1111-111111111111", "--expected-database", "clawmanager", "--expected-catalog-sha256", catalog.Hash}
	cases := map[string][]string{
		"no mode":             {},
		"both modes":          {"--apply", "--catalog-only"},
		"positional":          {"--catalog-only", "unexpected"},
		"missing pins":        {"--apply"},
		"missing credentials": pins,
	}
	for _, flag := range []string{"dsn-file", "expected-server-uuid", "expected-database", "expected-catalog-sha256", "history-review-file", "expected-history-review-sha256", "historical-sql-dir"} {
		cases["catalog rejects "+flag] = []string{"--catalog-only", "--" + flag, "private-input-marker"}
	}
	for _, flag := range []string{"history-review-file", "expected-history-review-sha256", "historical-sql-dir"} {
		cases["incomplete history "+flag] = append(append([]string{}, pins...), "--"+flag, "private-input-marker")
	}
	cases["unavailable history"] = append(append([]string{}, pins...), "--history-review-file", "private-input-marker", "--expected-history-review-sha256", strings.Repeat("a", 64), "--historical-sql-dir", t.TempDir())
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := invokeCLI(t, args...)
			if err == nil {
				t.Fatalf("unexpected success: %s", out)
			}
			want := "migration rejected or failed; partial DDL may exist; retain the same target/catalog for recovery"
			if strings.TrimSpace(string(out)) != want {
				t.Fatalf("unexpected public error: %q", out)
			}
		})
	}
}
