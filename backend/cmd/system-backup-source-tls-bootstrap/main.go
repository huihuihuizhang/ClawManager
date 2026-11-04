package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	bootstrap "clawreef/internal/systembackupsourcetlsbootstrap"
	"github.com/go-sql-driver/mysql"
)

// The same reviewed Linux ELF is used by the operator and by the original
// MySQL container's bounded helper. Helper output contains no private key or
// password; existing CA signing keys never leave that original container.
func run(ctx context.Context, args []string, in io.Reader, out io.Writer) int {
	if len(args) > 0 && args[0] == "mysql-helper" {
		if len(args) != 1 {
			return 2
		}
		raw, e := io.ReadAll(io.LimitReader(in, 16385))
		if e != nil || len(raw) > 16384 {
			return 1
		}
		defer clear(raw)
		var request bootstrap.MySQLHelperRequest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
			return 1
		}
		defer clear(request.AdminPassword)
		// Remove only the exact operation-owned uploaded helper, never data,
		// rollback custody, shared tool directories or a computed parent tree.
		if executable, e := os.Executable(); e == nil {
			dir := filepath.Dir(executable)
			base := filepath.Base(dir)
			suffix := strings.TrimPrefix(base, ".clawreef-source-tls-helper-")
			valid := len(suffix) == 32
			for _, r := range suffix {
				valid = valid && (r >= 'a' && r <= 'f' || r >= '0' && r <= '9')
			}
			if valid && filepath.Dir(dir) == "/tmp" && filepath.Base(executable) == "bootstrap" {
				defer os.Remove(dir)
				defer os.Remove(executable)
			}
		}
		result, e := bootstrap.RunMySQLHelper(ctx, request)
		if e != nil {
			return 1
		}
		if json.NewEncoder(out).Encode(result) != nil {
			return 3
		}
		return 0
	}
	f := flag.NewFlagSet("system-backup-source-tls-bootstrap", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "", "inspect, bootstrap, apply or rollback")
	kubeFile := f.String("kubeconfig-file", "", "")
	kubeSHA := f.String("kubeconfig-sha256", "", "")
	namespace := f.String("namespace", "", "")
	admin := f.String("local-admin-username", "", "")
	password := f.String("local-admin-password-file", "", "")
	helper := f.String("helper-file", "", "selected same-version Linux amd64 ELF")
	helperSHA := f.String("helper-sha256", "", "")
	directory := f.String("output-directory", "", "existing private directory")
	plan := f.String("plan-file", "", "")
	planSHA := f.String("plan-sha256", "", "")
	operation := f.String("operation", "", "")
	if ctx == nil || f.Parse(args) != nil || f.NArg() != 0 {
		return 2
	}
	for _, v := range []*string{kubeFile, kubeSHA, namespace, password, helper, helperSHA, directory} {
		if *v == "" {
			return 2
		}
	}
	if *mode != "inspect" && *mode != "bootstrap" && *mode != "apply" && *mode != "rollback" {
		return 2
	}
	if *mode == "inspect" || *mode == "bootstrap" {
		if *plan != "" || *planSHA != "" || *operation != "" {
			return 2
		}
	} else if *admin == "" || *plan == "" || *planSHA == "" || *operation == "" {
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client, e := bootstrap.NewClient(bounded, bootstrap.ClientOptions{KubeconfigFile: *kubeFile, KubeconfigSHA256: *kubeSHA, Namespace: *namespace, AdminUsername: *admin, PasswordFile: *password, HelperFile: *helper, HelperSHA256: *helperSHA, OutputDirectory: *directory})
	if e != nil {
		return 1
	}
	defer client.Close()
	var receipt bootstrap.BootstrapReceipt
	if *mode == "inspect" || *mode == "bootstrap" {
		receipt, e = client.Inspect(bounded)
		if e == nil && *mode == "bootstrap" {
			receipt, e = client.Apply(bounded, receipt.PlanFile, receipt.PlanSHA256, receipt.Operation, false)
		}
	} else {
		receipt, e = client.Apply(bounded, *plan, *planSHA, *operation, *mode == "rollback")
	}
	if e != nil {
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 3
	}
	return 0
}
func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout)
	if code != 0 {
		_, _ = io.WriteString(os.Stderr, "source TLS bootstrap not confirmed; retain operation plan and original TLS rollback custody\n")
	}
	os.Exit(code)
}
