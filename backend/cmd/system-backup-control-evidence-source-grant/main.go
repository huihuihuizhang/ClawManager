package main

import (
	"context"
	"io"
	"log"
	"os"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

func main() {
	log.SetOutput(io.Discard)
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
	os.Exit(install.RunOriginalControlEvidenceSourceGrant(context.Background(), os.Args[1:], os.Stdout))
}
