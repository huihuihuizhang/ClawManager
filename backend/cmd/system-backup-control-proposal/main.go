// system-backup-control-proposal produces an OFFLINE DRAFT from an independent
// observer's finite control-table metadata. It does not query source SQL, issue
// grants, sign approvals, freeze the repository registry or enable capture.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	appdb "clawreef/internal/db"
	root "clawreef/internal/systembackup"
)

func main() {
	observed := flag.String("observed", "", "independent JSON array of original control SQLTable metadata")
	server := flag.String("server-uuid", "", "original independently observed MySQL server UUID")
	database := flag.String("database", "", "original source schema")
	out := flag.String("out", "", "new draft file; an existing file is never overwritten")
	flag.Parse()
	if err := run(*observed, *server, *database, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(observed, server, database, out string) error {
	if observed == "" || out == "" {
		return fmt.Errorf("observed and out are required")
	}
	file, err := os.Open(observed)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	file.Close()
	if err != nil || len(raw) > 8<<20 {
		return fmt.Errorf("invalid bounded schema observation")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var tables []root.SQLTable
	if decoder.Decode(&tables) != nil || decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("invalid original SQLTable observation JSON")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		return err
	}
	proposal, err := root.NewControlScopeProposal(server, database, catalog.Hash, tables)
	if err != nil {
		return err
	}
	draft, err := json.MarshalIndent(proposal, "", "  ")
	if err != nil {
		return err
	}
	destination, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := destination.Write(append(draft, '\n'))
	closeErr := destination.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Println(out)
	return nil
}
