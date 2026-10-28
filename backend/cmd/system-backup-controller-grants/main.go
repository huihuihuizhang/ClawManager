// Command system-backup-controller-grants prints reviewable MySQL grants for
// the current D-only controller. It never connects to a database.
package main

import (
	"flag"
	"fmt"
	"os"

	"clawreef/internal/systembackupcontroller"
)

func main() {
	schema := flag.String("schema", "", "target MySQL schema")
	user := flag.String("user", "", "pre-created dedicated controller database user")
	host := flag.String("host", "", "MySQL account host")
	allowAnyHost := flag.Bool("allow-any-host", false, "explicitly acknowledge host %")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	statements, err := systembackupcontroller.ControllerGrantSQL(*schema, *user, *host, *allowAnyHost)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println("-- Review before applying. Create the user and Secret separately; no password is included.")
	for _, statement := range statements {
		fmt.Println(statement)
	}
}
