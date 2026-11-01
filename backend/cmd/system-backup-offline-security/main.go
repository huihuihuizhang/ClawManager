// This command only reads explicitly selected LOCAL public JSON inputs.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	offline "clawreef/internal/systembackupoffline"
)

func localRead(path string) ([]byte, error) {
	// Refuse UNC/device paths, URLs, alternate streams and symlink/reparse hops
	// before opening. The operator must use an ordinary local-drive directory.
	if path == "" || strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") || strings.Contains(path, "://") {
		return nil, offline.ErrInput
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, offline.ErrInput
	}
	volume := filepath.VolumeName(abs)
	if len(volume) > 2 || strings.Contains(strings.TrimPrefix(abs, volume), ":") {
		return nil, offline.ErrInput
	}
	for p := abs; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeIrregular != 0 {
			return nil, offline.ErrInput
		}
		parent := filepath.Dir(p)
		if p == parent {
			break
		}
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, offline.ErrInput
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > offline.MaxBytes {
		return nil, offline.ErrInput
	}
	raw, err := io.ReadAll(io.LimitReader(f, offline.MaxBytes+1))
	if err != nil || len(raw) > offline.MaxBytes {
		return nil, offline.ErrInput
	}
	return raw, nil
}

func run(args []string, out io.Writer, now time.Time) int {
	flags := flag.NewFlagSet("system-backup-offline-security", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	template := flags.String("template", "", "trust or bundle; prints unfilled public template")
	trustFile := flags.String("trust", "", "independently prepared local trust metadata JSON")
	bundleFile := flags.String("bundle", "", "local public material bundle JSON")
	fail := func() int {
		json.NewEncoder(out).Encode(map[string]any{"status": "rejected", "production_ready": false, "reason": "invalid_or_unavailable_local_input"})
		return 1
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return fail()
	}
	if *template != "" {
		if *trustFile != "" || *bundleFile != "" {
			return fail()
		}
		document, err := offline.TemplateDocument(*template)
		if err != nil {
			return fail()
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		if encoder.Encode(document) != nil {
			return 1
		}
		return 0
	}
	if *trustFile == *bundleFile {
		return fail()
	}
	tr, err := localRead(*trustFile)
	if err != nil {
		return fail()
	}
	br, err := localRead(*bundleFile)
	if err != nil {
		return fail()
	}
	var t offline.Trust
	var b offline.Bundle
	if offline.Decode(tr, &t) != nil || offline.Decode(br, &b) != nil {
		return fail()
	}
	report, err := offline.Review(t, b, now)
	if err != nil {
		return fail()
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if encoder.Encode(report) != nil {
		return 1
	}
	switch report.Status {
	case "rejected":
		return 1
	case "incomplete":
		return 2
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, time.Now().UTC())) }
