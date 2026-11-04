package main

import (
	"flag"
	"testing"
)

func TestFirstAdoptionWriterSelectionAuthoringFlags(t *testing.T) {
	for _, fault := range []string{"none", "partial_custody", "duplicate_participant", "invalid_policy"} {
		t.Run(fault, func(t *testing.T) {
			f := flag.NewFlagSet("selection", flag.ContinueOnError)
			s := registerWriterSelectionFlags(f)
			args := []string{"-source-config-file", "/private/source-config", "-source-config-sha256", "config-pin", "-observer-definition-file", "/private/pki-definition", "-observer-definition-sha256", "definition-pin", "-observer-receipt-file", "/private/pki-receipt", "-observer-receipt-sha256", "receipt-pin", "-selection-output-directory", "/private/selection", "-journal-directory", "/private/original-journal", "-participant-writer", "app-participant=deployment/ns/app"}
			switch fault {
			case "partial_custody":
				args = append(args, "-gateway-original-key-file", "/private/original.key")
			case "duplicate_participant":
				args = append(args, "-participant-writer", "app-participant=deployment/ns/replacement")
			case "invalid_policy":
				args = append(args, "-maintenance-lock-ttl", "30s")
			}
			e := f.Parse(args)
			valid := e == nil && s.valid()
			if valid != (fault == "none") {
				t.Fatal("source choices must be complete without hand authorization JSON", e)
			}
			if valid && s.participants["app-participant"] != "deployment/ns/app" {
				t.Fatal("participant binding was rewritten")
			}
		})
	}
}
