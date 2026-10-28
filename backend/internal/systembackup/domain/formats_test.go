package domain

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

func TestConfigFormatsPreserveDefinitionsAndStubCredentials(t *testing.T) {
	rules := []JSONRule{{Path: []string{"model"}, Action: "preserve", Required: true}, {Path: []string{"token"}, Action: "stub", Required: true}, {Path: []string{"enabled"}, Action: "disable", Required: true}, {Path: []string{"large"}, Action: "preserve", Required: true}}
	inputs := map[string]string{"json": `{"model":"example","token":"fixture-private","enabled":true,"large":9007199254740993}`, "yaml": "model: example\ntoken: fixture-private\nenabled: true\nlarge: 9007199254740993\n", "toml": "model = \"example\"\ntoken = \"fixture-private\"\nenabled = true\nlarge = 9007199254740993\n"}
	for format, raw := range inputs {
		t.Run(format, func(t *testing.T) {
			normalized, e := NormalizeDocument(context.Background(), format, []byte(raw), rules)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(normalized.Bytes), "fixture-private") || !strings.Contains(string(normalized.Bytes), "9007199254740993") {
				t.Fatal("secret retained or integer precision lost")
			}
			var out struct {
				Model, Token string
				Enabled      bool
				Large        int64
			}
			switch format {
			case "json":
				e = json.Unmarshal(normalized.Bytes, &out)
			case "yaml":
				e = yaml.Unmarshal(normalized.Bytes, &out)
			case "toml":
				e = toml.Unmarshal(normalized.Bytes, &out)
			}
			if e != nil || out.Model != "example" || out.Enabled || !strings.HasPrefix(out.Token, "drill-disabled-") || out.Large != 9007199254740993 {
				t.Fatal(string(normalized.Bytes), e)
			}
		})
	}
}
func TestDotenvExplicitDisableRules(t *testing.T) {
	rules := []JSONRule{{Path: []string{"MODEL"}, Action: "preserve"}, {Path: []string{"TOKEN"}, Action: "stub"}, {Path: []string{"SCHEDULER_ENABLED"}, Action: "disable-string"}}
	normalized, e := NormalizeDocument(context.Background(), "dotenv", []byte("export MODEL='example'\nTOKEN=fixture-private\nSCHEDULER_ENABLED=1\n"), rules)
	if e != nil {
		t.Fatal(e)
	}
	doc, e := parseDotenv(normalized.Bytes)
	if e != nil || doc["SCHEDULER_ENABLED"] != "0" || doc["MODEL"] != "example" || strings.Contains(string(normalized.Bytes), "fixture-private") {
		t.Fatal(string(normalized.Bytes), e)
	}
}
func TestFormatsRejectAmbiguousAndUnregisteredContent(t *testing.T) {
	cases := []struct{ format, input string }{{"yaml", "a: 1\na: 2"}, {"yaml", "a: &a token\nb: *a"}, {"yaml", "a: 1\n---\na: 2"}, {"yaml", "a: 2026-01-01"}, {"toml", "a = 1\na = 2"}, {"toml", "a = 2026-01-01"}, {"dotenv", "A=1\nA=2"}, {"dotenv", "A=$(touch bad)"}, {"dotenv", "A=${HOME}"}, {"dotenv", "A=foo # unsupported comment"}, {"dotenv", "A=1\nNEW=private"}, {"xml", "<a/>"}}
	rules := []JSONRule{{Path: []string{"a"}, Action: "preserve"}, {Path: []string{"A"}, Action: "preserve"}}
	for _, c := range cases {
		if _, e := NormalizeDocument(context.Background(), c.format, []byte(c.input), rules); e == nil {
			t.Fatal("unsafe document accepted", c.format, c.input)
		}
	}
}
