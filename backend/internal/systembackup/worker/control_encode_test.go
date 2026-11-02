package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Independent legacy encoding path: keep the original Hash-based validation
// branch and full request marshal as the byte/error differential oracle.
func legacyEncodeControlRequest(r ControlRequest) ([]byte, error) {
	if !validControl(r) {
		return nil, ErrRequest
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, ErrRequest
	}
	return raw, nil
}

func TestControlWireProjectionCoversEveryRequestField(t *testing.T) {
	original, wire := reflect.TypeOf(ControlRequest{}), reflect.TypeOf(controlRequestWire{})
	if original.NumField() != wire.NumField() {
		t.Fatal("ControlRequest fields changed without updating wire projection")
	}
	for i := 0; i < original.NumField(); i++ {
		a, b := original.Field(i), wire.Field(i)
		if a.Name != b.Name || a.Tag != b.Tag || a.Anonymous != b.Anonymous ||
			(i != 0 && a.Type != b.Type) || (i == 0 && b.Type != reflect.TypeOf(json.RawMessage{})) {
			t.Fatal("wire projection changed field order, coverage, type, or omitempty", a.Name)
		}
	}
}

func TestControlWireExactLegacyBytesWithEscapesAndOptionalFields(t *testing.T) {
	inv := keyInvocation(t)
	inv.FormalCapture = &FormalCaptureSpec{}
	// Populate every current nested optional Request pointer. These are wire
	// encoding fixtures, not admitted capture requests or authority evidence.
	value := reflect.ValueOf(&inv.Request).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Pointer {
			field.Set(reflect.New(field.Type().Elem()))
		}
	}
	for _, text := range []string{"", "plain", "<script>&\"中文\\\n\u2028\u2029", "invalid-utf8-\xff"} {
		inv.WorkspacePath, inv.StagingPath, inv.EvidencePath = text, text, text
		inv.Request.ArtifactName = text
		for flags := 0; flags < 8; flags++ {
			r := ControlRequest{Invocation: inv, InvocationSHA256: text, Action: text}
			if flags&1 != 0 {
				r.Point = text + "point"
			}
			if flags&2 != 0 {
				r.Result = &Result{Rows: 5, Tables: 2}
			}
			if flags&4 != 0 {
				r.Candidate = &FormalCaptureResult{Version: text, Rows: 9, Tables: 3}
			}
			invocationJSON, err := json.Marshal(r.Invocation)
			if err != nil {
				t.Fatal(err)
			}
			got, err := marshalControlRequestWire(r, invocationJSON)
			want, legacyErr := json.Marshal(r)
			if err != nil || legacyErr != nil || !bytes.Equal(got, want) {
				t.Fatal("wire bytes differ from full legacy marshal", flags, err, legacyErr)
			}
		}
	}
}

func TestControlEncodeValidationAndErrorsMatchLegacy(t *testing.T) {
	for _, scenario := range []string{"ready", "key-reserve", "key-check", "key-begin", "key-end", "wrong-hash", "expired", "bad-operation", "bad-action", "missing-nonce", "invalid-time", "changed-nested-field"} {
		t.Run(scenario, func(t *testing.T) {
			inv := keyInvocation(t)
			r := ControlRequest{Invocation: inv, Action: "key-check", Point: strings.Repeat("a", 32)}
			r.InvocationSHA256, _ = inv.Hash()
			switch scenario {
			case "ready":
				r.Action, r.Point = "ready", ""
			case "key-reserve", "key-check", "key-begin", "key-end":
				r.Action = scenario
			case "wrong-hash":
				r.InvocationSHA256 = strings.Repeat("0", 64)
			case "expired":
				r.Invocation.Request.Deadline = time.Now().Add(-time.Hour)
				r.InvocationSHA256, _ = r.Invocation.Hash()
			case "bad-operation":
				r.Invocation.Request.Operation = "unknown"
			case "bad-action":
				r.Action = "unknown"
			case "missing-nonce":
				r.Point = ""
			case "invalid-time":
				r.Invocation.Request.Deadline = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "changed-nested-field":
				r.Invocation.ProviderKey.Request.Context.Part = "changed"
			}
			want, legacyErr := legacyEncodeControlRequest(r)
			got, err := encodeControlRequest(r)
			if !errors.Is(err, legacyErr) || !bytes.Equal(got, want) {
				t.Fatal("encoding changed legacy bytes or error class", err, legacyErr)
			}
			valid := scenario == "ready" || strings.HasPrefix(scenario, "key-")
			if valid && err != nil || !valid && !errors.Is(err, ErrRequest) {
				t.Fatal("fixture did not exercise intended validation outcome", err)
			}
		})
	}
}

type controlEncodeTransport func(*http.Request) (*http.Response, error)

func (f controlEncodeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestControlEncodeSendPreservesFaultOrderAndHTTPCount(t *testing.T) {
	inv := keyInvocation(t)
	hash, _ := inv.Hash()
	base := ControlRequest{Invocation: inv, InvocationSHA256: hash, Action: "key-check", Point: strings.Repeat("a", 32)}
	for _, scenario := range []string{"wrong-hash-before-token", "expired-before-token", "nil-context-before-token", "missing-token", "temporary-response", "denied-response", "invalid-lease"} {
		t.Run(scenario, func(t *testing.T) {
			r := base
			ctx := context.Background()
			status, expectedCalls, wantErr := http.StatusForbidden, 0, ErrRequest
			calls := 0
			client := &ControlClient{endpoint: "https://control.invalid", tokenFile: filepath.Join(t.TempDir(), "missing-token")}
			client.http = &http.Client{Transport: controlEncodeTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(request.Body)
				want, legacyErr := legacyEncodeControlRequest(r)
				if err != nil || legacyErr != nil || !bytes.Equal(body, want) {
					t.Fatal("actual HTTP body differs from legacy", err, legacyErr)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}, nil
			})}
			switch scenario {
			case "wrong-hash-before-token":
				r.InvocationSHA256 = "wrong"
			case "expired-before-token":
				r.Invocation.Request.Deadline = time.Now().Add(-time.Hour)
				r.InvocationSHA256, _ = r.Invocation.Hash()
			case "nil-context-before-token":
				ctx = nil
			case "missing-token":
				wantErr = ErrNotReady
			case "temporary-response", "denied-response", "invalid-lease":
				client.tokenFile = ""
				expectedCalls, wantErr = 1, ErrExecution
				if scenario == "temporary-response" {
					status, wantErr = http.StatusServiceUnavailable, ErrNotReady
				} else if scenario == "invalid-lease" {
					status = http.StatusOK
				}
			}
			lease, err := client.send(ctx, r)
			lease.Clear()
			if !errors.Is(err, wantErr) || calls != expectedCalls {
				t.Fatal("send reordered validation/token/HTTP or changed error class", err, calls)
			}
		})
	}
	var missing *ControlClient
	base.InvocationSHA256 = "wrong"
	if _, err := missing.send(context.Background(), base); !errors.Is(err, ErrNotReady) {
		t.Fatal("missing client no longer precedes request validation", err)
	}
}

func TestControlEncodeRebuildsBodyAndReadsTokenOnEverySend(t *testing.T) {
	inv := keyInvocation(t)
	r := ControlRequest{Invocation: inv, Action: "key-check", Point: strings.Repeat("a", 32)}
	r.InvocationSHA256, _ = inv.Hash()
	tokenFile := filepath.Join(t.TempDir(), "token")
	var bodies [][]byte
	var tokens []string
	client := &ControlClient{endpoint: "https://control.invalid", tokenFile: tokenFile}
	client.http = &http.Client{Transport: controlEncodeTransport(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		want, legacyErr := legacyEncodeControlRequest(r)
		if err != nil || legacyErr != nil || !bytes.Equal(body, want) {
			t.Fatal("fresh send body differs from current invocation", err, legacyErr)
		}
		bodies = append(bodies, body)
		tokens = append(tokens, request.Header.Get("Authorization"))
		return &http.Response{StatusCode: http.StatusForbidden, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: request}, nil
	})}
	for _, token := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		r.Invocation.WorkspacePath += "/changed"
		r.InvocationSHA256, _ = r.Invocation.Hash()
		if _, err := client.send(context.Background(), r); !errors.Is(err, ErrExecution) {
			t.Fatal(err)
		}
	}
	if len(bodies) != 2 || bytes.Equal(bodies[0], bodies[1]) || tokens[0] == tokens[1] {
		t.Fatal("send reused prior invocation bytes or bearer token")
	}
	if err := os.WriteFile(tokenFile, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.send(context.Background(), r); !errors.Is(err, ErrNotReady) || len(bodies) != 2 {
		t.Fatal("changed invalid token reused a previous successful read", err)
	}
}
