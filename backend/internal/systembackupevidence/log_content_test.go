package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func logTestPolicy() JobLogPolicy {
	return JobLogPolicy{Events: map[string]map[string]LogFieldPolicy{
		"progress": {
			"stage":   {Kind: "enum", Required: true, Values: []string{"capture", "verify"}},
			"count":   {Kind: "uint", Required: true, Max: ^uint64(0)},
			"ok":      {Kind: "bool", Required: true},
			"private": {Kind: "drop"},
		},
	}}
}

const logGood = `{"schema_version":"system-backup-job-log.v1","level":"info","code":"progress","fields":{"stage":"capture","count":18446744073709551615,"ok":true}}`

func TestLogSanitizerClosedFields(t *testing.T) {
	bad := []string{
		`https://user:private@host/path?token=private`,
		strings.Replace(logGood, `"stage":"capture"`, `"stage":"https://user:private@host"`, 1),
		strings.Replace(logGood, `"ok":true`, `"ok":null`, 1),
		strings.Replace(logGood, `"ok":true`, `"ok":"private"`, 1),
		strings.Replace(logGood, `"ok":true`, `"ok":true,"password":"private"`, 1),
		strings.Replace(logGood, `"ok":true`, `"ok":true,"ok":false`, 1),
		strings.Replace(logGood, `"ok":true`, `"ok":true,"\u006fk":false`, 1),
		strings.Replace(logGood, `"ok":true`, `"OK":true`, 1),
		strings.Replace(logGood, `"ok":true`, `"ok":{"nested":"private"}`, 1),
		strings.Replace(logGood, `"code":"progress"`, `"code":"unknown"`, 1),
		strings.Replace(logGood, `"level":"info"`, `"level":"private"`, 1),
		strings.Replace(logGood, `"schema_version"`, `"Schema_version"`, 1),
		strings.Replace(logGood, `,"ok":true`, ``, 1),
		strings.Replace(logGood, `18446744073709551615`, `18446744073709551616`, 1),
		strings.Replace(logGood, `18446744073709551615`, `-1`, 1),
		strings.Replace(logGood, `18446744073709551615`, `1.5`, 1),
		strings.Replace(logGood, `18446744073709551615`, `1e2`, 1),
		logGood + `{}`, string([]byte{0xff}), strings.Repeat("x", MaxLogLineBytes+1), "",
	}
	for n, line := range bad {
		t.Run(string(rune('A'+n)), func(t *testing.T) {
			s, err := NewLogSanitizer(logTestPolicy(), 4*MaxLogChunkBytes, 2000)
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Sanitize(context.Background(), strings.NewReader(logGood+"\n"+line+"\n"+logGood))
			if err != nil || result.Lines != 2 || result.InputLines != 3 || len(result.Diagnostics) != 1 || result.Diagnostics[0] != (LogDiagnostic{"redaction_failed", 2}) {
				t.Fatalf("unsafe line handling: %+v %v", result.Diagnostics, err)
			}
			if bytes.Contains(result.Content, []byte("private")) {
				t.Fatal("raw secret escaped")
			}
		})
	}
	// Explicitly classified nested content is removed, not echoed or hashed in diagnostics.
	raw := strings.Replace(logGood, `"ok":true`, `"ok":true,"private":{"url":"https://user:private@host/?token=private"}`, 1)
	p := logTestPolicy()
	s, _ := NewLogSanitizer(p, 10000, 20)
	p.Events["progress"]["stage"].Values[0] = "changed"
	delete(p.Events["progress"], "private")
	result, err := s.Sanitize(context.Background(), strings.NewReader(raw+"\r\n"))
	if err != nil || result.Lines != 1 || len(result.Diagnostics) != 0 || bytes.Contains(result.Content, []byte("private")) || !bytes.Contains(result.Content, []byte("18446744073709551615")) {
		t.Fatal("policy snapshot or exact integer failed", err)
	}
}

type logErrorReader struct{}

func (logErrorReader) Read([]byte) (int, error) { return 0, errors.New("private reader token") }

type logPanicReader struct{}

func (logPanicReader) Read([]byte) (int, error) { panic("exhausted ingest must not read") }

func TestLogBudgetsAndFailures(t *testing.T) {
	p := logTestPolicy()
	s, _ := NewLogSanitizer(p, 10000, 2)
	first, err := s.Sanitize(context.Background(), strings.NewReader("private\n"+logGood+"\n"+logGood))
	if err != nil || first.Lines != 1 || first.InputLines != 2 || !first.Truncated || len(first.Diagnostics) != 2 {
		t.Fatal("dropped lines must consume task budget", err)
	}
	next, err := s.Sanitize(context.Background(), logPanicReader{})
	if err != nil || !next.Truncated || len(next.Content) != 0 || len(next.Diagnostics) != 0 {
		t.Fatal("must stop and not repeat diagnostic")
	}
	s, _ = NewLogSanitizer(p, int64(len(logGood)), 10)
	r, err := s.Sanitize(context.Background(), strings.NewReader(logGood))
	if err != nil || !r.Truncated || len(r.Content) != 0 {
		t.Fatal("newline must count toward bytes")
	}
	s, _ = NewLogSanitizer(p, 10000, 2)
	r, err = s.Sanitize(context.Background(), strings.NewReader(logGood+"\n"))
	if err != nil || r.Truncated {
		t.Fatal("premature stop")
	}
	r, err = s.Sanitize(context.Background(), strings.NewReader(logGood))
	if err != nil || !r.Truncated || r.Lines != 1 {
		t.Fatal("cross-chunk line budget")
	}
	for _, src := range []io.Reader{logErrorReader{}, strings.NewReader(strings.Repeat("x", MaxLogChunkBytes+1)), strings.NewReader(strings.Repeat("\n", MaxLogChunkLines+1))} {
		s, _ = NewLogSanitizer(p, 10000, 20)
		r, err = s.Sanitize(context.Background(), src)
		if err == nil || len(r.Content) != 0 || strings.Contains(err.Error(), "private") || s.linesLeft != 20 || s.bytesLeft != 10000 {
			t.Fatal("failed chunk escaped or consumed state", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, err = s.Sanitize(ctx, logPanicReader{}); err != ErrRedaction || len(r.Content) != 0 {
		t.Fatal("cancellation")
	}
	s, _ = NewLogSanitizer(p, 0, 10)
	if r, err = s.Sanitize(context.Background(), logPanicReader{}); err != nil || !r.Truncated {
		t.Fatal("zero budget")
	}
}

func TestLogPolicyRejectsUnsafeConfiguration(t *testing.T) {
	for _, field := range []LogFieldPolicy{
		{Kind: "string"}, {Kind: "enum"}, {Kind: "enum", Values: []string{"https://secret"}},
		{Kind: "enum", Values: []string{"ok", "ok"}}, {Kind: "bool", Max: 1}, {Kind: "drop", Values: []string{"ok"}},
	} {
		p := logTestPolicy()
		p.Events["progress"]["bad"] = field
		if _, err := NewJobLogRedactor(p); err != ErrRedaction {
			t.Fatal("unsafe schema accepted")
		}
	}
	for _, p := range []JobLogPolicy{{}, {Events: map[string]map[string]LogFieldPolicy{"private token": {}}}, {Events: map[string]map[string]LogFieldPolicy{"progress": {"bad-name": {Kind: "bool"}}}}} {
		if _, err := NewLogSanitizer(p, 1, 1); err != ErrRedaction {
			t.Fatal("unsafe policy accepted")
		}
	}
}

func sanitizedLogFixture(t *testing.T) (JobLogPolicy, Identity, []byte) {
	t.Helper()
	p := logTestPolicy()
	s, _ := NewLogSanitizer(p, 1<<20, 1000)
	r, err := s.Sanitize(context.Background(), strings.NewReader(strings.Repeat(logGood+"\n", 70)))
	if err != nil || len(r.Content) <= 8192 {
		t.Fatal("fixture", err)
	}
	i := Identity{Installation: "installation_test", ID: "sev_11111111-2222-4333-8444-555555555555", OwnerType: "backup", OwnerID: "sbk_11111111-2222-4333-8444-555555555555", Type: "job_log_chunk", Media: "text/plain", Classification: "internal", ContentHash: hash(r.Content), ContentSize: int64(len(r.Content))}
	return p, i, r.Content
}

type contentAuthorityFunc func(context.Context, Identity) (ContentAuthorization, error)

func (f contentAuthorityFunc) AuthorizeContent(ctx context.Context, i Identity) (ContentAuthorization, error) {
	return f(ctx, i)
}

func TestLogDispatchEnvelope(t *testing.T) {
	p, i, raw := sanitizedLogFixture(t)
	calls := 0
	d, err := NewContentDispatcher(contentAuthorityFunc(func(_ context.Context, got Identity) (ContentAuthorization, error) {
		calls++
		return ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("a", 64), ValidUntil: time.Now().Add(time.Minute), JobLog: &p}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	keys := testKeys{key: bytes.Repeat([]byte{7}, 32)}
	var dst bytes.Buffer
	prepared, err := Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, source(raw), d, keys, &dst)
	if err != nil || calls != 2 {
		t.Fatal("prepare", calls, err)
	}
	ref := Ref{strings.Repeat("a", 64), "v1", "evidence/log", "v1"}
	store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{"v1", hash(dst.Bytes()), int64(dst.Len())}}
	got, err := OpenRange(context.Background(), prepared.Manifest(), ref, store, keys, 0, i.ContentSize-1)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("log roundtrip", err)
	}
}

func TestContentDispatchRejectsBeforeKeys(t *testing.T) {
	p, base, raw := sanitizedLogFixture(t)
	for _, scenario := range []string{"unknown", "wrong_owner", "wrong_media", "identity", "producer", "expired", "denied", "revoked", "changed_policy", "changed_producer", "both_profiles", "missing_profile", "raw_secret", "noncanonical", "lines", "checksum", "size", "reader"} {
		t.Run(scenario, func(t *testing.T) {
			i := base
			data := append([]byte(nil), raw...)
			policy, _ := freezeLogPolicy(p)
			switch scenario {
			case "unknown":
				i.Type = "verifier_report"
			case "wrong_owner":
				i.OwnerType = "system"
				i.OwnerID = i.Installation
			case "wrong_media":
				i.Media = "application/json"
			case "raw_secret":
				data = []byte(strings.Repeat(strings.Replace(logGood, `"ok":true`, `"ok":true,"private":"private token"`, 1)+"\n", 70))
			case "noncanonical":
				data = []byte(strings.Repeat(logGood+"\n", 70))
			case "lines":
				data = bytes.Repeat(bytes.SplitN(raw, []byte{'\n'}, 2)[0], 1)
				data = bytes.Repeat(append(data, '\n'), 1001)
			}
			i.ContentHash = hash(data)
			i.ContentSize = int64(len(data))
			if scenario == "checksum" {
				i.ContentHash = strings.Repeat("0", 64)
			}
			if scenario == "size" {
				i.ContentSize++
			}
			calls := 0
			d, _ := NewContentDispatcher(contentAuthorityFunc(func(_ context.Context, _ Identity) (ContentAuthorization, error) {
				calls++
				a := ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("a", 64), ValidUntil: time.Now().Add(time.Minute), JobLog: &policy}
				switch scenario {
				case "identity":
					a.Identity.Installation = "installation_other"
				case "producer":
					a.ProducerIdentityHash = ""
				case "expired":
					a.ValidUntil = time.Now().Add(-time.Second)
				case "denied":
					return a, errors.New("private credential")
				case "revoked":
					if calls == 2 {
						return a, errors.New("private revoked")
					}
				case "changed_policy":
					if calls == 2 {
						policy.Events["progress"]["count"] = LogFieldPolicy{Kind: "uint", Required: true, Max: ^uint64(0) - 1}
					}
				case "changed_producer":
					if calls == 2 {
						a.ProducerIdentityHash = strings.Repeat("b", 64)
					}
				case "both_profiles":
					a.Capability = &CapabilityContentPolicy{}
				case "missing_profile":
					a.JobLog = nil
				}
				return a, nil
			}))
			keys := &countingContentKeys{}
			var dst bytes.Buffer
			src := source(data)
			if scenario == "reader" {
				src = func() (io.ReadCloser, error) { return io.NopCloser(logErrorReader{}), nil }
			}
			_, err := Prepare(context.Background(), i, KeyRef{strings.Repeat("b", 64), "v1"}, src, d, keys, &dst)
			if err == nil || keys.calls != 0 || dst.Len() != 0 || strings.Contains(err.Error(), "private") {
				t.Fatal("rejection was late or leaked", err)
			}
		})
	}
}

func TestContentDispatchCapability(t *testing.T) {
	v, i, raw := capabilityFixture(t)
	d, _ := NewContentDispatcher(contentAuthorityFunc(func(context.Context, Identity) (ContentAuthorization, error) {
		return ContentAuthorization{Identity: i, ProducerIdentityHash: strings.Repeat("a", 64), ValidUntil: time.Now().Add(time.Minute), Capability: &v.policy}, nil
	}))
	if err := d.Validate(context.Background(), i, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := NewContentDispatcher(nil); err != ErrRedaction {
		t.Fatal("nil authority accepted")
	}
	// Diagnostics serialize only ordinal/code, never a source error, body, or hash.
	s, _ := NewLogSanitizer(logTestPolicy(), 1000, 10)
	r, _ := s.Sanitize(context.Background(), strings.NewReader("private password"))
	b, _ := json.Marshal(r.Diagnostics)
	if bytes.Contains(b, []byte("private")) || bytes.Contains(b, []byte(hash([]byte("private password")))) {
		t.Fatal("diagnostic leaked")
	}
}
