package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"sync"
	"unicode/utf8"
)

const (
	JobLogSchema     = "system-backup-job-log.v1"
	MaxLogChunkBytes = 1 << 20
	MaxLogChunkLines = 1000
	MaxLogLineBytes  = 64 << 10
)

// JobLogPolicy is a reviewed producer-specific schema, supplied by a trusted
// registry, never by the log. There is deliberately no arbitrary string type.
// Names/enums themselves must be reviewed for disclosure before registration.
type JobLogPolicy struct {
	Events map[string]map[string]LogFieldPolicy
}
type LogFieldPolicy struct {
	Kind     string // enum, bool, uint, or drop
	Required bool
	Values   []string
	Max      uint64
}

var logName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func freezeLogPolicy(p JobLogPolicy) (JobLogPolicy, error) {
	if len(p.Events) == 0 || len(p.Events) > 64 {
		return JobLogPolicy{}, ErrRedaction
	}
	out := JobLogPolicy{Events: make(map[string]map[string]LogFieldPolicy)}
	for code, fields := range p.Events {
		if !logName.MatchString(code) || len(fields) > 32 {
			return JobLogPolicy{}, ErrRedaction
		}
		copyFields := make(map[string]LogFieldPolicy)
		for name, f := range fields {
			if !logName.MatchString(name) || !oneOf(f.Kind, "enum", "bool", "uint", "drop") ||
				f.Kind != "uint" && f.Max != 0 || f.Kind != "enum" && len(f.Values) != 0 {
				return JobLogPolicy{}, ErrRedaction
			}
			if f.Kind == "enum" {
				if len(f.Values) == 0 || len(f.Values) > 64 {
					return JobLogPolicy{}, ErrRedaction
				}
				seen := map[string]bool{}
				for _, v := range f.Values {
					if !logName.MatchString(v) || seen[v] {
						return JobLogPolicy{}, ErrRedaction
					}
					seen[v] = true
				}
			}
			f.Values = append([]string(nil), f.Values...)
			copyFields[name] = f
		}
		out.Events[code] = copyFields
	}
	return out, nil
}

// logLine returns a new canonical line. In validation mode, dropped fields are
// forbidden: sanitization happens BEFORE content length/checksum are assigned.
func logLine(raw []byte, p JobLogPolicy, sanitize bool) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxLogLineBytes || !utf8.Valid(raw) {
		return nil, ErrRedaction
	}
	root, err := capabilityFields(raw, []string{"schema_version", "level", "code", "fields"}, "")
	if err != nil {
		return nil, ErrRedaction
	}
	defer wipeTransitFields(root)
	var schema, level, code string
	if json.Unmarshal(root["schema_version"], &schema) != nil || schema != JobLogSchema ||
		json.Unmarshal(root["level"], &level) != nil || !oneOf(level, "debug", "info", "warn", "error") ||
		json.Unmarshal(root["code"], &code) != nil {
		return nil, ErrRedaction
	}
	rules, ok := p.Events[code]
	if !ok {
		return nil, ErrRedaction
	}
	fields, err := transitObject(root["fields"])
	if err != nil {
		return nil, ErrRedaction
	}
	defer wipeTransitFields(fields)
	clean := make(map[string]any)
	for name, f := range rules {
		if _, exists := fields[name]; f.Required && !exists && (sanitize || f.Kind != "drop") {
			return nil, ErrRedaction
		}
	}
	for name, value := range fields {
		f, ok := rules[name]
		if !ok {
			return nil, ErrRedaction
		}
		switch f.Kind {
		case "drop":
			if !sanitize {
				return nil, ErrRedaction
			}
		case "enum":
			var s string
			if json.Unmarshal(value, &s) != nil || !oneOf(s, f.Values...) {
				return nil, ErrRedaction
			}
			clean[name] = s
		case "bool":
			v := string(bytes.TrimSpace(value))
			if v != "true" && v != "false" {
				return nil, ErrRedaction
			}
			clean[name] = v == "true"
		case "uint":
			v, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 10, 64)
			if err != nil || v > f.Max {
				return nil, ErrRedaction
			}
			clean[name] = v
		}
	}
	// json.Marshal sorts map keys and preserves uint64 exactly (no float conversion).
	line, err := json.Marshal(map[string]any{"schema_version": JobLogSchema, "level": level, "code": code, "fields": clean})
	if err != nil || len(line)+1 > MaxLogLineBytes {
		wipe(line)
		return nil, ErrRedaction
	}
	return append(line, '\n'), nil
}

// LogDiagnostic contains only closed codes and a chunk-local line ordinal.
// The observer must persist these with its authenticated task/Job identity.
type LogDiagnostic struct {
	Code string
	Line int
}
type LogChunk struct {
	Content                []byte
	Diagnostics            []LogDiagnostic
	InputBytes, InputLines int64
	ChargedBytes           int64 // sum of max(raw line bytes, canonical line bytes)
	Lines                  int
	Truncated              bool
}

// LogSanitizer consumes complete observer chunks (<=1 MiB, <=1000 lines).
// The last line may end at EOF. The observer must not split a line between calls.
// Budgets conservatively count ALL raw input, including discarded lines, as well
// as output. D/B must restore counters from trusted task state on restart; this
// in-memory object is not a durable limit or producer authenticator.
type LogSanitizer struct {
	mu                   sync.Mutex
	policy               JobLogPolicy
	bytesLeft, linesLeft int64
	stopped              bool
}

func NewLogSanitizer(p JobLogPolicy, remainingBytes, remainingLines int64) (*LogSanitizer, error) {
	frozen, err := freezeLogPolicy(p)
	if err != nil || remainingBytes < 0 || remainingLines < 0 {
		return nil, ErrRedaction
	}
	return &LogSanitizer{policy: frozen, bytesLeft: remainingBytes, linesLeft: remainingLines}, nil
}

func (s *LogSanitizer) Sanitize(ctx context.Context, src io.Reader) (LogChunk, error) {
	if s == nil || src == nil || ctx.Err() != nil {
		return LogChunk{}, ErrRedaction
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return LogChunk{Truncated: true}, nil
	}
	if s.bytesLeft == 0 || s.linesLeft == 0 {
		s.stopped = true
		return LogChunk{Truncated: true, Diagnostics: []LogDiagnostic{{Code: "log_truncated"}}}, nil
	}
	raw, err := io.ReadAll(io.LimitReader(src, MaxLogChunkBytes+1))
	defer wipe(raw)
	if err != nil || ctx.Err() != nil {
		return LogChunk{}, ErrRedaction
	}
	if len(raw) > MaxLogChunkBytes {
		return LogChunk{}, ErrCapacity
	}
	lineCount := bytes.Count(raw, []byte{'\n'})
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		lineCount++
	}
	if lineCount > MaxLogChunkLines {
		return LogChunk{}, ErrCapacity
	}
	result := LogChunk{}
	bytesLeft, linesLeft := s.bytesLeft, s.linesLeft
	for n := 1; len(raw) > 0; n++ {
		if ctx.Err() != nil {
			wipe(result.Content)
			return LogChunk{}, ErrRedaction
		}
		end := bytes.IndexByte(raw, '\n')
		if end < 0 {
			end = len(raw)
		} else {
			end++
		}
		line := raw[:end]
		raw = raw[end:]
		clean, lineErr := logLine(bytes.TrimSuffix(line, []byte{'\n'}), s.policy, true)
		charge := int64(len(line))
		if int64(len(clean)) > charge {
			charge = int64(len(clean))
		}
		if len(result.Content)+len(clean) > MaxLogChunkBytes {
			wipe(clean)
			wipe(result.Content)
			return LogChunk{}, ErrCapacity
		}
		if linesLeft == 0 || charge > bytesLeft {
			wipe(clean)
			result.Truncated = true
			result.Diagnostics = append(result.Diagnostics, LogDiagnostic{Code: "log_truncated", Line: n})
			break
		}
		bytesLeft -= charge
		linesLeft--
		result.InputBytes += int64(len(line))
		result.ChargedBytes += charge
		result.InputLines++
		if lineErr != nil {
			result.Diagnostics = append(result.Diagnostics, LogDiagnostic{Code: "redaction_failed", Line: n})
			continue
		}
		result.Content = append(result.Content, clean...)
		result.Lines++
		wipe(clean)
	}
	if ctx.Err() != nil {
		wipe(result.Content)
		return LogChunk{}, ErrRedaction
	}
	if !result.Truncated && (bytesLeft == 0 || linesLeft == 0) {
		result.Truncated = true
		result.Diagnostics = append(result.Diagnostics, LogDiagnostic{Code: "log_truncated", Line: int(result.InputLines)})
	}
	s.bytesLeft, s.linesLeft, s.stopped = bytesLeft, linesLeft, result.Truncated
	return result, nil
}

type JobLogRedactor struct{ policy JobLogPolicy }

func NewJobLogRedactor(p JobLogPolicy) (*JobLogRedactor, error) {
	frozen, err := freezeLogPolicy(p)
	if err != nil {
		return nil, err
	}
	return &JobLogRedactor{policy: frozen}, nil
}

func (v *JobLogRedactor) Validate(ctx context.Context, i Identity, src io.Reader) error {
	if v == nil || src == nil || ctx.Err() != nil || !i.valid() || i.Type != "job_log_chunk" || i.Media != "text/plain" || i.ContentSize > MaxLogChunkBytes {
		return ErrRedaction
	}
	raw, err := io.ReadAll(io.LimitReader(src, MaxLogChunkBytes+1))
	defer wipe(raw)
	if err != nil || int64(len(raw)) != i.ContentSize || hash(raw) != i.ContentHash || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return ErrRedaction
	}
	for n := 0; len(raw) > 0; n++ {
		if n >= MaxLogChunkLines || ctx.Err() != nil {
			return ErrRedaction
		}
		end := bytes.IndexByte(raw, '\n')
		if end < 0 {
			return ErrRedaction
		}
		clean, err := logLine(raw[:end], v.policy, false)
		matches := bytes.Equal(clean, raw[:end+1])
		wipe(clean)
		if err != nil || !matches {
			return ErrRedaction
		}
		raw = raw[end+1:]
	}
	if ctx.Err() != nil {
		return ErrRedaction
	}
	return nil
}
