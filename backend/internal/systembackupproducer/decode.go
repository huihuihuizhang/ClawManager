package systembackupproducer

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"
)

// The raw transport cap is independent of the 32/64 KiB canonical request cap.
// Input whitespace/escape expansion cannot allocate an unbounded parse tree.
const MaxJSONBytes = 1 << 20

func DecodeResult(raw []byte) (ResultRequest, error) {
	var r ResultRequest
	if err := DecodeRecord(raw, &r); err != nil {
		return ResultRequest{}, err
	}
	return r, nil
}
func DecodeCommand(raw []byte) (CommandRequest, error) {
	var r CommandRequest
	if err := DecodeRecord(raw, &r); err != nil {
		return CommandRequest{}, err
	}
	return r, nil
}

// DecodeRecord accepts only closed C1 data records. Decode into a fresh value
// and publish it only after validation; an error never leaves partially trusted
// fields in the caller's destination. It does not authenticate any record.
func DecodeRecord(raw []byte, out any) error {
	switch out.(type) {
	case *ResultRequest, *CommandRequest, *DomainRecord, *GrantRecord, *RunRecord, *TargetRecord, *HistoricalBindingRecord, *ReceiptRecord, *CommandReceiptRecord, *ReferenceRecord:
	default:
		return ErrInvalid
	}
	rv := reflect.ValueOf(out)
	if rv.IsNil() {
		return ErrInvalid
	}
	next := reflect.New(rv.Elem().Type())
	if err := decodeObject(raw, next.Interface()); err != nil {
		return err
	}
	rv.Elem().Set(next.Elem())
	return nil
}
func decodeObject(raw []byte, out any) error {
	v, e := parseJSON(raw)
	if e != nil {
		return e
	}
	if e = checkShape(v, reflect.TypeOf(out).Elem()); e != nil {
		return e
	}
	if e = json.Unmarshal(raw, out); e != nil {
		return ErrInvalid
	}
	return validateTyped(reflect.ValueOf(out))
}

func parseJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxJSONBytes || !utf8.Valid(raw) || !validEscapes(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 16 {
			return nil, ErrInvalid
		}
		tok, e := d.Token()
		if e != nil {
			return nil, ErrInvalid
		}
		switch x := tok.(type) {
		case nil, bool, string:
			return x, nil
		case json.Delim:
			switch x {
			case '{':
				m := map[string]any{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, ErrInvalid
					}
					key, ok := k.(string)
					if !ok {
						return nil, ErrInvalid
					}
					if _, exists := m[key]; exists {
						return nil, ErrInvalid
					}
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					m[key] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, ErrInvalid
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					v, e := read(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, ErrInvalid
				}
				return a, nil
			}
		}
		return nil, ErrInvalid // in particular, every JSON number is forbidden
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}

// encoding/json replaces unmatched UTF-16 surrogates with U+FFFD. Check the
// original escape bytes first so two distinct identities cannot hash alike.
func validEscapes(raw []byte) bool {
	inside := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inside = !inside
			continue
		}
		if !inside || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inside
}

func checkShape(value any, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		return checkShape(value, t.Elem())
	}
	if t == reflect.TypeOf(Admission{}) || t == reflect.TypeOf(Host{}) || t == reflect.TypeOf(Results{}) {
		m, ok := value.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		var branch reflect.Type
		switch t {
		case reflect.TypeOf(Admission{}):
			switch m["scenario"] {
			case "unconfigured":
				branch = reflect.TypeOf(UnconfiguredAdmission{})
			case "disabled", "enabled":
				branch = reflect.TypeOf(ConfiguredAdmission{})
			}
		case reflect.TypeOf(Host{}):
			switch m["kind"] {
			case "service":
				branch = reflect.TypeOf(ServiceHost{})
			case "job":
				branch = reflect.TypeOf(JobHost{})
			}
		case reflect.TypeOf(Results{}):
			switch m["kind"] {
			case "provider":
				branch = reflect.TypeOf(ProviderResults{})
			case "dependency":
				branch = reflect.TypeOf(DependencyResults{})
			}
		}
		if branch == nil {
			return ErrInvalid
		}
		return checkShape(value, branch)
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := value.(map[string]any)
		if !ok || len(m) != t.NumField() {
			return ErrInvalid
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := f.Tag.Get("json")
			v, ok := m[key]
			if key == "" || !ok {
				return ErrInvalid
			}
			if e := checkShape(v, f.Type); e != nil {
				return e
			}
		}
	case reflect.Slice:
		a, ok := value.([]any)
		if !ok || len(a) < 1 || len(a) > 32 {
			return ErrInvalid
		}
		for _, v := range a {
			if e := checkShape(v, t.Elem()); e != nil {
				return e
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
