package systembackupproducer

import (
	"encoding/binary"
	"unicode/utf8"
)

// parseFrame is the inverse of C1 typed framing. Limits apply before allocating;
// object keys must already be strictly sorted, so duplicate/noncanonical frames
// cannot acquire an alternative storage identity.
func parseFrame(raw []byte, limit int) (any, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, ErrInvalid
	}
	p := frameReader{raw: raw}
	v, err := p.value(0)
	if err != nil || p.pos != len(raw) {
		return nil, ErrInvalid
	}
	return v, nil
}

type frameReader struct {
	raw []byte
	pos int
}

func (p *frameReader) length() (uint64, error) {
	if len(p.raw)-p.pos < 8 {
		return 0, ErrInvalid
	}
	n := binary.BigEndian.Uint64(p.raw[p.pos : p.pos+8])
	p.pos += 8
	return n, nil
}

func (p *frameReader) value(depth int) (any, error) {
	if depth > 16 || p.pos >= len(p.raw) {
		return nil, ErrInvalid
	}
	tag := p.raw[p.pos]
	p.pos++
	switch tag {
	case 'n':
		return nil, nil
	case 't':
		return true, nil
	case 'f':
		return false, nil
	case 's':
		n, err := p.length()
		if err != nil || n > uint64(len(p.raw)-p.pos) {
			return nil, ErrInvalid
		}
		b := p.raw[p.pos : p.pos+int(n)]
		p.pos += int(n)
		if !utf8.Valid(b) {
			return nil, ErrInvalid
		}
		return string(b), nil
	case 'a', 'o':
		n, err := p.length()
		if err != nil || n > uint64(len(p.raw)-p.pos) {
			return nil, ErrInvalid
		}
		// Every object entry needs at least a string frame (9 bytes) and value.
		if tag == 'o' && n > uint64((len(p.raw)-p.pos)/10) {
			return nil, ErrInvalid
		}
		if tag == 'a' {
			a := make([]any, 0, int(n))
			for i := uint64(0); i < n; i++ {
				v, e := p.value(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			return a, nil
		}
		m := make(map[string]any, int(n))
		previous := ""
		for i := uint64(0); i < n; i++ {
			key, e := p.value(depth + 1)
			if e != nil {
				return nil, e
			}
			k, ok := key.(string)
			if !ok || (i > 0 && k <= previous) {
				return nil, ErrInvalid
			}
			v, e := p.value(depth + 1)
			if e != nil {
				return nil, e
			}
			m[k] = v
			previous = k
		}
		return m, nil
	default:
		return nil, ErrInvalid
	}
}
