package domain

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strconv"
)

const imageCiphertextLimit = (16 << 20) + 12 + 16 // actual AES-GCM nonce/tag

type imageMaterialLimits struct{ objects, item, total int }

// This preflight walks the original bytes without allocating JSON strings,
// object slices or decoded base64. The wire format already requires canonical
// json.Marshal output; fixed field order also rejects missing, duplicate and
// unknown fields before a typed decoder can allocate their values.
type imageMaterialScan struct {
	ctx            context.Context
	raw            []byte
	i, cipherBytes int
	limits         imageMaterialLimits
}

func (p *imageMaterialScan) space() {
	for p.i < len(p.raw) {
		switch p.raw[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}
func (p *imageMaterialScan) take(c byte) error {
	if e := p.ctx.Err(); e != nil {
		return e
	}
	p.space()
	if p.i >= len(p.raw) || p.raw[p.i] != c {
		return ErrData
	}
	p.i++
	return nil
}
func (p *imageMaterialScan) text(limit int) ([]byte, error) {
	if e := p.take('"'); e != nil {
		return nil, e
	}
	start := p.i
	for p.i < len(p.raw) {
		if (p.i-start)&4095 == 0 {
			if e := p.ctx.Err(); e != nil {
				return nil, e
			}
		}
		if p.i-start > limit {
			return nil, ErrCapacity
		}
		c := p.raw[p.i]
		p.i++
		if c == '"' {
			return p.raw[start : p.i-1], nil
		}
		if c < 32 {
			return nil, ErrData
		}
		if c == '\\' {
			if p.i >= len(p.raw) {
				return nil, ErrData
			}
			p.i++
		}
	}
	return nil, ErrData
}
func (p *imageMaterialScan) fields(names []string, visit func(int) error) error {
	if e := p.take('{'); e != nil {
		return e
	}
	for i, name := range names {
		if i > 0 {
			if e := p.take(','); e != nil {
				return e
			}
		}
		key, e := p.text(64)
		if e != nil {
			return e
		}
		if !bytes.Equal(key, []byte(name)) {
			return ErrData
		}
		if e = p.take(':'); e != nil {
			return e
		}
		if e = visit(i); e != nil {
			return e
		}
	}
	return p.take('}')
}
func (p *imageMaterialScan) number() (int64, error) {
	if e := p.ctx.Err(); e != nil {
		return 0, e
	}
	p.space()
	start := p.i
	for p.i < len(p.raw) && (p.raw[p.i] == '-' || p.raw[p.i] >= '0' && p.raw[p.i] <= '9') {
		p.i++
		if p.i-start > 20 {
			return 0, ErrData
		}
	}
	n, e := strconv.ParseInt(string(p.raw[start:p.i]), 10, 64)
	if e != nil {
		return 0, ErrData
	}
	return n, nil
}
func (p *imageMaterialScan) strings(names []string) error {
	return p.fields(names, func(int) error { _, e := p.text(64 << 10); return e })
}
func (p *imageMaterialScan) realm() error {
	return p.strings([]string{"Endpoint", "TLSServerName", "RootCASHA256", "Region"})
}
func (p *imageMaterialScan) binding() error {
	return p.fields([]string{"backup_id", "attempt", "path", "part_index", "capture_context_hash", "envelope_id"}, func(i int) error {
		if i == 3 {
			_, e := p.number()
			return e
		}
		_, e := p.text(64 << 10)
		return e
	})
}
func (p *imageMaterialScan) sqlReceipt() error {
	return p.fields([]string{"name", "size", "sha256"}, func(i int) error {
		if i == 1 {
			_, e := p.number()
			return e
		}
		_, e := p.text(64 << 10)
		return e
	})
}
func (p *imageMaterialScan) ref() (int, error) {
	size := int64(0)
	e := p.fields([]string{"ArtifactID", "Bucket", "Key", "Version", "SHA256", "Size"}, func(i int) error {
		if i == 5 {
			var e error
			size, e = p.number()
			if e != nil {
				return e
			}
			if size <= 0 || size > int64(p.limits.item) {
				return ErrCapacity
			}
			return nil
		}
		_, e := p.text(64 << 10)
		return e
	})
	return int(size), e
}
func (p *imageMaterialScan) reserveCipher(size int) error {
	if size > p.limits.total-p.cipherBytes {
		return ErrCapacity
	}
	p.cipherBytes += size
	return nil
}
func (p *imageMaterialScan) cipher(size int) error {
	// Ref.Size is checked first; reject the total before scanning or decoding
	// this item's base64. No decoded buffer exists anywhere in the preflight.
	if e := p.reserveCipher(size); e != nil {
		return e
	}
	raw, e := p.text((p.limits.item + 2) / 3 * 4)
	if e != nil {
		return e
	}
	if len(raw) == 0 || len(raw)%4 != 0 {
		return ErrData
	}
	padding := 0
	for n := len(raw) - 1; n >= 0 && raw[n] == '='; n-- {
		padding++
	}
	if padding > 2 || len(raw)/4*3-padding != size {
		return ErrData
	}
	for i, c := range raw[:len(raw)-padding] {
		if i&4095 == 0 {
			if e := p.ctx.Err(); e != nil {
				return e
			}
		}
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return ErrData
		}
	}
	return nil
}
func (p *imageMaterialScan) objects(captured bool) error {
	p.space()
	if bytes.HasPrefix(p.raw[p.i:], []byte("null")) {
		p.i += 4
		return nil
	}
	if e := p.take('['); e != nil {
		return e
	}
	p.space()
	if p.i < len(p.raw) && p.raw[p.i] == ']' {
		p.i++
		return nil
	}
	for count := 0; ; count++ {
		// Check before even parsing an additional object, much less appending
		// a typed struct. Receipt arrays have the same independent limit.
		if count >= p.limits.objects {
			return ErrCapacity
		}
		size := 0
		names := []string{"Ref", "Ciphertext"}
		if !captured {
			names = []string{"Source", "TargetVersion", "PlaintextSHA256"}
		}
		e := p.fields(names, func(i int) error {
			if i == 0 {
				var e error
				size, e = p.ref()
				if e == nil && !captured {
					e = p.reserveCipher(size)
				}
				return e
			}
			if captured {
				return p.cipher(size)
			}
			_, e := p.text(64 << 10)
			return e
		})
		if e != nil {
			return e
		}
		p.space()
		if p.i < len(p.raw) && p.raw[p.i] == ']' {
			p.i++
			return nil
		}
		if e = p.take(','); e != nil {
			return e
		}
	}
}
func preflightImageMaterial(ctx context.Context, raw []byte, captured bool, limits imageMaterialLimits) error {
	if ctx == nil || limits.objects <= 0 || limits.item <= 0 || limits.total <= 0 {
		return ErrData
	}
	p := imageMaterialScan{ctx: ctx, raw: raw, limits: limits}
	var e error
	if captured {
		e = p.fields([]string{"Version", "SourceSQLSHA256", "SourceRealm", "Objects"}, func(i int) error {
			switch i {
			case 2:
				return p.realm()
			case 3:
				return p.objects(true)
			}
			_, e := p.text(64 << 10)
			return e
		})
	} else {
		e = p.fields([]string{"Version", "SourceSQLSHA256", "ImageSQLSHA256", "Database", "ServerUUID", "Bucket", "InterruptedAt", "TargetRealm", "SourceRealm", "SourceImageBinding", "ExpectedSQLSHA256", "ExpectedSQLReceipt", "ExpectedSQLBinding", "Objects"}, func(i int) error {
			switch i {
			case 7, 8:
				return p.realm()
			case 9, 12:
				return p.binding()
			case 11:
				return p.sqlReceipt()
			case 13:
				return p.objects(false)
			}
			_, e := p.text(64 << 10)
			return e
		})
	}
	if e != nil {
		return e
	}
	p.space()
	if p.i != len(raw) {
		return ErrData
	}
	return ctx.Err()
}

func clearImageMaterial(out any) {
	switch data := out.(type) {
	case *capturedImageObjects:
		if data != nil {
			for _, o := range data.Objects {
				clear(o.Ciphertext)
			}
			*data = capturedImageObjects{}
		}
	case *imageReceiptData:
		if data != nil {
			*data = imageReceiptData{}
		}
	}
}

// Failures always clear partial typed ciphertext, including Decode/canonical
// errors and cancellation after a successful Decode. The original AEAD plaintext
// buffer is separately cleared by openImageMaterial on every exit.
func decodeImageMaterial(ctx context.Context, plain []byte, out any) (err error) {
	captured := false
	switch value := out.(type) {
	case *capturedImageObjects:
		if value == nil {
			return ErrData
		}
		captured = true
	case *imageReceiptData:
		if value == nil {
			return ErrData
		}
	default:
		return ErrData
	}
	clearImageMaterial(out)
	defer func() {
		if err != nil {
			clearImageMaterial(out)
		}
	}()
	if err = preflightImageMaterial(ctx, plain, captured, imageMaterialLimits{64, imageCiphertextLimit, imageObjectBudget}); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrData
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrData
	}
	canonical, e := json.Marshal(out)
	defer clear(canonical)
	if e != nil || !bytes.Equal(bytes.TrimSpace(plain), canonical) {
		return ErrData
	}
	return ctx.Err()
}
