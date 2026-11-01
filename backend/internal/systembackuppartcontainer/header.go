package systembackuppartcontainer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
)

type headerPlan struct {
	Size      int64
	Tail      []byte
	MemberSHA []string
}

func planHeader(header Header, indexLimit int64) (headerPlan, error) {
	var zero headerPlan
	if indexLimit < 1 || indexLimit > MaxIndexBytes || len(header.Members) == 0 || len(header.Members) > MaxMembers {
		return zero, ErrContainer
	}
	scope, err := canonical(header.Scope)
	if err != nil || len(scope) > maxScopeMetadataBytes {
		return zero, ErrContainer
	}
	version, _ := json.Marshal(Version)
	source, _ := json.Marshal(header.SourceInventorySHA256)
	tail := append([]byte(`],"schema_version":`), version...)
	tail = append(tail, []byte(`,"scope":`)...)
	tail = append(tail, scope...)
	tail = append(tail, []byte(`,"source_inventory_sha256":`)...)
	tail = append(tail, source...)
	tail = append(tail, '}')
	plan := headerPlan{Size: int64(len(`{"members":[`) + len(tail) + len(header.Members) - 1), Tail: tail, MemberSHA: make([]string, 0, len(header.Members))}
	for _, member := range header.Members {
		raw, err := canonical(member)
		if err != nil || len(raw) > maxMemberMetadataBytes || int64(len(raw)) > indexLimit-plan.Size {
			return zero, ErrContainer
		}
		plan.Size += int64(len(raw))
		plan.MemberSHA = append(plan.MemberSHA, checksum(raw))
	}
	if plan.Size > indexLimit || plan.Size > MaxHeaderBytes {
		return zero, ErrContainer
	}
	return plan, nil
}

func writeHeader(dst io.Writer, header Header, plan headerPlan) error {
	if _, err := io.WriteString(dst, `{"members":[`); err != nil {
		return ErrContainer
	}
	for index, member := range header.Members {
		raw, err := canonical(member)
		if err != nil || index >= len(plan.MemberSHA) || checksum(raw) != plan.MemberSHA[index] {
			return ErrContainer
		}
		if index != 0 {
			if _, err = io.WriteString(dst, ","); err != nil {
				return ErrContainer
			}
		}
		if _, err = io.Copy(dst, bytes.NewReader(raw)); err != nil {
			return ErrContainer
		}
	}
	if _, err := io.Copy(dst, bytes.NewReader(plan.Tail)); err != nil {
		return ErrContainer
	}
	return nil
}

type headerCursor struct {
	reader   *bufio.Reader
	position int64
}

func (c *headerCursor) literal(want string) bool {
	for index := range want {
		value, err := c.reader.ReadByte()
		if err != nil {
			return false
		}
		c.position++
		if value != want[index] {
			return false
		}
	}
	return true
}

// Retains at most ONE bounded member JSON object while scanning the header.
// Typed metadata is retained, but no 512 MiB/8 GiB index-sized byte allocation.
func (c *headerCursor) object(limit int) ([]byte, error) {
	var raw []byte
	depth := 0
	quoted, escaped := false, false
	for len(raw) < limit {
		value, err := c.reader.ReadByte()
		if err != nil {
			return nil, ErrContainer
		}
		c.position++
		if len(raw) == 0 && value != '{' {
			return nil, ErrContainer
		}
		raw = append(raw, value)
		if quoted {
			if escaped {
				escaped = false
			} else if value == '\\' {
				escaped = true
			} else if value == '"' {
				quoted = false
			}
			continue
		}
		if value == '"' {
			quoted = true
			continue
		}
		if value == '{' || value == '[' {
			depth++
			if depth > 32 {
				return nil, ErrContainer
			}
		}
		if value == '}' || value == ']' {
			depth--
			if depth == 0 {
				return raw, nil
			}
			if depth < 0 {
				return nil, ErrContainer
			}
		}
	}
	return nil, ErrContainer
}

func readHeader(src io.Reader, headerSize, indexLimit int64) (Header, error) {
	var header Header
	if headerSize < 1 || headerSize > indexLimit || indexLimit < 1 || indexLimit > MaxIndexBytes || headerSize > MaxHeaderBytes {
		return header, ErrContainer
	}
	cursor := headerCursor{reader: bufio.NewReaderSize(src, 64<<10)}
	if !cursor.literal(`{"members":[`) {
		return header, ErrContainer
	}
	for {
		if len(header.Members) >= MaxMembers {
			return Header{}, ErrContainer
		}
		raw, err := cursor.object(maxMemberMetadataBytes)
		if err != nil {
			return Header{}, err
		}
		var member Member
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&member) != nil {
			return Header{}, ErrContainer
		}
		roundtrip, err := canonical(member)
		if err != nil || !bytes.Equal(roundtrip, raw) {
			return Header{}, ErrContainer
		}
		header.Members = append(header.Members, member)
		separator, err := cursor.reader.ReadByte()
		if err != nil {
			return Header{}, ErrContainer
		}
		cursor.position++
		if separator == ']' {
			break
		}
		if separator != ',' {
			return Header{}, ErrContainer
		}
	}
	version, _ := json.Marshal(Version)
	if !cursor.literal(`,"schema_version":` + string(version) + `,"scope":`) {
		return Header{}, ErrContainer
	}
	rawScope, err := cursor.object(maxScopeMetadataBytes)
	if err != nil {
		return Header{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(rawScope))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&header.Scope) != nil {
		return Header{}, ErrContainer
	}
	roundtrip, err := canonical(header.Scope)
	if err != nil || !bytes.Equal(roundtrip, rawScope) || !cursor.literal(`,"source_inventory_sha256":"`) {
		return Header{}, ErrContainer
	}
	var source [64]byte
	if _, err = io.ReadFull(cursor.reader, source[:]); err != nil {
		return Header{}, ErrContainer
	}
	cursor.position += 64
	header.SourceInventorySHA256 = string(source[:])
	header.Version = Version
	if !digest.MatchString(header.SourceInventorySHA256) || !cursor.literal(`"}`) || cursor.position != headerSize {
		return Header{}, ErrContainer
	}
	if _, err = cursor.reader.ReadByte(); err != io.EOF {
		return Header{}, ErrContainer
	}
	return header, nil
}
