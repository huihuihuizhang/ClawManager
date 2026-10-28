package systembackupsecurity

import (
	"strconv"
	"unicode/utf8"
)

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them
// explicitly so an invalid wire identity cannot turn into a valid signed one.
func providerJSONUnicode(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for ; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
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
			if n >= 0xDC00 && n <= 0xDFFF {
				return false
			}
			if n >= 0xD800 && n <= 0xDBFF {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if e != nil || low < 0xDC00 || low > 0xDFFF {
					return false
				}
				i += 6
			}
		}
	}
	return true
}
