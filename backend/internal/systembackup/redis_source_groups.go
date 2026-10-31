package systembackup

import (
	"encoding/json"
	"strconv"
	"strings"
)

// XINFO GROUPS is preserved as the original RESP array encoded in JSON. Byte
// strings remain base64. Unknown shapes/fields fail closed instead of silently
// omitting consumer progress or pending state from a supported stream record.
func validRedisSourceGroups(raw []byte) bool {
	var groups [][]json.RawMessage
	if json.Unmarshal(raw, &groups) != nil || groups == nil || len(groups) > 10000 {
		return false
	}
	seenNames := map[string]bool{}
	for _, group := range groups {
		if len(group) < 8 || len(group) > 12 || len(group)%2 != 0 {
			return false
		}
		fields := map[string]bool{}
		for n := 0; n < len(group); n += 2 {
			var name []byte
			if json.Unmarshal(group[n], &name) != nil || fields[string(name)] {
				return false
			}
			fields[string(name)] = true
			switch string(name) {
			case "name":
				var value []byte
				if json.Unmarshal(group[n+1], &value) != nil || len(value) < 1 || len(value) > 4096 || seenNames[string(value)] {
					return false
				}
				seenNames[string(value)] = true
			case "last-delivered-id":
				var value []byte
				if json.Unmarshal(group[n+1], &value) != nil {
					return false
				}
				parts := strings.Split(string(value), "-")
				if len(parts) != 2 {
					return false
				}
				for _, part := range parts {
					if part == "" || len(part) > 20 {
						return false
					}
					if _, err := strconv.ParseUint(part, 10, 64); err != nil {
						return false
					}
				}
			case "consumers", "pending":
				var value int64
				if string(group[n+1]) == "null" || json.Unmarshal(group[n+1], &value) != nil || value < 0 {
					return false
				}
			case "entries-read", "lag":
				if string(group[n+1]) != "null" {
					var value int64
					if json.Unmarshal(group[n+1], &value) != nil || value < 0 {
						return false
					}
				}
			default:
				return false
			}
		}
		if !fields["name"] || !fields["consumers"] || !fields["pending"] || !fields["last-delivered-id"] {
			return false
		}
	}
	return true
}
