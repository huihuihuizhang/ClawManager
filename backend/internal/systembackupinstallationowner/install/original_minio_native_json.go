package install

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The actual pinned Python producer uses precise integer JSON, not JCS/IEEE754.
// Preserve native 64-bit ns/inode values and bounded full-tree output. This
// decoder is only for native DATA, never grants, permissions or signed records.
func decodeOriginalNativeJSON(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return ErrInstall
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		if depth > 160 || tokens > 4000000 {
			return ErrInstall
		}
		tokens++
		t, e := d.Token()
		if e != nil {
			return ErrInstall
		}
		if number, ok := t.(json.Number); ok {
			s := number.String()
			if strings.ContainsAny(s, ".eE+") {
				return ErrInstall
			}
			if _, e := strconv.ParseInt(s, 10, 64); e != nil {
				if strings.HasPrefix(s, "-") {
					return ErrInstall
				}
				if _, e = strconv.ParseUint(s, 10, 64); e != nil {
					return ErrInstall
				}
			}
			return nil
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return ErrInstall
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, e := d.Token()
				if e != nil {
					return ErrInstall
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrInstall
				}
				seen[name] = true
			}
			if e := value(depth + 1); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return ErrInstall
		}
		return nil
	}
	if value(0) != nil {
		return ErrInstall
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInstall
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInstall
	}
	return nil
}

func originalNativeExactKeys(raw []byte, keys ...string) bool {
	var fields map[string]json.RawMessage
	if decodeOriginalNativeJSON(raw, &fields, 32<<20) != nil || len(fields) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, found := fields[key]; !found {
			return false
		}
	}
	return true
}

type originalNativeTreeMetadata struct {
	Device uint64            `json:"device"`
	Inode  uint64            `json:"inode"`
	Size   int64             `json:"size"`
	Mode   uint32            `json:"mode"`
	UID    uint32            `json:"uid"`
	GID    uint32            `json:"gid"`
	Mtime  int64             `json:"mtime_ns"`
	Ctime  int64             `json:"ctime_ns"`
	Nlink  uint64            `json:"nlink"`
	Xattrs map[string]string `json:"xattrs_base64"`
}

func decodeOriginalMinIOFullInventory(raw []byte, out *originalMinIOFullTree) error {
	if out == nil || decodeOriginalNativeJSON(raw, out, 32<<20) != nil || !originalNativeExactKeys(raw, "profile", "phase", "plan_sha256", "node", "root", "mount", "format", "before", "after", "complete_reachable_tree", "tree_sha256", "excluded_paths") {
		return ErrInstall
	}
	if !originalNativeExactKeys(out.Node, "boot_id", "machine_id", "hostname") || !originalNativeExactKeys(out.Mount, "id", "device", "root", "path", "options", "filesystem", "source") || !originalNativeExactKeys(out.Format, "format_sha256", "deployment_id", "drive_id", "sets") {
		return ErrInstall
	}
	var node struct {
		BootID    string `json:"boot_id"`
		MachineID string `json:"machine_id"`
		Hostname  string `json:"hostname"`
	}
	var mount struct{ ID, Device, Root, Path, Options, Filesystem, Source string }
	var format struct {
		Hash         string     `json:"format_sha256"`
		DeploymentID string     `json:"deployment_id"`
		DriveID      string     `json:"drive_id"`
		Sets         [][]string `json:"sets"`
	}
	if decodeOriginalNativeJSON(out.Node, &node, 262144) != nil || decodeOriginalNativeJSON(out.Mount, &mount, 262144) != nil || decodeOriginalNativeJSON(out.Format, &format, 262144) != nil || node.BootID == "" || node.MachineID == "" || node.Hostname == "" || mount.Root != "/" || !digestPattern.MatchString(format.Hash) || len(format.Sets) != 1 || len(format.Sets[0]) != 1 || format.Sets[0][0] != format.DriveID || format.DeploymentID == "" {
		return ErrInstall
	}
	for _, actor := range []json.RawMessage{out.Before, out.After} {
		if out.Phase == "warm" {
			var state struct {
				ID, State string
				PID       int    `json:"pid"`
				Start     string `json:"pid_start"`
			}
			if !originalNativeExactKeys(actor, "id", "state", "pid", "pid_start") || decodeOriginalNativeJSON(actor, &state, 262144) != nil || state.ID == "" || state.State != "CONTAINER_RUNNING" || state.PID <= 1 || state.Start == "" {
				return ErrInstall
			}
		} else if out.Phase == "cold" {
			var state struct {
				ID, State, FinishedAt string
				ExitCode              *int
			}
			if !originalNativeExactKeys(actor, "id", "state", "finishedAt", "exitCode") || decodeOriginalNativeJSON(actor, &state, 262144) != nil || state.ID == "" || state.State != "CONTAINER_EXITED" || state.FinishedAt == "" {
				return ErrInstall
			}
		} else {
			return ErrInstall
		}
	}
	var rows []json.RawMessage
	if decodeOriginalNativeJSON(out.Tree, &rows, 32<<20) != nil || len(rows) == 0 || len(rows) > 100000 || hash(out.Tree) != out.TreeSHA256 {
		return ErrInstall
	}
	paths := map[string]bool{}
	for index, row := range rows {
		var entry struct {
			Path, Type string
			Metadata   json.RawMessage
			SHA256     string
		}
		if decodeOriginalNativeJSON(row, &entry, 32<<20) != nil || paths[entry.Path] || index == 0 && (entry.Path != "" || entry.Type != "directory") || index > 0 && entry.Path == "" {
			return ErrInstall
		}
		paths[entry.Path] = true
		if entry.Type == "file" {
			if !originalNativeExactKeys(row, "path", "type", "metadata", "sha256") || !digestPattern.MatchString(entry.SHA256) {
				return ErrInstall
			}
		} else if entry.Type == "directory" {
			if !originalNativeExactKeys(row, "path", "type", "metadata") {
				return ErrInstall
			}
		} else {
			return ErrInstall
		}
		var metadata originalNativeTreeMetadata
		if !originalNativeExactKeys(entry.Metadata, "device", "inode", "size", "mode", "uid", "gid", "mtime_ns", "ctime_ns", "nlink", "xattrs_base64") || decodeOriginalNativeJSON(entry.Metadata, &metadata, 32<<20) != nil || metadata.Size < 0 || metadata.Xattrs == nil || metadata.Nlink == 0 || entry.Type == "file" && metadata.Nlink != 1 {
			return ErrInstall
		}
	}
	return nil
}
