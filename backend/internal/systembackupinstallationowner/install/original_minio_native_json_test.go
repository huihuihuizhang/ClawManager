package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func originalNativeInventoryCodecFixture(t *testing.T, files int) []byte {
	t.Helper()
	meta := func(mode uint32, links uint64) map[string]any {
		return map[string]any{"device": uint64(2049), "inode": uint64(42), "size": int64(0), "mode": mode, "uid": uint32(0), "gid": uint32(0), "mtime_ns": int64(1793890000000000001), "ctime_ns": int64(1793890000000000003), "nlink": links, "xattrs_base64": map[string]string{}}
	}
	rows := []map[string]any{{"path": "", "type": "directory", "metadata": meta(0040700, 2)}}
	for n := 0; n < files; n++ {
		rows = append(rows, map[string]any{"path": fmt.Sprintf("file-%06d", n), "type": "file", "metadata": meta(0100600, 1), "sha256": hash(nil)})
	}
	tree, e := json.Marshal(rows)
	if e != nil {
		t.Fatal(e)
	}
	actor := map[string]any{"id": "original-container", "state": "CONTAINER_RUNNING", "pid": 101, "pid_start": "12345"}
	data := map[string]any{"profile": "original-minio-hostpath-native-raw-cut.v1", "phase": "warm", "plan_sha256": hash([]byte("plan")), "root": "/original/minio", "node": map[string]string{"boot_id": "boot", "machine_id": "machine", "hostname": "node"}, "mount": map[string]string{"id": "1", "device": "8:1", "root": "/", "path": "/", "options": "rw", "filesystem": "ext4", "source": "/dev/sda1"}, "format": map[string]any{"format_sha256": hash([]byte("format")), "deployment_id": "deployment", "drive_id": "drive", "sets": [][]string{{"drive"}}}, "before": actor, "after": actor, "complete_reachable_tree": json.RawMessage(tree), "tree_sha256": hash(tree), "excluded_paths": []string{}}
	raw, e := json.Marshal(data)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestOriginalNativeInventoryPreservesExactNanosecondsAndLargeTree(t *testing.T) {
	for _, files := range []int{1, 1500} {
		t.Run(fmt.Sprint(files), func(t *testing.T) {
			raw := originalNativeInventoryCodecFixture(t, files)
			if files > 1 && len(raw) <= 262144 {
				t.Fatal("fixture must cross generic signed-document limit")
			}
			var out originalMinIOFullTree
			if decodeOriginalMinIOFullInventory(raw, &out) != nil {
				t.Fatal("real integer native schema rejected")
			}
			if !bytes.Contains(out.Tree, []byte("1793890000000000001")) || !bytes.Contains(out.Tree, []byte("1793890000000000003")) || hash(out.Tree) != out.TreeSHA256 {
				t.Fatal("native int64/tree digest changed")
			}
		})
	}
}

func TestOriginalNativeInventoryRejectsAmbiguousOrUnknownData(t *testing.T) {
	raw := originalNativeInventoryCodecFixture(t, 1)
	cases := map[string][]byte{
		"duplicate-ns":     bytes.Replace(raw, []byte(`"mtime_ns":1793890000000000001`), []byte(`"mtime_ns":1793890000000000001,"mtime_ns":1793890000000000001`), 1),
		"float-ns":         bytes.Replace(raw, []byte(`1793890000000000001`), []byte(`1.793890000000000001e18`), 1),
		"unknown-metadata": bytes.Replace(raw, []byte(`"mtime_ns":1793890000000000001`), []byte(`"unclassified":0,"mtime_ns":1793890000000000001`), 1),
		"second-document":  append(bytes.Clone(raw), []byte(`{}`)...),
		"unknown-outer":    append([]byte(`{"unknown":0,`), raw[1:]...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var out originalMinIOFullTree
			if decodeOriginalMinIOFullInventory(body, &out) == nil {
				t.Fatal("ambiguous native data accepted")
			}
		})
	}
}

func TestOriginalNativeDataReceiptAllowsCLIWhitespaceButNotDuplicateFields(t *testing.T) {
	var out struct{ Maximum int64 }
	if decodeOriginalNativeJSON([]byte("{\"Maximum\":1793890000000000001}\n"), &out, 262144) != nil || out.Maximum != 1793890000000000001 {
		t.Fatal("native data receipt lost integer/EOF whitespace")
	}
	if decodeOriginalNativeJSON([]byte(`{"Maximum":1,"Maximum":2}`), &out, 262144) == nil {
		t.Fatal("duplicate receipt field")
	}
}
