//go:build linux

package quiesce

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func originalHistoryDirectoryLinuxFixture(t *testing.T, filename string, until time.Time) (*VerifiedNodeObservation, ObservationBinding, string) {
	t.Helper()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(filename)
	if e != nil {
		t.Fatal(e)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing native stat")
	}
	raw, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		t.Fatal(e)
	}
	best := ""
	length := -1
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if mountSeparator(f) < 0 {
			t.Fatal("bad native mount fixture")
		}
		mp, e := mountUnescape(f[4])
		if e != nil {
			t.Fatal(e)
		}
		if withinObservation(filename, mp) && len(mp) > length {
			best = line
			length = len(mp)
		}
	}
	if best == "" {
		t.Fatal("no native mount fixture")
	}
	bootID := strings.TrimSpace(string(boot))
	v, b := originalHistoryDirectoryTestProof(t, observedPath{Path: filename, Device: uint64(st.Dev), Inode: st.Ino, Mount: best}, bootID, until)
	return v, b, bootID
}

func TestOriginalHistoryDirectoryLinuxActualPagesAndEOF(t *testing.T) {
	for _, count := range []int{0, 301} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			filename := t.TempDir()
			for n := 0; n < count; n++ {
				if e := os.WriteFile(filepath.Join(filename, fmt.Sprintf("retained-%03d", n)), []byte("not-read"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			v, b, boot := originalHistoryDirectoryLinuxFixture(t, filename, time.Now().Add(4*time.Second))
			r, e := OpenOriginalNodeHistoryDirectory(ctx, v, b, boot, filename)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			seen := map[string]bool{}
			eof := false
			for page := 0; page < 8; page++ {
				entries, e := r.ReadDir(ctx, 128)
				if e != nil && e != io.EOF {
					t.Fatal(e)
				}
				for _, entry := range entries {
					if seen[entry.Name] {
						t.Fatal("duplicate actual page member")
					}
					seen[entry.Name] = true
				}
				if e == io.EOF {
					eof = true
					break
				}
			}
			if !eof || len(seen) != count {
				t.Fatal("actual pages did not reach complete EOF", len(seen), eof)
			}
			clone := &OriginalNodeHistoryDirectory{origin: r, dir: r.dir}
			if clone.Close() == nil {
				t.Fatal("copied reader closed original descriptor")
			}
			if _, e := r.ReadDir(ctx, 1); e != io.EOF {
				t.Fatal("original damaged by clone", e)
			}
		})
	}
}

func TestOriginalHistoryDirectoryLinuxRejectsNativeDrift(t *testing.T) {
	for _, kind := range []string{"replacement", "new-entry", "mode-change", "closed-descriptor", "proof-change", "foreign-context", "invalid-page-size"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			parent := t.TempDir()
			filename := filepath.Join(parent, "original")
			if e := os.Mkdir(filename, 0700); e != nil {
				t.Fatal(e)
			}
			v, b, boot := originalHistoryDirectoryLinuxFixture(t, filename, time.Now().Add(4*time.Second))
			r, e := OpenOriginalNodeHistoryDirectory(ctx, v, b, boot, filename)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			readctx := ctx
			n := 1
			switch kind {
			case "replacement":
				if e := os.Rename(filename, filename+"-retained"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(filename, 0700); e != nil {
					t.Fatal(e)
				}
			case "new-entry":
				if e := os.WriteFile(filepath.Join(filename, "unknown"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "mode-change":
				if e := os.Chmod(filename, 0755); e != nil {
					t.Fatal(e)
				}
			case "closed-descriptor":
				if e := r.dir.Close(); e != nil {
					t.Fatal(e)
				}
			case "proof-change":
				v.response.Anchor = "different"
			case "foreign-context":
				other, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				readctx = other
			case "invalid-page-size":
				n = 0
			}
			if entries, e := r.ReadDir(readctx, n); e == nil || e == io.EOF || entries != nil {
				t.Fatal("uncertain page/EOF survived drift", e)
			}
			if !r.closed || r.dir != nil {
				t.Fatal("failed reader retained descriptor")
			}
		})
	}
}

func TestOriginalHistoryDirectoryLinuxRefusesAliasAndOffNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filename := t.TempDir()
	v, b, boot := originalHistoryDirectoryLinuxFixture(t, filename, time.Now().Add(4*time.Second))
	if r, e := OpenOriginalNodeHistoryDirectory(ctx, v, b, "another-node-boot", filename); e == nil || r != nil {
		t.Fatal("foreign boot accepted")
	}
	// Even a self-consistent private metadata fixture cannot pass actual boot.
	foreign, fb := originalHistoryDirectoryTestProof(t, observedPath{Path: filename, Device: 1, Inode: 2, Mount: "mount"}, "foreign", time.Now().Add(time.Second))
	if r, e := OpenOriginalNodeHistoryDirectory(ctx, foreign, fb, "foreign", filename); e == nil || r != nil {
		t.Fatal("off-node metadata accepted")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if e := os.Symlink(filename, alias); e != nil {
		t.Fatal(e)
	}
	if r, e := OpenOriginalNodeHistoryDirectory(ctx, v, b, boot, alias); e == nil || r != nil {
		t.Fatal("caller path alias accepted")
	}
}

func TestOriginalHistoryDirectoryLinuxClosesAtOriginalCapOrCancel(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			filename := t.TempDir()
			v, b, boot := originalHistoryDirectoryLinuxFixture(t, filename, time.Now().Add(300*time.Millisecond))
			r, e := OpenOriginalNodeHistoryDirectory(ctx, v, b, boot, filename)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			if cancelled {
				cancel()
			}
			end := time.Now().Add(2 * time.Second)
			closed := false
			for time.Now().Before(end) {
				r.mu.Lock()
				closed = r.closed && r.dir == nil
				r.mu.Unlock()
				if closed {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !closed {
				t.Fatal("abandoned native descriptor outlived original cap/cancellation")
			}
			if entries, e := r.ReadDir(ctx, 1); e == nil || e == io.EOF || entries != nil {
				t.Fatal("closed observation returned EOF", e)
			}
		})
	}
}
