//go:build linux

package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func originalRelayReadNativeProcess(pid int) (originalRelayNativeProcess, error) {
	var zero originalRelayNativeProcess
	if pid <= 1 {
		return zero, ErrInstall
	}
	base := "/proc/" + strconv.Itoa(pid)
	stat, e := os.ReadFile(base + "/stat")
	if e != nil {
		return zero, e
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return zero, ErrInstall
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return zero, ErrInstall
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return zero, e
	}
	ns, e := os.Readlink(base + "/ns/pid")
	if e != nil {
		return zero, e
	}
	exe, e := os.Readlink(base + "/exe")
	if e != nil {
		return zero, e
	}
	f, e := os.Open(base + "/exe")
	if e != nil {
		return zero, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&022 != 0 || st.Size() < 1 || st.Size() > 128<<20 {
		return zero, ErrInstall
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if e != nil || n != st.Size() {
		return zero, ErrInstall
	}
	cmd, e := os.ReadFile(base + "/cmdline")
	if e != nil || len(cmd) < 1 || len(cmd) > 65536 {
		return zero, ErrInstall
	}
	c := sha256.Sum256(cmd)
	return originalRelayNativeProcess{PID: pid, BootID: strings.TrimSpace(string(boot)), PIDNamespace: ns, StartTicks: fields[19], Executable: exe, ExecutableSHA256: hex.EncodeToString(h.Sum(nil)), CommandSHA256: hex.EncodeToString(c[:])}, nil
}
func originalRelaySignalExactProcess(ctx context.Context, p originalRelayNativeProcess, serveSHA, planSHA, pkiSHA string) (bool, error) {
	if p.PID <= 1 || p.PID == os.Getpid() {
		return false, ErrInstall
	}
	fd, e := unix.PidfdOpen(p.PID, 0)
	if e != nil {
		return false, ErrInstall
	}
	defer unix.Close(fd)
	actual, e := originalRelayReadNativeProcess(p.PID)
	if e != nil || actual != p {
		return false, ErrInstall
	}
	self, e := originalRelayReadNativeProcess(os.Getpid())
	if e != nil || self.BootID != p.BootID || self.PIDNamespace != p.PIDNamespace || self.ExecutableSHA256 != p.ExecutableSHA256 {
		return false, ErrInstall
	}
	cmd, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.PID))
	if e != nil {
		return false, ErrInstall
	}
	parts := strings.Split(string(cmd), "\x00")
	if len(parts) < 2 || parts[1] != "relay-serve" {
		return false, ErrInstall
	}
	flags := map[string]string{}
	for n := 2; n+1 < len(parts); n += 2 {
		flags[parts[n]] = parts[n+1]
	}
	if flags["--inputs-sha256"] != serveSHA || flags["--plan-sha256"] != planSHA {
		return false, ErrInstall
	}
	input, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: flags["--inputs-file"], SHA256: serveSHA}, 262144)
	var selection OriginalReadOnlyRelayInputs
	if e != nil || decodeExact(input, &selection) != nil || selection.Material.SHA256 != pkiSHA {
		return false, ErrInstall
	}
	if ctx.Err() != nil {
		return false, ErrInstall
	}
	if unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0) != nil {
		return false, ErrCommitUnknown
	}
	for {
		if ctx.Err() != nil {
			return false, ErrCommitUnknown
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, e := unix.Poll(fds, 100)
		if e != nil && !errors.Is(e, unix.EINTR) {
			return false, ErrCommitUnknown
		}
		if n > 0 && fds[0].Revents&unix.POLLIN != 0 {
			return true, nil
		}
		time.Sleep(time.Millisecond)
	}
}
func originalRelayProcessAbsent(p originalRelayNativeProcess) (bool, error) {
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil || strings.TrimSpace(string(boot)) != p.BootID {
		return false, ErrInstall
	}
	ns, e := os.Readlink("/proc/self/ns/pid")
	if e != nil || ns != p.PIDNamespace {
		return false, ErrInstall
	}
	stat, e := os.ReadFile("/proc/" + strconv.Itoa(p.PID) + "/stat")
	if errors.Is(e, os.ErrNotExist) {
		return true, nil
	}
	if e != nil {
		return false, ErrInstall
	}
	end := strings.LastIndex(string(stat), ")")
	if end < 0 {
		return false, ErrInstall
	}
	parts := strings.Fields(string(stat[end+1:]))
	if len(parts) < 20 {
		return false, ErrInstall
	}
	if parts[19] != p.StartTicks {
		return true, nil
	}
	if (parts[0] == "Z" || parts[0] == "X") && parts[17] == "1" {
		return true, nil
	}
	actual, e := originalRelayReadNativeProcess(p.PID)
	if errors.Is(e, os.ErrNotExist) {
		return true, nil
	}
	if e != nil {
		return false, ErrInstall
	}
	if actual.StartTicks != p.StartTicks {
		return true, nil
	}
	return false, nil
}
