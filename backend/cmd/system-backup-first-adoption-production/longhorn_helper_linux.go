//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const longhornHelperOutputLimit = 262144

var errLonghornHelperOutput = errors.New("longhorn helper output limit")

type longhornHelperOutput struct {
	bytes.Buffer
	stop func()
}

func (w *longhornHelperOutput) Write(p []byte) (int, error) {
	if len(p) > longhornHelperOutputLimit-w.Len() {
		w.stop()
		return 0, errLonghornHelperOutput
	}
	return w.Buffer.Write(p)
}

func runLonghornPreColdHelper(ctx context.Context, code, input []byte, expectedPythonSHA string, stderr io.Writer) ([]byte, error) {
	const python = "/usr/bin/python3.12"
	if len(code) == 0 || len(code) > 64<<10 || len(expectedPythonSHA) != 64 {
		return nil, errLonghornHelperOutput
	}
	f, err := os.Open(python)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > 64<<20 {
		return nil, errLonghornHelperOutput
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (64<<20)+1)); err != nil {
		return nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedPythonSHA {
		return nil, errLonghornHelperOutput
	}
	// Execute the already verified inode through its inherited descriptor.
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-B", "-c", string(code))
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	cmd.Cancel = func() error { kill(); return nil }
	cmd.WaitDelay = 5 * time.Second
	stdout := &longhornHelperOutput{stop: kill}
	cmd.Stdout = stdout
	err = cmd.Run()
	// Also remove any descendant left after an erroneous helper early return.
	kill()
	if err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}
